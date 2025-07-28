import { ethers } from 'ethers';
import { Buffer } from 'buffer';
import axios from 'axios';
import * as crypto from 'crypto';
import { zeroize } from '@moca-network/crypto-utils';
import { TEE_ENABLED, THRESHOLD, USE_POST_QUANTUM } from './config';
import { dilithiumSign, dilithiumVerify, generateDilithiumKeyPair } from '@moca-network/post-quantum';

/**
 * 增强型MPC签名节点
 * 支持阈值签名、TEE保护和后量子算法
 */
export class EnhancedMPCSigner {
    private keyShare: Buffer | null = null;
    private postQuantumKeyPair: { publicKey: Buffer, secretKey: Buffer } | null = null;
    private nodeRegistryUrl: string;
    private nodeId: number;
    private totalNodes: number;
    private pendingShares: { [messageHash: string]: { share: Buffer, index: number }[] } = {};
    private signatureListeners: { [messageHash: string]: (signature: any) => void } = {};
    private isTeeInitialized: boolean = false;

    constructor(
        nodeRegistryUrl: string,
        nodeId: number,
        totalNodes: number
    ) {
        this.nodeRegistryUrl = nodeRegistryUrl;
        this.nodeId = nodeId;
        this.totalNodes = totalNodes;
    }

    /**
     * 初始化MPC节点，加载或生成密钥分片
     */
    async init(sharePath?: string): Promise<void> {
        console.log(`Initializing MPC node ${this.nodeId}/${this.totalNodes}...`);

        // 初始化后量子密钥对（如启用）
        if (USE_POST_QUANTUM) {
            console.log('Generating post-quantum key pair (Dilithium)...');
            this.postQuantumKeyPair = generateDilithiumKeyPair();
        }

        // 加载或生成MPC密钥分片
        if (sharePath) {
            // 实际实现中应使用HSM或安全存储
            // this.keyShare = await this.loadSecureKeyShare(sharePath);
            console.log(`Loaded key share from ${sharePath}`);
        } else {
            // 生成新的密钥分片
            this.keyShare = crypto.randomBytes(32);
            console.log('Generated new key share');
        }

        // 初始化TEE（如启用）
        if (TEE_ENABLED) {
            await this.initializeTEE();
        }

        console.log('MPC node initialized successfully');
    }

    /**
     * 安全签名方法，支持后量子签名
     */
    async signHash(hashHex: string): Promise<{
        r: string,
        s: string,
        v: number,
        quantumSignature?: Buffer,
        quantumPublicKey?: Buffer
    }> {
        if (!this.keyShare) {
            throw new Error('Key share not initialized');
        }

        const msgBytes = Buffer.from(hashHex.slice(2), 'hex');

        try {
            if (USE_POST_QUANTUM && this.postQuantumKeyPair) {
                // 使用后量子签名算法
                const quantumSignature = dilithiumSign(
                    this.postQuantumKeyPair.secretKey,
                    msgBytes
                );

                // 同时生成传统签名用于兼容性
                let traditionalSignature;
                if (TEE_ENABLED) {
                    traditionalSignature = await this.signWithTEE(hashHex);
                } else {
                    traditionalSignature = await this.signWithECDSA(msgBytes);
                }

                return {
                    ...traditionalSignature,
                    quantumSignature,
                    quantumPublicKey: this.postQuantumKeyPair.publicKey
                };
            } else {
                // 使用传统签名
                if (TEE_ENABLED) {
                    return this.signWithTEE(hashHex);
                } else {
                    return this.signWithECDSA(msgBytes);
                }
            }
        } finally {
            // 安全清除临时密钥材料
            if (!TEE_ENABLED && this.keyShare) {
                crypto.randomFillSync(Buffer.from(this.keyShare));
                zeroize(this.keyShare);
            }
        }
    }

    /**
     * 验证后量子签名
     */
    verifyQuantumSignature(
        message: Buffer,
        signature: Buffer,
        publicKey: Buffer
    ): boolean {
        if (!USE_POST_QUANTUM) {
            throw new Error('Post-quantum verification disabled');
        }
        return dilithiumVerify(publicKey, message, signature);
    }

    /**
     * 使用ECDSA签名
     */
    private async signWithECDSA(msgBytes: Buffer): Promise<{ r: string, s: string, v: number }> {
        if (!this.keyShare) {
            throw new Error('Key share not initialized');
        }

        // 生成部分签名
        const partialSignature = this.generatePartialSignature(msgBytes);

        // 发送部分签名到MPC网络
        const response = await axios.post(`${this.nodeRegistryUrl}/partial-sign`, {
            nodeId: this.nodeId,
            messageHash: ethers.utils.keccak256(msgBytes),
            partialSignature: partialSignature.toString('base64')
        });

        return {
            r: response.data.r,
            s: response.data.s,
            v: response.data.v
        };
    }

    /**
     * 使用TEE进行安全签名
     */
    private async signWithTEE(hashHex: string): Promise<{ r: string, s: string, v: number }> {
        if (!this.isTeeInitialized) {
            throw new Error('TEE not initialized');
        }

        // 与TEE enclave通信
        const response = await axios.post(`${this.nodeRegistryUrl}/tee-sign`, {
            nodeId: this.nodeId,
            messageHash: hashHex,
            nonce: crypto.randomBytes(16).toString('hex')
        });

        // 验证TEE响应的完整性
        if (!this.verifyTEEResponse(response.data)) {
            throw new Error('Invalid TEE response');
        }

        return {
            r: response.data.r,
            s: response.data.s,
            v: response.data.v
        };
    }

    /**
     * 处理接收到的签名分片并实现聚合
     */
    async handleSignatureShare(messageHash: string, share: Buffer, index: number) {
        // 验证分片发送者
        if (index < 1 || index > this.totalNodes) {
            throw new Error('Invalid node index');
        }

        // 收集签名分片
        if (!this.pendingShares[messageHash]) {
            this.pendingShares[messageHash] = [];
        }

        // 防止重复添加相同节点的分片
        if (!this.pendingShares[messageHash].some(s => s.index === index)) {
            this.pendingShares[messageHash].push({ share, index });
            console.log(`Received signature share ${this.pendingShares[messageHash].length}/${THRESHOLD} for ${messageHash}`);
        }

        // 检查是否收集到足够的分片
        if (this.pendingShares[messageHash].length >= THRESHOLD) {
            try {
                const signature = await this.aggregateSignatures(
                    messageHash,
                    this.pendingShares[messageHash]
                );

                // 触发等待的回调
                if (this.signatureListeners[messageHash]) {
                    this.signatureListeners[messageHash](signature);
                    delete this.signatureListeners[messageHash];
                    delete this.pendingShares[messageHash]; // 清理已处理的分片
                }
            } catch (error) {
                console.error(`Signature aggregation failed: ${error.message}`);
            }
        }
    }

    /**
     * 实现签名聚合逻辑
     */
    private async aggregateSignatures(messageHash: string, shares: { share: Buffer, index: number }[]) {
        const response = await axios.post(`${this.nodeRegistryUrl}/aggregate-signatures`, {
            messageHash,
            shares: shares.map(s => ({
                data: s.share.toString('base64'),
                index: s.index
            })),
            nodeId: this.nodeId
        });

        return {
            r: response.data.r,
            s: response.data.s,
            v: response.data.v,
            aggregatedBy: this.nodeId,
            timestamp: Date.now()
        };
    }

    /**
     * 生成部分签名
     */
    private generatePartialSignature(msgBytes: Buffer): Buffer {
        // 实际实现中应使用threshold_ecdsa库
        const hash = createHash('sha256')
            .update(Buffer.concat([this.keyShare!, msgBytes]))
            .digest();
        return hash;
    }

    /**
     * 初始化TEE环境
     */
    private async initializeTEE(): Promise<void> {
        try {
            const response = await axios.post(`${this.nodeRegistryUrl}/init-tee`, {
                nodeId: this.nodeId,
                publicKey: this.postQuantumKeyPair?.publicKey.toString('base64')
            });

            this.isTeeInitialized = response.data.success;
            if (this.isTeeInitialized) {
                console.log('TEE initialized successfully');
            } else {
                throw new Error('TEE initialization failed');
            }
        } catch (error) {
            console.error('Failed to initialize TEE:', error);
            throw error;
        }
    }

    /**
     * 验证TEE响应
     */
    private verifyTEEResponse(response: any): boolean {
        // 实际实现中应验证TEE的报告和签名
        if (!response || !response.r || !response.s || !response.v || !response.teeSignature) {
            return false;
        }

        // 简化的验证逻辑，实际应更复杂
        const message = ethers.utils.solidityPack(['string', 'bytes32'], [
            'TEE_SIGNATURE',
            ethers.utils.keccak256(Buffer.from(`${response.r}${response.s}${response.v}`))
        ]);

        // 验证TEE签名
        try {
            const teePubKey = process.env.TEE_PUBLIC_KEY as string;
            return ethers.utils.verifyMessage(message, response.teeSignature) === teePubKey;
        } catch (error) {
            return false;
        }
    }

    /**
     * 注册签名回调
     */
    onSignatureReady(messageHash: string, callback: (signature: any) => void) {
        this.signatureListeners[messageHash] = callback;
    }

    /**
     * 安全销毁密钥材料
     */
    async destroy(): Promise<void> {
        if (this.keyShare) {
            zeroize(this.keyShare);
            this.keyShare = null;
        }

        if (this.postQuantumKeyPair) {
            zeroize(this.postQuantumKeyPair.secretKey);
            this.postQuantumKeyPair = null;
        }

        console.log(`MPC node ${this.nodeId} key materials zeroized`);
    }
}
