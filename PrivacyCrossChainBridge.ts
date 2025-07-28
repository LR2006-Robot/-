import { ethers } from 'ethers';
import { ZKProver } from './zk-prover';
import { DIDRelay } from './DIDRelay';
import { EnhancedMPCSigner } from './EnhancedMPCSigner';
import { PrivacyPolicyManager, PrivacyLevel } from './PrivacyPolicyManager';
import { PrivacyCrossChainVerifier__factory } from './typechain-types';
import { Buffer } from 'buffer';
import axios from 'axios';
import { v4 as uuidv4 } from 'uuid';
import { zeroize } from '@moca-network/crypto-utils';
import { TEE_ENABLED, USE_POST_QUANTUM, CIRCUIT_PATH } from './config';

/**
 * 跨链交易状态
 */
export enum CrossChainStatus {
    INITIATED = 'INITIATED',
    PROOF_GENERATED = 'PROOF_GENERATED',
    SIGNATURE_COMPLETED = 'SIGNATURE_COMPLETED',
    BROADCASTED = 'BROADCASTED',
    CONFIRMED = 'CONFIRMED',
    FAILED = 'FAILED'
}

/**
 * 隐私跨链桥服务
 * 整合ZK证明、DID中继和MPC签名，提供隐私保护的跨链交易
 */
export class PrivacyCrossChainBridge {
    private zkProver: ZKProver;
    private didRelay: DIDRelay;
    private mpcSigner: EnhancedMPCSigner;
    private policyManager: PrivacyPolicyManager;
    private provider: ethers.providers.Provider;
    private signer: ethers.Signer;
    private verifierContract: ethers.Contract;
    private nodeRegistryUrl: string;
    private oracleUrl: string;
    private transactionCache: Map<string, {
        status: CrossChainStatus;
        data: any;
        timestamp: number;
    }>;

    constructor(
        nodeRegistryUrl: string,
        oracleUrl: string,
        didRegistryUrl: string,
        verifierAddress: string,
        providerUrl: string,
        privateKey: string,
        nodeId: number,
        totalNodes: number
    ) {
        this.nodeRegistryUrl = nodeRegistryUrl;
        this.oracleUrl = oracleUrl;
        this.transactionCache = new Map();

        // 初始化核心组件
        this.zkProver = new ZKProver(CIRCUIT_PATH);
        this.didRelay = new DIDRelay(didRegistryUrl, oracleUrl, providerUrl);
        this.mpcSigner = new EnhancedMPCSigner(nodeRegistryUrl, nodeId, totalNodes);
        this.policyManager = new PrivacyPolicyManager(oracleUrl);

        // 初始化以太坊提供者和签名者
        this.provider = new ethers.providers.JsonRpcProvider(providerUrl);
        this.signer = new ethers.Wallet(privateKey, this.provider);

        // 初始化验证合约
        this.verifierContract = PrivacyCrossChainVerifier__factory.connect(
            verifierAddress,
            this.signer
        );
    }

    /**
     * 初始化跨链桥服务
     */
    async init(mpcSharePath?: string): Promise<void> {
        console.log('Initializing privacy cross-chain bridge...');

        // 初始化所有组件
        await Promise.all([
            this.zkProver.init(),
            this.mpcSigner.init(mpcSharePath),
            this.syncTransactionCache()
        ]);

        console.log('Privacy cross-chain bridge initialized successfully');
    }

    /**
     * 发起隐私跨链转账
     */
    async initiatePrivateTransfer(
        sourceChainId: string,
        targetChainId: string,
        recipient: string,
        amount: bigint,
        merkleRoot: string,
        userId?: string
    ): Promise<{ transferId: string; txHash?: string; status: CrossChainStatus }> {
        const transferId = uuidv4();
        let status = CrossChainStatus.INITIATED;
        let txHash: string | undefined;

        try {
            // 1. 记录初始状态
            this.updateTransactionCache(transferId, status, {
                sourceChainId,
                targetChainId,
                recipient,
                amount: amount.toString(),
                merkleRoot,
                timestamp: Date.now()
            });

            // 2. 获取当前Gas价格和推荐的隐私级别
            const gasPrice = await this.getGasPrice(targetChainId);
            const { level: privacyLevel, reasons } = await this.policyManager.getRecommendedPrivacyLevel(
                userId || recipient,
                targetChainId,
                amount,
                gasPrice
            );

            console.log(`Using privacy level ${PrivacyLevel[privacyLevel]} for transfer ${transferId}:`, reasons);

            // 3. 获取隐私配置
            const privacyConfig = this.policyManager.getPrivacyConfig(privacyLevel);

            // 4. 创建中继地址（如需要）
            let relayId = '';
            if (privacyConfig.useRelayAddress) {
                const { relayId: newRelayId } = await this.didRelay.createRelayAddress(recipient);
                relayId = newRelayId;
                console.log(`Created relay address for transfer ${transferId}: ${relayId}`);
            }

            // 5. 生成ZK证明（如需要）
            let zkProof: any = null;
            if (privacyConfig.useZKProof) {
                const timestamp = BigInt(Math.floor(Date.now() / 1000));
                const nonce = BigInt(Math.floor(Math.random() * 1e18));

                const zkInputs = {
                    amount,
                    timestamp,
                    merkleRoot,
                    privacyLevel,
                    nonce,
                    sourceChainId: ethers.utils.id(sourceChainId).slice(0, 34), // 转换为十六进制
                    targetChainId: ethers.utils.id(targetChainId).slice(0, 34)
                };

                const proofResult = await this.zkProver.generateProof(zkInputs);
                zkProof = proofResult.proof;
                status = CrossChainStatus.PROOF_GENERATED;
                this.updateTransactionCache(transferId, status, { ...zkInputs, proof: true });
                console.log(`Generated ZK proof for transfer ${transferId}`);
            }

            // 6. 获取MPC签名
            const timestamp = BigInt(Math.floor(Date.now() / 1000));
            const messageHash = this.generateMessageHash(
                sourceChainId,
                recipient,
                amount,
                timestamp,
                merkleRoot,
                privacyLevel,
                relayId
            );

            const signature = await this.mpcSigner.signHash(messageHash);
            status = CrossChainStatus.SIGNATURE_COMPLETED;
            this.updateTransactionCache(transferId, status, { signature: 'exists' });
            console.log(`Obtained MPC signature for transfer ${transferId}`);

            // 7. 构建证明输入
            const inputs = [
                amount.toString(),
                timestamp.toString(),
                merkleRoot,
                privacyLevel.toString(),
                uuidv4() // nonce
            ];

            // 8. 调用智能合约铸造函数
            const tx = await this.verifierContract.mintWithProof(
                sourceChainId,
                zkProof?.a || [0, 0],
                zkProof?.b || [[0, 0], [0, 0]],
                zkProof?.c || [0, 0],
                inputs,
                relayId,
                signature.v,
                signature.r,
                signature.s,
                signature.quantumSignature || '0x',
                signature.quantumPublicKey || '0x'
            );

            txHash = tx.hash;
            status = CrossChainStatus.BROADCASTED;
            this.updateTransactionCache(transferId, status, { txHash });
            console.log(`Broadcasted transaction for transfer ${transferId}: ${txHash}`);

            // 9. 等待交易确认
            const receipt = await tx.wait(1); // 等待1个确认
            if (receipt.status === 1) {
                status = CrossChainStatus.CONFIRMED;
                this.updateTransactionCache(transferId, status, { blockNumber: receipt.blockNumber });
                console.log(`Transaction confirmed for transfer ${transferId} in block ${receipt.blockNumber}`);
            } else {
                throw new Error('Transaction failed');
            }
        } catch (error) {
            status = CrossChainStatus.FAILED;
            this.updateTransactionCache(transferId, status, { error: (error as Error).message });
            console.error(`Transfer ${transferId} failed:`, error);
        }

        return { transferId, txHash, status };
    }

    /**
     * 发起资产销毁（跨链转出）
     */
    async burnForTransfer(
        amount: bigint,
        targetChainId: string,
        userId?: string
    ): Promise<{ transferId: string; txHash?: string; status: CrossChainStatus }> {
        const transferId = uuidv4();
        let status = CrossChainStatus.INITIATED;
        let txHash: string | undefined;

        try {
            // 1. 记录初始状态
            this.updateTransactionCache(transferId, status, {
                amount: amount.toString(),
                targetChainId,
                timestamp: Date.now()
            });

            // 2. 获取推荐的隐私级别
            const gasPrice = await this.getGasPrice(await this.provider.getNetwork().then(n => n.chainId.toString()));
            const { level: privacyLevel } = await this.policyManager.getRecommendedPrivacyLevel(
                userId || await this.signer.getAddress(),
                targetChainId,
                amount,
                gasPrice
            );

            // 3. 生成目标交易哈希
            const targetTxHash = ethers.utils.keccak256(
                Buffer.from(`${transferId}${Date.now()}${Math.random()}`)
            );

            // 4. 调用销毁函数
            const tx = await this.verifierContract.burnToChain(
                amount,
                targetChainId,
                targetTxHash,
                privacyLevel
            );

            txHash = tx.hash;
            status = CrossChainStatus.BROADCASTED;
            this.updateTransactionCache(transferId, status, { txHash, targetTxHash });
            console.log(`Broadcasted burn transaction ${transferId}: ${txHash}`);

            // 5. 等待确认
            const receipt = await tx.wait(1);
            if (receipt.status === 1) {
                status = CrossChainStatus.CONFIRMED;
                this.updateTransactionCache(transferId, status, { blockNumber: receipt.blockNumber });
                console.log(`Burn transaction confirmed ${transferId} in block ${receipt.blockNumber}`);
            } else {
                throw new Error('Burn transaction failed');
            }
        } catch (error) {
            status = CrossChainStatus.FAILED;
            this.updateTransactionCache(transferId, status, { error: (error as Error).message });
            console.error(`Burn transfer ${transferId} failed:`, error);
        }

        return { transferId, txHash, status };
    }

    /**
     * 锁定原生资产用于跨链
     */
    async lockNativeAsset(
        amount: bigint,
        targetChainId: string,
        userId?: string
    ): Promise<{ transferId: string; txHash?: string; status: CrossChainStatus }> {
        const transferId = uuidv4();
        let status = CrossChainStatus.INITIATED;
        let txHash: string | undefined;

        try {
            // 1. 记录初始状态
            this.updateTransactionCache(transferId, status, {
                amount: amount.toString(),
                targetChainId,
                timestamp: Date.now()
            });

            // 2. 获取推荐的隐私级别
            const gasPrice = await this.getGasPrice(await this.provider.getNetwork().then(n => n.chainId.toString()));
            const { level: privacyLevel } = await this.policyManager.getRecommendedPrivacyLevel(
                userId || await this.signer.getAddress(),
                targetChainId,
                amount,
                gasPrice
            );

            // 3. 生成目标交易哈希
            const targetTxHash = ethers.utils.keccak256(
                Buffer.from(`${transferId}${Date.now()}${Math.random()}`)
            );

            // 4. 调用锁定函数
            const tx = await this.verifierContract.lockNativeAsset(
                targetChainId,
                targetTxHash,
                privacyLevel,
                { value: amount }
            );

            txHash = tx.hash;
            status = CrossChainStatus.BROADCASTED;
            this.updateTransactionCache(transferId, status, { txHash, targetTxHash });
            console.log(`Broadcasted lock transaction ${transferId}: ${txHash}`);

            // 5. 等待确认
            const receipt = await tx.wait(1);
            if (receipt.status === 1) {
                status = CrossChainStatus.CONFIRMED;
                this.updateTransactionCache(transferId, status, { blockNumber: receipt.blockNumber });
                console.log(`Lock transaction confirmed ${transferId} in block ${receipt.blockNumber}`);
            } else {
                throw new Error('Lock transaction failed');
            }
        } catch (error) {
            status = CrossChainStatus.FAILED;
            this.updateTransactionCache(transferId, status, { error: (error as Error).message });
            console.error(`Lock transfer ${transferId} failed:`, error);
        }

        return { transferId, txHash, status };
    }

    /**
     * 获取交易状态
     */
    getTransferStatus(transferId: string): { status: CrossChainStatus; data: any } | null {
        const entry = this.transactionCache.get(transferId);
        return entry ? { status: entry.status, data: entry.data } : null;
    }

    /**
     * 设置用户隐私偏好
     */
    async setUserPrivacyPreference(userId: string, level: PrivacyLevel): Promise<void> {
        this.policyManager.setUserPreference(userId, level);

        // 同时更新链上偏好（如需要）
        const userAddress = await this.signer.getAddress();
        if (userId === userAddress) {
            const tx = await this.verifierContract.setPrivacyPreference(level);
            await tx.wait();
            console.log(`Set on-chain privacy preference for ${userId} to ${PrivacyLevel[level]}`);
        }
    }

    /**
     * 生成消息哈希
     */
    private generateMessageHash(
        sourceChainId: string,
        recipient: string,
        amount: bigint,
        timestamp: bigint,
        merkleRoot: string,
        privacyLevel: PrivacyLevel,
        relayId: string
    ): string {
        return ethers.utils.solidityKeccak256(
            ["string", "string", "address", "uint256", "uint256", "bytes32", "uint256", "bytes32"],
            ["PRIVACY_BRIDGE", sourceChainId, recipient, amount, timestamp, merkleRoot, privacyLevel, relayId]
        );
    }

    /**
     * 获取Gas价格（Gwei）
     */
    private async getGasPrice(chainId: string): Promise<number> {
        try {
            const response = await axios.get(`${this.oracleUrl}/gas-price/${chainId}`);
            return parseFloat(response.data.gasPriceGwei);
        } catch (error) {
            console.error(`Failed to get gas price for ${chainId}, using default:`, error);
            return 30; // 默认30 Gwei
        }
    }

    /**
     * 更新交易缓存
     */
    private updateTransactionCache(transferId: string, status: CrossChainStatus, data: any): void {
        this.transactionCache.set(transferId, {
            status,
            data: { ...data, updatedAt: Date.now() },
            timestamp: Date.now()
        });

        // 限制缓存大小，超过1000条清理最旧的
        if (this.transactionCache.size > 1000) {
            const oldestKey = Array.from(this.transactionCache.entries())
                .sort((a, b) => a[1].timestamp - b[1].timestamp)[0][0];
            this.transactionCache.delete(oldestKey);
        }
    }

    /**
     * 同步交易缓存（从链上）
     */
    private async syncTransactionCache(): Promise<void> {
        console.log('Syncing transaction cache from blockchain...');

        // 监听最近的铸造事件
        const filter = this.verifierContract.filters.AssetMinted();
        const events = await this.verifierContract.queryFilter(filter, -1000); // 最近1000个区块

        for (const event of events) {
            const transferId = ethers.utils.keccak256(
                Buffer.from(`${event.transactionHash}${event.logIndex}`)
            );

            if (!this.transactionCache.has(transferId)) {
                this.updateTransactionCache(transferId, CrossChainStatus.CONFIRMED, {
                    txHash: event.transactionHash,
                    blockNumber: event.blockNumber,
                    recipient: event.args?.to,
                    amount: event.args?.amount.toString(),
                    chain: event.args?.chainId,
                    merkleRoot: event.args?.merkleRoot
                });
            }
        }

        console.log(`Synced ${events.length} transactions to cache`);
    }

    /**
     * 销毁服务，安全清理敏感数据
     */
    async destroy(): Promise<void> {
        await this.mpcSigner.destroy();
        console.log('Privacy cross-chain bridge destroyed, sensitive data cleared');
    }
}

// 主函数示例
async function main() {
    // 配置参数
    const config = {
        nodeRegistryUrl: "https://mpc-node-registry.example.com",
        oracleUrl: "https://zk-oracle.example.com",
        didRegistryUrl: "https://did-registry.example.com",
        verifierAddress: "0xYourVerifierContractAddress",
        providerUrl: "https://mainnet.infura.io/v3/your-project-id",
        privateKey: process.env.BRIDGE_PRIVATE_KEY as string,
        nodeId: parseInt(process.env.NODE_ID || "1"),
        totalNodes: parseInt(process.env.TOTAL_NODES || "4")
    };

    // 初始化桥接服务
    const bridge = new PrivacyCrossChainBridge(
        config.nodeRegistryUrl,
        config.oracleUrl,
        config.didRegistryUrl,
        config.verifierAddress,
        config.providerUrl,
        config.privateKey,
        config.nodeId,
        config.totalNodes
    );

    await bridge.init();
    console.log("Privacy cross-chain bridge is running...");

    // 示例：发起跨链转账
    const recipient = "0xRecipientAddress";
    const amount = ethers.utils.parseEther("1.5");
    const merkleRoot = "0xYourMerkleRootHash";

    const result = await bridge.initiatePrivateTransfer(
        "ethereum",    // 源链
        "moca",        // 目标链
        recipient,     // 接收者
        amount,        // 金额
        merkleRoot     // Merkle根
    );

    console.log(`Transfer initiated:`, result);

    // 监听交易状态
    setInterval(async () => {
        const status = bridge.getTransferStatus(result.transferId);
        if (status && status.status === CrossChainStatus.CONFIRMED) {
            console.log(`Transfer ${result.transferId} completed successfully!`);
            process.exit(0);
        } else if (status && status.status === CrossChainStatus.FAILED) {
            console.error(`Transfer ${result.transferId} failed:`, status.data.error);
            process.exit(1);
        }
    }, 5000);
}

// 启动主函数
main().catch(console.error);
