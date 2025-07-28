import { ethers } from 'ethers';
import { randomBytes, createHash } from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import { DIDDocument, VerifiableCredential } from '@moca-network/did-core';
import axios from 'axios';

/**
 * 中继地址过期时间（10分钟）
 */
const RELAY_ADDRESS_TTL = 600 * 1000;

/**
 * DID中继服务 - 管理跨链身份中继和隐私保护
 */
export class DIDRelay {
    private didRegistryUrl: string;
    private oracleUrl: string;
    private provider: ethers.providers.Provider;
    private relayAddresses: Map<string, {
        address: string;
        expires: number;
        targetAddress: string;
        credentials: VerifiableCredential[]
    }>;

    constructor(
        didRegistryUrl: string,
        oracleUrl: string,
        providerUrl: string
    ) {
        this.didRegistryUrl = didRegistryUrl;
        this.oracleUrl = oracleUrl;
        this.provider = new ethers.providers.JsonRpcProvider(providerUrl);
        this.relayAddresses = new Map();

        // 定期清理过期的中继地址
        setInterval(() => this.cleanupExpiredRelays(), 60 * 1000);
    }

    /**
     * 创建临时中继地址
     * @param targetAddress 目标链地址
     * @param credentials 验证凭证
     * @returns 临时中继地址和ID
     */
    async createRelayAddress(
        targetAddress: string,
        credentials: VerifiableCredential[] = []
    ): Promise<{ relayId: string; relayAddress: string }> {
        // 生成随机中继地址
        const privateKey = randomBytes(32);
        const wallet = new ethers.Wallet(privateKey);
        const relayAddress = wallet.address;

        // 生成唯一中继ID
        const relayId = uuidv4();

        // 存储中继信息
        this.relayAddresses.set(relayId, {
            address: relayAddress,
            expires: Date.now() + RELAY_ADDRESS_TTL,
            targetAddress,
            credentials
        });

        // 安全清理私钥
        randomBytes(privateKey.length).copy(privateKey);

        // 通知预言机新的中继地址
        await this.notifyOracle(relayId, relayAddress, targetAddress);

        return { relayId, relayAddress };
    }

    /**
     * 解析中继地址获取目标地址
     * @param relayId 中继ID
     * @param signature 中继ID的签名
     * @returns 目标地址（如验证通过）
     */
    async resolveRelayAddress(
        relayId: string,
        signature: string
    ): Promise<string> {
        const relayInfo = this.relayAddresses.get(relayId);

        if (!relayInfo) {
            throw new Error('Relay address not found');
        }

        if (relayInfo.expires < Date.now()) {
            throw new Error('Relay address expired');
        }

        // 验证签名
        const messageHash = ethers.utils.hashMessage(relayId);
        const signerAddress = ethers.utils.verifyMessage(relayId, signature);

        // 检查签名者是否为授权预言机
        const isAuthorized = await this.checkOracleAuthorization(signerAddress);
        if (!isAuthorized) {
            throw new Error('Unauthorized oracle signature');
        }

        return relayInfo.targetAddress;
    }

    /**
     * 获取中继地址的验证凭证
     * @param relayId 中继ID
     * @returns 验证凭证列表
     */
    getRelayCredentials(relayId: string): VerifiableCredential[] {
        const relayInfo = this.relayAddresses.get(relayId);
        return relayInfo ? relayInfo.credentials : [];
    }

    /**
     * 清理过期的中继地址
     */
    private cleanupExpiredRelays(): void {
        const now = Date.now();
        for (const [relayId, info] of this.relayAddresses.entries()) {
            if (info.expires < now) {
                this.relayAddresses.delete(relayId);
                console.log(`Cleaned up expired relay: ${relayId}`);
            }
        }
    }

    /**
     * 通知预言机新的中继地址
     */
    private async notifyOracle(relayId: string, relayAddress: string, targetAddress: string): Promise<void> {
        try {
            await axios.post(`${this.oracleUrl}/register-relay`, {
                relayId,
                relayAddress,
                targetAddress,
                expires: new Date(Date.now() + RELAY_ADDRESS_TTL).toISOString()
            });
        } catch (error) {
            console.error('Failed to notify oracle about new relay address:', error);
            // 不中断流程，仅记录错误
        }
    }

    /**
     * 检查地址是否为授权预言机
     */
    private async checkOracleAuthorization(address: string): Promise<boolean> {
        try {
            const response = await axios.get(`${this.didRegistryUrl}/oracles/${address}`);
            return response.data.isAuthorized === true;
        } catch (error) {
            console.error('Failed to check oracle authorization:', error);
            return false;
        }
    }

    /**
     * 获取DID文档
     */
    async getDIDDocument(did: string): Promise<DIDDocument> {
        const response = await axios.get(`${this.didRegistryUrl}/did/${did}`);
        return response.data as DIDDocument;
    }

    /**
     * 创建可验证凭证
     */
    async createVerifiableCredential(
        issuer: string,
        subject: string,
        type: string,
        claims: Record<string, any>
    ): Promise<VerifiableCredential> {
        const credential = {
            id: `urn:uuid:${uuidv4()}`,
            type: ['VerifiableCredential', type],
            issuer,
            issuanceDate: new Date().toISOString(),
            credentialSubject: {
                id: subject,
                ...claims
            }
        };

        // 请求DID注册表签名凭证
        const response = await axios.post(`${this.didRegistryUrl}/issue-credential`, {
            credential
        });

        return response.data as VerifiableCredential;
    }
}
