import { ethers } from 'ethers';
import axios from 'axios';

/**
 * 隐私级别枚举
 */
export enum PrivacyLevel {
    // 最低隐私：基本哈希处理
    Basic = 1,
    // 中等隐私：完整ZK证明，不隐藏金额范围
    Standard = 2,
    // 高级隐私：完整ZK证明，隐藏金额范围，使用中继地址
    Enhanced = 3,
    // 最高隐私：所有数据加密，多重ZK证明，临时身份
    Maximum = 4
}

/**
 * 隐私策略管理器
 * 根据网络状况、交易金额和用户偏好动态调整隐私保护级别
 */
export class PrivacyPolicyManager {
    private oracleUrl: string;
    private userPreferences: Map<string, PrivacyLevel>;
    private gasPriceThresholds: { [level: number]: number }; // Gwei
    private amountThresholds: { [level: number]: bigint }; // wei
    private chainPrivacyDefaults: Map<string, PrivacyLevel>;
    private networkCongestionCache: Map<string, number>; // chainId -> congestion level (0-100)
    private lastCongestionCheck: number;

    constructor(oracleUrl: string) {
        this.oracleUrl = oracleUrl;
        this.userPreferences = new Map();
        this.networkCongestionCache = new Map();
        this.lastCongestionCheck = 0;

        // 初始化Gas价格阈值（Gwei）
        this.gasPriceThresholds = {
            [PrivacyLevel.Basic]: 50,
            [PrivacyLevel.Standard]: 30,
            [PrivacyLevel.Enhanced]: 20,
            [PrivacyLevel.Maximum]: 10
        };

        // 初始化金额阈值（wei）
        this.amountThresholds = {
            [PrivacyLevel.Basic]: ethers.utils.parseEther('0.1'),
            [PrivacyLevel.Standard]: ethers.utils.parseEther('1'),
            [PrivacyLevel.Enhanced]: ethers.utils.parseEther('10'),
            [PrivacyLevel.Maximum]: ethers.utils.parseEther('100')
        };

        // 初始化链默认隐私级别
        this.chainPrivacyDefaults = new Map([
            ['ethereum', PrivacyLevel.Standard],
            ['binance', PrivacyLevel.Basic],
            ['moca', PrivacyLevel.Enhanced],
            ['avalanche', PrivacyLevel.Standard],
            ['polygon', PrivacyLevel.Basic]
        ]);
    }

    /**
     * 设置用户隐私偏好
     */
    setUserPreference(userId: string, level: PrivacyLevel): void {
        if (Object.values(PrivacyLevel).includes(level)) {
            this.userPreferences.set(userId, level);
        } else {
            throw new Error('Invalid privacy level');
        }
    }

    /**
     * 获取推荐的隐私级别
     */
    async getRecommendedPrivacyLevel(
        userId: string,
        chainId: string,
        amount: bigint,
        gasPrice: number // Gwei
    ): Promise<{ level: PrivacyLevel; reasons: string[] }> {
        const reasons: string[] = [];
        let level: PrivacyLevel | null = null;

        // 1. 检查用户是否有明确偏好
        if (this.userPreferences.has(userId)) {
            level = this.userPreferences.get(userId)!;
            reasons.push(`User preference set to ${PrivacyLevel[level]}`);
        }

        // 2. 检查网络拥堵情况
        const congestion = await this.getNetworkCongestion(chainId);

        // 3. 如果没有用户偏好，基于金额、Gas价格和网络状况确定
        if (level === null) {
            // 基于金额确定基础级别
            if (amount >= this.amountThresholds[PrivacyLevel.Maximum]) {
                level = PrivacyLevel.Maximum;
                reasons.push(`Amount exceeds ${ethers.utils.formatEther(this.amountThresholds[PrivacyLevel.Maximum])} ETH`);
            } else if (amount >= this.amountThresholds[PrivacyLevel.Enhanced]) {
                level = PrivacyLevel.Enhanced;
                reasons.push(`Amount exceeds ${ethers.utils.formatEther(this.amountThresholds[PrivacyLevel.Enhanced])} ETH`);
            } else if (amount >= this.amountThresholds[PrivacyLevel.Standard]) {
                level = PrivacyLevel.Standard;
                reasons.push(`Amount exceeds ${ethers.utils.formatEther(this.amountThresholds[PrivacyLevel.Standard])} ETH`);
            } else {
                level = this.chainPrivacyDefaults.get(chainId) || PrivacyLevel.Standard;
                reasons.push(`Using default level for ${chainId}`);
            }

            // 根据Gas价格调整
            if (gasPrice > this.gasPriceThresholds[level] && level > PrivacyLevel.Basic) {
                level = level - 1 as PrivacyLevel;
                reasons.push(`High gas price (${gasPrice} Gwei), reducing privacy level to ${PrivacyLevel[level]}`);
            }

            // 根据网络拥堵调整
            if (congestion > 70 && level > PrivacyLevel.Basic) {
                level = Math.max(PrivacyLevel.Basic, level - 1) as PrivacyLevel;
                reasons.push(`Network congestion (${congestion}%), reducing privacy level to ${PrivacyLevel[level]}`);
            } else if (congestion < 30 && level < PrivacyLevel.Maximum) {
                level = Math.min(PrivacyLevel.Maximum, level + 1) as PrivacyLevel;
                reasons.push(`Network uncongested (${congestion}%), increasing privacy level to ${PrivacyLevel[level]}`);
            }
        }

        return { level, reasons };
    }

    /**
     * 获取隐私级别对应的配置
     */
    getPrivacyConfig(level: PrivacyLevel): {
        useZKProof: boolean;
        hideAmount: boolean;
        useRelayAddress: boolean;
        usePostQuantum: boolean;
        zkCircuitSize: 'small' | 'medium' | 'large';
    } {
        switch (level) {
            case PrivacyLevel.Basic:
                return {
                    useZKProof: false,
                    hideAmount: false,
                    useRelayAddress: false,
                    usePostQuantum: false,
                    zkCircuitSize: 'small'
                };
            case PrivacyLevel.Standard:
                return {
                    useZKProof: true,
                    hideAmount: false,
                    useRelayAddress: false,
                    usePostQuantum: false,
                    zkCircuitSize: 'small'
                };
            case PrivacyLevel.Enhanced:
                return {
                    useZKProof: true,
                    hideAmount: true,
                    useRelayAddress: true,
                    usePostQuantum: false,
                    zkCircuitSize: 'medium'
                };
            case PrivacyLevel.Maximum:
                return {
                    useZKProof: true,
                    hideAmount: true,
                    useRelayAddress: true,
                    usePostQuantum: true,
                    zkCircuitSize: 'large'
                };
            default:
                return this.getPrivacyConfig(PrivacyLevel.Standard);
        }
    }

    /**
     * 获取网络拥堵程度
     */
    private async getNetworkCongestion(chainId: string): Promise<number> {
        // 缓存10分钟
        const now = Date.now();
        if (now - this.lastCongestionCheck < 600000 && this.networkCongestionCache.has(chainId)) {
            return this.networkCongestionCache.get(chainId)!;
        }

        try {
            const response = await axios.get(`${this.oracleUrl}/network-congestion/${chainId}`);
            const congestion = Math.min(100, Math.max(0, response.data.congestionLevel));
            this.networkCongestionCache.set(chainId, congestion);
            this.lastCongestionCheck = now;
            return congestion;
        } catch (error) {
            console.error(`Failed to get network congestion for ${chainId}:`, error);
            return 50; // 默认中等拥堵
        }
    }

    /**
     * 估算不同隐私级别的Gas成本
     */
    async estimateGasCost(chainId: string, level: PrivacyLevel): Promise<bigint> {
        try {
            const response = await axios.get(`${this.oracleUrl}/gas-estimate/${chainId}/${level}`);
            return BigInt(response.data.estimatedGas);
        } catch (error) {
            console.error(`Failed to estimate gas cost for ${chainId} level ${level}:`, error);
            // 返回默认估算值
            const defaults: { [level: number]: bigint } = {
                [PrivacyLevel.Basic]: BigInt(150000),
                [PrivacyLevel.Standard]: BigInt(250000),
                [PrivacyLevel.Enhanced]: BigInt(350000),
                [PrivacyLevel.Maximum]: BigInt(500000)
            };
            return defaults[level] || defaults[PrivacyLevel.Standard];
        }
    }
}
