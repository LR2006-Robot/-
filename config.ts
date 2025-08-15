/**
 * 项目核心配置文件
 */

// 是否启用TEE（可信执行环境）进行密钥管理和签名
export const TEE_ENABLED = process.env.TEE_ENABLED === 'true' || false;

// 是否启用后量子签名算法（Dilithium）
export const USE_POST_QUANTUM = process.env.USE_POST_QUANTUM === 'true' || true;

// MPC签名所需的节点阈值
export const THRESHOLD = parseInt(process.env.THRESHOLD || '3', 10);

// ZK-SNARK电路文件路径
export const CIRCUIT_PATH = 'circuits/transfer.circom';

// 默认的以太坊节点提供商URL
export const DEFAULT_PROVIDER_URL = 'https://mainnet.infura.io/v3/your-project-id';

// 默认的DID注册中心URL
export const DEFAULT_DID_REGISTRY_URL = 'https://did-registry.example.com';

// 默认的预言机URL
export const DEFAULT_ORACLE_URL = 'https://zk-oracle.example.com';

// 默认的MPC节点注册中心URL
export const DEFAULT_NODE_REGISTRY_URL = 'https://mpc-node-registry.example.com';
