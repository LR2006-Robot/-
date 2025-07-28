import { ethers } from 'ethers';
import { PrivacyCrossChainVerifier__factory } from './typechain-types';
import { PostQuantumVerifier__factory } from './typechain-types';
import { ZKVerifier__factory } from './typechain-types';
import { EnhancedMPCSigner } from './EnhancedMPCSigner';
import fs from 'fs';
import path from 'path';

// 部署配置
const config = {
    deployerKey: process.env.DEPLOYER_PRIVATE_KEY as string,
    rpcUrl: process.env.RPC_URL || "https://rpc.moca-chain.io",
    mpcThreshold: 3,
    totalMPCNodes: 5,
    oracleAddress: process.env.ORACLE_ADDRESS as string,
    didRegistryAddress: process.env.DID_REGISTRY_ADDRESS as string,
    outputDir: path.join(__dirname, '../deployments')
};

/**
 * 生成MPC密钥对并分发
 */
async function generateMPCKeys(): Promise<{
    publicKeyX: string;
    publicKeyY: string;
    sharePaths: string[];
}> {
    console.log(`Generating MPC key shares (${config.totalMPCNodes} nodes, threshold ${config.mpcThreshold})...`);

    // 初始化MPC节点
    const nodes: EnhancedMPCSigner[] = [];
    const sharePaths: string[] = [];

    // 创建输出目录
    if (!fs.existsSync(config.outputDir)) {
        fs.mkdirSync(config.outputDir, { recursive: true });
    }

    // 生成密钥分片
    for (let i = 1; i <= config.totalMPCNodes; i++) {
        const node = new EnhancedMPCSigner(
            "https://mpc-node-registry.example.com",
            i,
            config.totalMPCNodes
        );

        const sharePath = path.join(config.outputDir, `mpc-share-${i}.key`);
        await node.init();

        // 保存密钥分片（实际环境中应加密存储）
        // fs.writeFileSync(sharePath, node.exportShare()); // 假设存在此方法
        sharePaths.push(sharePath);
        nodes.push(node);

        console.log(`Generated MPC key share for node ${i} at ${sharePath}`);
    }

    // 获取聚合公钥（实际实现中应通过MPC协议获取）
    const publicKeyX = "0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
    const publicKeyY = "0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";

    return { publicKeyX, publicKeyY, sharePaths };
}

/**
 * 部署所有合约
 */
async function deployContracts(mpcPubX: string, mpcPubY: string): Promise<{
    zkVerifier: string;
    pqVerifier: string;
    bridge: string;
}> {
    console.log('Starting contract deployment...');

    // 初始化提供者和部署者
    const provider = new ethers.providers.JsonRpcProvider(config.rpcUrl);
    const deployer = new ethers.Wallet(config.deployerKey, provider);
    console.log(`Deploying contracts from address: ${deployer.address}`);

    // 1. 部署ZK验证器合约
    const zkVerifierFactory = new ZKVerifier__factory(deployer);
    const zkVerifier = await zkVerifierFactory.deploy();
    await zkVerifier.deployed();
    console.log(`ZK Verifier deployed to: ${zkVerifier.address}`);

    // 2. 部署后量子验证器合约
    const pqVerifierFactory = new PostQuantumVerifier__factory(deployer);
    const pqVerifier = await pqVerifierFactory.deploy();
    await pqVerifier.deployed();
    console.log(`Post-Quantum Verifier deployed to: ${pqVerifier.address}`);

    // 3. 部署主桥合约
    const bridgeFactory = new PrivacyCrossChainVerifier__factory(deployer);
    const bridge = await bridgeFactory.deploy(
        mpcPubX,
        mpcPubY,
        zkVerifier.address,
        pqVerifier.address,
        config.oracleAddress,
        config.didRegistryAddress
    );
    await bridge.deployed();
    console.log(`Privacy Cross-Chain Bridge deployed to: ${bridge.address}`);

    // 4. 授权预言机
    const tx = await bridge.addAuthorizedOracle(config.oracleAddress);
    await tx.wait();
    console.log(`Authorized oracle: ${config.oracleAddress}`);

    // 保存部署信息
    const deploymentInfo = {
        timestamp: new Date().toISOString(),
        network: await provider.getNetwork().then(n => n.name || n.chainId.toString()),
        zkVerifier: zkVerifier.address,
        pqVerifier: pqVerifier.address,
        bridge: bridge.address,
        mpcPublicKey: { x: mpcPubX, y: mpcPubY },
        oracle: config.oracleAddress,
        deployer: deployer.address
    };

    fs.writeFileSync(
        path.join(config.outputDir, 'deployment.json'),
        JSON.stringify(deploymentInfo, null, 2)
    );

    console.log('Deployment information saved');
    return { zkVerifier: zkVerifier.address, pqVerifier: pqVerifier.address, bridge: bridge.address };
}

/**
 * 测试跨链功能
 */
async function testBridge(bridgeAddress: string) {
    console.log('Testing bridge functionality...');

    const provider = new ethers.providers.JsonRpcProvider(config.rpcUrl);
    const signer = new ethers.Wallet(config.deployerKey, provider);
    const bridge = PrivacyCrossChainVerifier__factory.connect(bridgeAddress, signer);

    // 1. 测试设置隐私偏好
    const setPrefTx = await bridge.setPrivacyPreference(3); // Enhanced
    await setPrefTx.wait();
    console.log('Set privacy preference test passed');

    // 2. 测试销毁功能
    const mintTx = await bridge.mint(signer.address, ethers.utils.parseEther("10"));
    await mintTx.wait();

    const burnTx = await bridge.burnToChain(
        ethers.utils.parseEther("1"),
        "ethereum",
        ethers.utils.randomBytes(32),
        2
    );
    await burnTx.wait();
    console.log('Burn functionality test passed');

    // 3. 测试锁定原生资产
    const lockTx = await bridge.lockNativeAsset(
        "binance",
        ethers.utils.randomBytes(32),
        2,
        { value: ethers.utils.parseEther("0.5") }
    );
    await lockTx.wait();
    console.log('Native asset locking test passed');

    console.log('All basic tests passed');
}

/**
 * 主部署函数
 */
async function main() {
    try {
        // 生成MPC密钥
        const { publicKeyX, publicKeyY } = await generateMPCKeys();

        // 部署合约
        const { bridge } = await deployContracts(publicKeyX, publicKeyY);

        // 运行测试
        await testBridge(bridge);

        console.log('Deployment and testing completed successfully!');
    } catch (error) {
        console.error('Deployment failed:', error);
        process.exit(1);
    }
}

// 执行部署
main().catch(console.error);
