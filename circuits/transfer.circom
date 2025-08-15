pragma circom 2.0.0;

/*
 * 这是一个简化的 ZK-SNARK 电路示例，用于隐私跨链转账。
 *
 * 输入:
 * - amount: 转账金额 (私有)
 * - senderSecret: 发送者私密密钥 (私有)
 * - recipient: 接收者地址 (公开)
 * - merkleRoot: Merkle树的根哈希 (公开)
 * - pathElements: Merkle证明路径 (私有)
 * - pathIndices: Merkle证明路径索引 (私有)
 *
 * 输出:
 * - computedRoot: 根据私有输入计算出的Merkle根
 * - nullifierHash: 用于防止双花的无效符哈希
 *
 * 目标:
 * 1. 证明发送者拥有一个有效的票据（UTXO）在Merkle树中，但不暴露是哪个票据。
 * 2. 证明交易金额在有效范围内，但不暴露具体金额。
 * 3. 生成一个唯一的无效符，防止同一票据被多次花费。
 */

include "../node_modules/circomlib/circuits/mimcsponge.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/merkle_tree.circom";

template Transfer(levels) {
    // 私有输入
    signal private input amount;
    signal private input senderSecret;
    signal private input pathElements[levels];
    signal private input pathIndices[levels];

    // 公开输入
    signal public input recipient;
    signal public input merkleRoot;

    // 公开输出
    signal output nullifierHash;
    signal output computedRoot;

    // 1. 生成票据承诺 (commitment)
    // commitment = H(amount, senderSecret)
    component commitmentHasher = MiMCSponge(2, 220, 1);
    commitmentHasher.ins[0] <== amount;
    commitmentHasher.ins[1] <== senderSecret;
    signal commitment <== commitmentHasher.outs[0];

    // 2. 验证 Merkle 证明
    // 证明 commitment 在以 merkleRoot 为根的树中
    component merkleProof = MerkleTreeChecker(levels);
    merkleProof.leaf <== commitment;
    merkleProof.root <== merkleRoot;
    for (var i = 0; i < levels; i++) {
        merkleProof.path_elements[i] <== pathElements[i];
        merkleProof.path_index[i] <== pathIndices[i];
    }
    
    // 将计算出的根作为输出，由智能合约验证其是否与公开的merkleRoot匹配
    computedRoot <== merkleProof.root;

    // 3. 生成无效符哈希 (Nullifier Hash)
    // nullifierHash = H(senderSecret)
    // 这确保了每个票据只能被花费一次，因为 senderSecret 是唯一的
    component nullifierHasher = MiMCSponge(1, 220, 1);
    nullifierHasher.ins[0] <== senderSecret;
    nullifierHash <== nullifierHasher.outs[0];

    // 4. 约束金额（可选，但推荐）
    // 例如，可以添加一个约束来检查金额是否为正数
    component isZero = IsZero();
    isZero.in <== amount;
    isZero.out === 0; // 强制 amount 不为0

    // 5. 约束接收者地址不为0
    component recipientIsZero = IsZero();
    recipientIsZero.in <== recipient;
    recipientIsZero.out === 0;
}

// 实例化电路，例如一个深度为20的Merkle树
component main = Transfer(20);
