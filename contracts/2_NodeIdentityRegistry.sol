// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol"; // 防重入攻击
import "@openzeppelin/contracts/access/AccessControl.sol"; // 权限控制（筛选合约专属调用）
import "./1_BLSSignature.sol";

/**
 * @title NodeIdentityRegistry
 * @dev 公有链环境下的节点身份确权智能合约（DID+资产质押）
 * 适配 Dynamic-EquiSelect 方案，支持身份注册、验证、冻结、罚没
 */
contract NodeIdentityRegistry is ReentrancyGuard, AccessControl, BLSSignature{
    // ==================== 核心数据结构 ====================
    /**
     * @dev 节点身份信息结构体（链上存储核心数据）
     */
    struct NodeInfo {
        bytes blsPublicKey; // BLS12-381 公钥（十六进制编码）
        string nodeID; // 唯一标识：SHA-256(pk || salt)
        uint256 stakeAmount; // 质押金额（ wei 单位）
        uint256 stakeTime; // 质押时间（区块时间戳）
        uint256 joinTime; // 加入时间（区块时间戳）
        Status status; // 身份状态
        uint256 minStakeRequired; // 该节点当前最低质押要求（阶梯质押用）
        uint256 violationCount; // 违规次数（累计3次触发永久冻结）
        string ipfsAuxHash; // 辅助信息IPFS哈希（如设备信息、带宽声明）
    }

    /**
     * @dev 身份状态枚举（覆盖动态生命周期）
     */
    enum Status {
        Inactive, // 未激活（注册中）
        Active, // 活跃（可参与筛选）
        Frozen, // 冻结（违规暂禁）
        Revoked, // 注销（主动退出）
        PermanentlyFrozen // 永久冻结（多次违规）
    }

    // ==================== 状态变量 ====================
    bytes32 public constant SELECTION_CONTRACT_ROLE = keccak256("SELECTION_CONTRACT_ROLE"); // 筛选合约角色（唯一可触发罚没）
    string public constant DID_PREFIX = "did:ethr:"; // DID前缀（W3C标准）
    address public immutable contractAddress; // 合约地址（DID组成部分）
    uint256 public baseMinStake; // 基础最低质押额（如 0.1 ETH = 1e17 wei）
    uint256 public constant VIOLATION_LIMIT = 3; // 最大违规次数（超3次永久冻结）
    uint256 public constant STAKING_LOCK_PERIOD = 7 days; // 质押冻结期（退出后7天解锁）

    // DID → 节点信息映射（核心存储）
    mapping(string => NodeInfo) public nodeRegistry;
    // 公钥 → DID 映射（防公钥复用，防女巫攻击）
    mapping(bytes => string) public pkToDID;
    // 活跃节点候选池（链上集合，供筛选合约读取）
    string[] public activeCandidatePool;

    // ==================== 事件定义（供其他模块监听） ====================
    event DIDCreated(string indexed did, bytes indexed blsPk, uint256 stakeAmount, uint256 timestamp);
    event IdentityVerified(string indexed did, bool isVerified, uint256 timestamp);
    event NodeFrozen(string indexed did, string reason, uint256 violationCount, uint256 timestamp);
    event NodeUnfrozen(string indexed did, uint256 timestamp);
    event StakeConfiscated(string indexed did, uint256 confiscatedAmount, uint256 timestamp);
    event DIDRevoked(string indexed did, uint256 unlockTime, uint256 timestamp);
    event PublicKeyUpdated(string indexed did, bytes oldPk, bytes newPk, uint256 timestamp);

    // ==================== 构造函数（初始化） ====================
    constructor(uint256 _baseMinStake, address _selectionContract) {
        require(_baseMinStake > 0, "Base stake cannot be zero");
        require(_selectionContract != address(0), "Invalid selection contract");
        baseMinStake = _baseMinStake;
        contractAddress = address(this);
        _grantRole(SELECTION_CONTRACT_ROLE, _selectionContract); // 授权筛选合约触发罚没
    }

    // ==================== 核心函数：身份注册（createDID） ====================
    /**
     * @dev 节点创建DID并完成质押确权
     * @param _blsPk BLS12-381 公钥（十六进制编码）
     * @param _nodeID 本地生成的唯一标识（SHA-256(pk || salt)）
     * @param _salt 随机盐值（与 nodeID 生成时一致）
     * @param _signature BLS签名（sk 对 (pk || nodeID || salt) 的签名）
     * @param _ipfsAuxHash 辅助信息IPFS哈希（可选）
     * @return did 生成的去中心化身份标识
     */
    function createDID(
        bytes calldata _blsPk,
        string calldata _nodeID,
        bytes32 _salt,
        bytes calldata _signature,
        string calldata _ipfsAuxHash
    ) external payable nonReentrant returns (string memory did) {
        // 1. 输入合法性校验
        require(_blsPk.length > 0, "BLS public key cannot be empty");
        require(bytes(_nodeID).length > 0, "NodeID cannot be empty");
        require(_signature.length > 0, "Signature cannot be empty");
        // 比较字符串哈希：将存储的字符串和空字符串都转为bytes，计算keccak256后比较
        require(
            keccak256(bytes(pkToDID[_blsPk])) == keccak256(bytes("")), 
            "Public key already bound to DID"
        );

        // 2. 验证 nodeID 合法性（确保由当前公钥+盐值生成）
        bytes32 computedNodeID = keccak256(abi.encodePacked(_blsPk, _salt));
        require(keccak256(bytes(_nodeID)) == computedNodeID, "Invalid NodeID (mismatch pk/salt)");

        // 3. 验证 BLS 签名（此处需对接 BLS12-381 验证库，示例用接口表示）
        bytes32 message = keccak256(abi.encodePacked(_blsPk, _nodeID, _salt));
        require(verifyBLS签名(_blsPk, message, _signature), "Invalid BLS signature");

        // 4. 质押金额校验（新节点按基础最低质押额要求）
        uint256 requiredStake = baseMinStake;
        require(msg.value >= requiredStake, "Insufficient stake (below base requirement)");

        // 5. 生成 DID（W3C 标准格式：did:ethr:{合约地址}:{nodeID}）
        did = string(abi.encodePacked(DID_PREFIX, toString(contractAddress), ":", _nodeID));
        require(
            bytes(nodeRegistry[did].nodeID).length == 0, 
            "DID already exists" // 防重复注册
        );
        // 6. 存储节点信息
        nodeRegistry[did] = NodeInfo({
            blsPublicKey: _blsPk,
            nodeID: _nodeID,
            stakeAmount: msg.value,
            stakeTime: block.timestamp,
            joinTime: block.timestamp,
            status: Status.Active, // 注册成功直接激活
            minStakeRequired: requiredStake,
            violationCount: 0,
            ipfsAuxHash: _ipfsAuxHash
        });

        // 7. 绑定公钥与 DID
        pkToDID[_blsPk] = did;

        // 8. 加入活跃候选池
        activeCandidatePool.push(did);

        // 9. 触发事件（供筛选合约监听）
        emit DIDCreated(did, _blsPk, msg.value, block.timestamp);
    }

    // ==================== 核心函数：身份验证（verifyIdentity） ====================
    /**
     * @dev 筛选前验证节点身份有效性（由筛选合约调用）
     * @param _did 节点DID
     * @param _proof BLS签名（sk 对 (did || blockHash || timestamp) 的签名）
     * @param _blockHash 当前筛选轮次的区块哈希
     * @param _timestamp 签名时间戳
     * @return isVerified 验证结果
     */
    function verifyIdentity(
        string calldata _did,
        bytes calldata _proof,
        bytes32 _blockHash,
        uint256 _timestamp
    ) external view returns (bool isVerified) {
        NodeInfo storage node = nodeRegistry[_did];

        // 校验1：DID已注册且状态活跃
        require(bytes(node.nodeID).length > 0, "DID not registered");
        require(node.status == Status.Active, "Node is not active (frozen/revoked)");

        // 校验2：时间戳防重放攻击（允许±5个区块时间偏差）
        uint256 blockTime = block.timestamp;
        require(_timestamp >= blockTime - 5 * 15 && _timestamp <= blockTime + 5 * 15, "Invalid timestamp (replay attack)");

        // 校验3：BLS签名有效性
        bytes32 message = keccak256(abi.encodePacked(_did, _blockHash, _timestamp));
        require(verifyBLS签名(node.blsPublicKey, message, _proof), "Invalid verification proof");

        // 校验4：质押状态有效（金额≥当前最低要求）
        require(node.stakeAmount >= node.minStakeRequired, "Stake below current requirement");

        return true;
    }

    // ==================== 核心函数：质押罚没与冻结（仅筛选合约可调用） ====================
    /**
     * @dev 触发质押罚没并冻结节点（由筛选合约检测到违规后调用）
     * @param _did 违规节点DID
     * @param _reason 违规原因（如"提交错误结果"、"伪造签名"）
     */
    function freezeAndConfiscateStake(string calldata _did, string calldata _reason) external onlyRole(SELECTION_CONTRACT_ROLE) {
        NodeInfo storage node = nodeRegistry[_did];
        require(bytes(node.nodeID).length > 0, "DID not registered");
        require(node.status != Status.PermanentlyFrozen, "Node already permanently frozen");

        // 1. 累计违规次数
        node.violationCount += 1;
        uint256 currentViolation = node.violationCount;

        // 2. 冻结节点状态
        if (currentViolation >= VIOLATION_LIMIT) {
            node.status = Status.PermanentlyFrozen; // 超3次永久冻结
        } else {
            node.status = Status.Frozen; // 未超3次临时冻结
        }

        // 3. 罚没质押资产（转入指定地址，如社区基金）
        uint256 confiscatedAmount = node.stakeAmount;
        node.stakeAmount = 0; // 清空质押金额
        (bool success, ) = msg.sender.call{value: confiscatedAmount}(""); // 筛选合约接收罚没资产（可自定义接收地址）
        require(success, "Stake confiscation failed");

        // 4. 从候选池移除
        removeFromCandidatePool(_did);

        // 5. 触发事件
        emit NodeFrozen(_did, _reason, currentViolation, block.timestamp);
        emit StakeConfiscated(_did, confiscatedAmount, block.timestamp);
    }

    // ==================== 辅助函数：身份状态管理 ====================
    /**
     * @dev 节点主动注销DID（退出系统）
     */
    function revokeDID() external nonReentrant {
        string memory did = getDIDBySender(); // 通过签名验证当前调用者是DID所有者
        NodeInfo storage node = nodeRegistry[did];
        require(node.status == Status.Active || node.status == Status.Frozen, "Invalid node status");

        // 1. 更新状态为注销
        node.status = Status.Revoked;

        // 2. 从候选池移除
        removeFromCandidatePool(did);

        // 3. 触发事件（退出后7天解锁质押资产）
        emit DIDRevoked(did, block.timestamp + STAKING_LOCK_PERIOD, block.timestamp);
    }

    /**
     * @dev 临时冻结节点解冻（仅节点本人可申请，冻结期满后）
     */
    function unfreezeDID() external payable nonReentrant {
        string memory did = getDIDBySender();
        NodeInfo storage node = nodeRegistry[did];
        require(node.status == Status.Frozen, "Node is not frozen");
        require(node.violationCount < VIOLATION_LIMIT, "Cannot unfreeze permanently frozen node");

        // 解冻后需重新质押（金额≥当前最低要求）
        require(msg.value >= node.minStakeRequired, "Insufficient stake to unfreeze");
        node.stakeAmount = msg.value;
        node.status = Status.Active;
        activeCandidatePool.push(did); // 重新加入候选池

        emit NodeUnfrozen(did, block.timestamp);
    }

    /**
     * @dev 节点更新公钥（密钥轮换）
     * @param _newBlsPk 新BLS公钥
     * @param _signature 原私钥对（did + newPk）的签名
     */
    function updatePublicKey(bytes calldata _newBlsPk, bytes calldata _signature) external nonReentrant {
        require(_newBlsPk.length > 0, "New public key cannot be empty");
        string memory did = getDIDBySender();
        NodeInfo storage node = nodeRegistry[did];
        bytes memory oldPk = node.blsPublicKey;

        // 验证签名（确保是原私钥所有者操作）
        bytes32 message = keccak256(abi.encodePacked(did, _newBlsPk));
        require(verifyBLS签名(oldPk, message, _signature), "Invalid signature for key update");

        // 更新公钥映射
        delete pkToDID[oldPk];
        pkToDID[_newBlsPk] = did;
        node.blsPublicKey = _newBlsPk;

        emit PublicKeyUpdated(did, oldPk, _newBlsPk, block.timestamp);
    }

    // ==================== 工具函数（内部/视图） ====================
    /**
     * @dev BLS12-381 签名验证（对接实际BLS库，如 blst 合约实现）
     */
    function verifyBLS签名(bytes memory _pk, bytes32 _message, bytes memory _signature) internal pure returns (bool) {
        // 实际实现需集成 BLS12-381 验证逻辑，示例返回true（论文中需补充完整库调用）
        // 参考：https://github.com/sigp/blst-rs/tree/master/contracts
        return true;
    }

    /**
     * @dev 从候选池移除节点
     */
    function removeFromCandidatePool(string memory _did) internal {
        for (uint256 i = 0; i < activeCandidatePool.length; i++) {
            if (keccak256(bytes(activeCandidatePool[i])) == keccak256(bytes(_did))) {
                activeCandidatePool[i] = activeCandidatePool[activeCandidatePool.length - 1];
                activeCandidatePool.pop();
                break;
            }
        }
    }

    /**
     * @dev 通过签名验证当前调用者是DID所有者（工具函数）
     */
    function getDIDBySender() internal view returns (string memory) {
        // 实际实现：调用者用私钥签名当前地址，合约验证签名并关联DID（论文中需补充完整逻辑）
        // 简化示例：假设调用者地址与DID绑定（实际需通过签名验证）
        for (uint256 i = 0; i < activeCandidatePool.length; i++) {
            string memory did = activeCandidatePool[i];
            if (msg.sender == address(uint160(uint256(keccak256(bytes(did)))))) {
                return did;
            }
        }
        revert("Sender not bound to any DID");
    }

    /**
     * @dev 地址转字符串（工具函数）
     */
    function toString(address _addr) internal pure returns (string memory) {
        bytes32 value = bytes32(uint256(uint160(_addr)));
        bytes memory alphabet = "0123456789abcdef";
        bytes memory str = new bytes(42);
        str[0] = '0';
        str[1] = 'x';
        for (uint256 i = 0; i < 20; i++) {
            str[2 + i * 2] = alphabet[uint8(value[i + 12] >> 4)];
            str[3 + i * 2] = alphabet[uint8(value[i + 12] & 0x0f)];
        }
        return string(str);
    }

    // ==================== 权限管理（仅Owner可调用） ====================
    /**
     * @dev 更新基础最低质押额（适配链上资产价格波动）
     */
    function updateBaseMinStake(uint256 _newBaseMinStake) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(_newBaseMinStake > 0, "Base stake cannot be zero");
        baseMinStake = _newBaseMinStake;
    }

    /**
     * @dev 授权新的筛选合约（兼容方案迭代）
     */
    function grantSelectionContractRole(address _newContract) external onlyRole(DEFAULT_ADMIN_ROLE) {
        grantRole(SELECTION_CONTRACT_ROLE, _newContract);
    }
}