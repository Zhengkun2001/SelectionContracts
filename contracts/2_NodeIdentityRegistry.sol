// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "./1_BLSSignature.sol";

/**
 * @title NodeIdentityRegistry
 * @dev 公有链环境下的节点身份确权智能合约（DID+资产质押）
 * 适配 Dynamic-EquiSelect 方案，支持身份注册、验证、冻结、罚没、注销
 */
contract NodeIdentityRegistry is ReentrancyGuard, AccessControl, BLSSignature {
    // ==================== 核心数据结构 ====================
    struct NodeInfo {
        bytes blsPublicKey; // BLS12-381 G1压缩公钥（48字节）
        bytes32 nodeID; // 唯一标识：SHA-256(pk || salt)
        uint256 stakeAmount; // 质押金额（wei）
        uint256 stakeTime; // 质押时间（区块时间戳）
        uint256 joinTime; // 加入时间（区块时间戳）
        Status status; // 身份状态
        uint256 violationCount; // 违规次数（累计3次永久冻结）
        string ipfsAuxHash; // 辅助信息IPFS哈希（设备信息、带宽声明等）
    }

    enum Status {
        Inactive, // 未激活（注册中）0
        Active, // 活跃（可参与筛选）1
        Frozen, // 冻结（违规暂禁）2
        Revoked, // 注销（主动退出）3
        PermanentlyFrozen // 永久冻结（多次违规）4
    }

    // ==================== 状态变量 ====================
    bytes32 public constant SELECTION_CONTRACT_ROLE = keccak256("SELECTION_CONTRACT_ROLE");
    string public constant DID_PREFIX = "did:ethr:";
    address public immutable contractAddress;
    uint256 public baseMinStake; // 统一最低质押额（替代节点级minStakeRequired）
    uint256 public constant VIOLATION_LIMIT = 3; // 最大违规次数
    uint256 public constant STAKING_LOCK_PERIOD = 7 days; // 质押冻结期
    uint256 public constant FREEZE_DURATION = 3 days; // 临时冻结时长

    // 核心存储映射
    mapping(string => NodeInfo) public nodeRegistry; // DID → 节点信息
    mapping(bytes => string) public pkToDID; // BLS公钥 → DID（防复用）
    mapping(address => string[]) public ownerToDIDs; // 地址 → 关联的DID数组
    mapping(string => uint256) public didToCandidateIndex; // DID → 候选池索引（优化删除）
    mapping(string => uint256) public didFrozenUntil; // DID → 临时冻结结束时间
    mapping(string => uint256) public didWithdrawUnlockTime; // DID → 提款解锁时间

    // 活跃节点候选池（供筛选合约读取）
    string[] public activeCandidatePool;

    // ==================== 事件定义 ====================
    event DIDCreated(string indexed did, bytes indexed blsPk, uint256 stakeAmount, uint256 timestamp);
    event IdentityVerified(string indexed did, bool isVerified, uint256 timestamp);
    event NodeFrozen(string indexed did, string reason, uint256 violationCount, uint256 timestamp);
    event NodeUnfrozen(string indexed did, uint256 timestamp);
    event StakeConfiscated(string indexed did, uint256 confiscatedAmount, uint256 timestamp);
    event DIDRevoked(string indexed did, uint256 unlockTime, uint256 timestamp);
    event PublicKeyUpdated(string indexed did, bytes oldPk, bytes newPk, uint256 timestamp);
    event BaseMinStakeUpdated(uint256 oldBaseMinStake, uint256 newBaseMinStake, uint256 timestamp);
    event StakeWithdrawn(string indexed did, uint256 withdrawAmount, uint256 timestamp);

    // ==================== 构造函数 ====================
    constructor(uint256 _baseMinStake, address _selectionContract) {
        require(_baseMinStake > 0, "Base stake cannot be zero");
        require(_selectionContract != address(0), "Invalid selection contract");

        baseMinStake = _baseMinStake;
        contractAddress = address(this);

        // 授权筛选合约角色 + 部署者为默认管理员
        _grantRole(SELECTION_CONTRACT_ROLE, _selectionContract);
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    // ==================== 核心函数：身份注册 ====================
    function createDID(
        bytes calldata _blsPk,
        bytes32 _nodeID, // 改为bytes32（直接传入哈希值）
        bytes32 _salt,
        bytes calldata _signature,
        string calldata _ipfsAuxHash
    ) external payable nonReentrant returns (string memory did) {
        // 1. 基础参数校验
        require(_blsPk.length == 48, "Invalid BLS pk (must be 48 bytes)");
        require(_signature.length == 96, "Invalid BLS sig (must be 96 bytes)");
        require(_strEquals(pkToDID[_blsPk], ""), "Public key already bound to DID");

        // 2. 验证nodeID合法性（pk + salt 哈希匹配）
        bytes32 computedNodeID = sha256(abi.encodePacked(_blsPk, _salt));
        require(_nodeID == computedNodeID, "Invalid NodeID (mismatch pk/salt)");

        // 3. BLS签名验证（验证pk + nodeID + salt的签名）
        bytes32 message = sha256(abi.encodePacked(_blsPk, _nodeID, _salt));
        require(verifyBLSSignature(_blsPk, message, _signature), "Invalid BLS signature");

        // 4. 质押金额校验
        require(msg.value >= baseMinStake, "Insufficient stake (below base requirement)");

        // 5. 生成W3C标准DID（did:ethr:{合约地址}:{nodeID}）
        did = string(abi.encodePacked(DID_PREFIX, toString(contractAddress), ":", toString(_nodeID)));
        require(nodeRegistry[did].nodeID.length == 0, "DID already exists");

        // 6. 存储节点信息
        nodeRegistry[did] = NodeInfo({
            blsPublicKey: _blsPk,
            nodeID: _nodeID,
            stakeAmount: msg.value,
            stakeTime: block.timestamp,
            joinTime: block.timestamp,
            status: Status.Active,
            violationCount: 0,
            ipfsAuxHash: _ipfsAuxHash
        });

        // 7. 绑定关联关系（公钥→DID、地址→DID、DID→候选池索引）
        pkToDID[_blsPk] = did;
        ownerToDIDs[msg.sender].push(did);
        
        uint256 candidateIndex = activeCandidatePool.length;
        activeCandidatePool.push(did);
        didToCandidateIndex[did] = candidateIndex;

        // 8. 触发事件
        emit DIDCreated(did, _blsPk, msg.value, block.timestamp);
    }

    // ==================== 核心函数：身份验证 ====================
    function verifyIdentity(
        string calldata _did,
        bytes calldata _proof,
        bytes32 _blockHash,
        uint256 _timestamp
    ) external returns (bool isVerified) {
        NodeInfo storage node = nodeRegistry[_did];

        // 1. 基础状态校验
        require(node.nodeID.length > 0, "DID not registered");
        require(node.status == Status.Active, "Node is not active (frozen/revoked)");

        // 2. 时间戳防重放（±5个区块，假设15秒/块）
        uint256 blockTime = block.timestamp;
        require(
            _timestamp >= blockTime - 5 * 15 && _timestamp <= blockTime + 5 * 15,
            "Invalid timestamp (replay attack)"
        );

        // 3. BLS签名验证（验证did + blockHash + timestamp的签名）
        bytes32 message = sha256(abi.encodePacked(_did, _blockHash, _timestamp));
        require(verifyBLSSignature(node.blsPublicKey, message, _proof), "Invalid verification proof");

        // 4. 质押金额校验（满足当前基础最低要求）
        require(node.stakeAmount >= baseMinStake, "Stake below current requirement");

        emit IdentityVerified(_did, true, block.timestamp);
        return true;
    }

    // ==================== 核心函数：质押罚没与冻结 ====================
    function freezeAndConfiscateStake(string calldata _did, string calldata _reason)
        external
        onlyRole(SELECTION_CONTRACT_ROLE)
        nonReentrant
    {
        NodeInfo storage node = nodeRegistry[_did];
        require(node.nodeID.length > 0, "DID not registered");
        require(node.status != Status.PermanentlyFrozen, "Node already permanently frozen");

        // 1. 累计违规次数
        node.violationCount += 1;
        uint256 currentViolation = node.violationCount;

        // 2. 更新状态与冻结时间
        if (currentViolation >= VIOLATION_LIMIT) {
            node.status = Status.PermanentlyFrozen;
            delete didFrozenUntil[_did]; // 永久冻结无需解冻时间
        } else {
            node.status = Status.Frozen;
            didFrozenUntil[_did] = block.timestamp + FREEZE_DURATION; // 临时冻结3天
        }

        // 3. 罚没质押资产（转入筛选合约）
        uint256 confiscatedAmount = node.stakeAmount;
        node.stakeAmount = 0;
        payable(msg.sender).transfer(confiscatedAmount); // 2300 gas限制防重入

        // 4. 从候选池移除
        removeFromCandidatePool(_did);

        // 5. 触发事件
        emit NodeFrozen(_did, _reason, currentViolation, block.timestamp);
        emit StakeConfiscated(_did, confiscatedAmount, block.timestamp);
    }

    // ==================== 核心函数：身份状态管理 ====================
    // 节点主动注销DID
    function revokeDID() external nonReentrant {
        string memory did = getDIDBySender();
        NodeInfo storage node = nodeRegistry[did];
        require(
            node.status == Status.Active || node.status == Status.Frozen,
            "Invalid node status (only active/frozen can revoke)"
        );

        // 1. 更新状态与提款解锁时间
        node.status = Status.Revoked;
        didWithdrawUnlockTime[did] = block.timestamp + STAKING_LOCK_PERIOD;

        // 2. 从候选池移除
        removeFromCandidatePool(did);

        // 3. 触发事件
        emit DIDRevoked(did, didWithdrawUnlockTime[did], block.timestamp);
    }

    // 临时冻结节点解冻（需重新质押）
    function unfreezeDID() external payable nonReentrant {
        string memory did = getDIDBySender();
        NodeInfo storage node = nodeRegistry[did];

        // 1. 解冻条件校验
        require(node.status == Status.Frozen, "Node is not frozen");
        require(node.violationCount < VIOLATION_LIMIT, "Cannot unfreeze permanently frozen node");
        require(block.timestamp >= didFrozenUntil[did], "Cannot unfreeze before freeze period ends");
        require(msg.value >= baseMinStake, "Insufficient stake to unfreeze");

        // 2. 更新状态与质押金额
        node.status = Status.Active;
        node.stakeAmount = msg.value;

        // 3. 重新加入候选池
        uint256 candidateIndex = activeCandidatePool.length;
        activeCandidatePool.push(did);
        didToCandidateIndex[did] = candidateIndex;

        // 4. 触发事件
        emit NodeUnfrozen(did, block.timestamp);
    }

    // 节点更新BLS公钥（密钥轮换）
    function updatePublicKey(bytes calldata _newBlsPk, bytes calldata _signature) external nonReentrant {
        // 1. 基础参数校验
        require(_newBlsPk.length == 48, "Invalid new BLS pk (must be 48 bytes)");
        require(_signature.length == 96, "Invalid signature (must be 96 bytes)");
        require(_strEquals(pkToDID[_newBlsPk], ""), "New public key already bound to DID");

        // 2. 验证调用者身份
        string memory did = getDIDBySender();
        NodeInfo storage node = nodeRegistry[did];
        bytes memory oldPk = node.blsPublicKey;

        // 3. 验证原私钥签名（确保所有者操作）
        bytes32 message = sha256(abi.encodePacked(did, _newBlsPk));
        require(verifyBLSSignature(oldPk, message, _signature), "Invalid signature for key update");

        // 4. 更新公钥映射
        delete pkToDID[oldPk];
        pkToDID[_newBlsPk] = did;
        node.blsPublicKey = _newBlsPk;

        // 5. 触发事件
        emit PublicKeyUpdated(did, oldPk, _newBlsPk, block.timestamp);
    }

    // 质押金提款（注销后冻结期结束）
    function withdrawStake() external nonReentrant {
        string memory did = getDIDBySender();
        NodeInfo storage node = nodeRegistry[did];
        uint256 unlockTime = didWithdrawUnlockTime[did];

        // 1. 提款条件校验
        require(node.status == Status.Revoked, "DID not revoked");
        require(block.timestamp >= unlockTime, "Stake still locked (wait for freeze period)");
        require(node.stakeAmount > 0, "No stake to withdraw");

        // 2. 转账给用户（先清空状态再转账，防重入）
        uint256 withdrawAmount = node.stakeAmount;
        node.stakeAmount = 0;
        delete didWithdrawUnlockTime[did];

        (bool success, ) = msg.sender.call{value: withdrawAmount}("");
        require(success, "Stake withdrawal failed");

        // 3. 触发事件
        emit StakeWithdrawn(did, withdrawAmount, block.timestamp);
    }

    // ==================== 辅助函数 ====================
    // 从候选池移除节点（O(1)效率）
    function removeFromCandidatePool(string memory _did) internal {
        uint256 targetIndex = didToCandidateIndex[_did];
        uint256 lastIndex = activeCandidatePool.length - 1;

        // 若目标不是最后一个元素，交换到末尾
        if (targetIndex != lastIndex) {
            string memory lastDID = activeCandidatePool[lastIndex];
            activeCandidatePool[targetIndex] = lastDID;
            didToCandidateIndex[lastDID] = targetIndex; // 更新最后一个元素的索引
        }

        // 删除末尾元素并清空索引
        activeCandidatePool.pop();
        delete didToCandidateIndex[_did];
    }

    // 获取调用者绑定的DID（默认返回第一个，支持多DID扩展）
    function getDIDBySender() internal view returns (string memory) {
        string[] memory userDIDs = ownerToDIDs[msg.sender];
        require(userDIDs.length > 0, "Sender not bound to any DID");
        return userDIDs[0]; // 若需多DID，可扩展为传入索引参数
    }

    // ==================== 工具函数 ====================
    // 地址转字符串（十六进制格式）
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

    // bytes32转字符串（十六进制格式）
    function toString(bytes32 _value) internal pure returns (string memory) {
        bytes memory alphabet = "0123456789abcdef";
        bytes memory str = new bytes(66);

        str[0] = '0';
        str[1] = 'x';
        for (uint256 i = 0; i < 32; i++) {
            str[2 + i * 2] = alphabet[uint8(_value[i] >> 4)];
            str[3 + i * 2] = alphabet[uint8(_value[i] & 0x0f)];
        }
        return string(str);
    }

    // 字符串比较（避免重复keccak256计算）
    function _strEquals(string memory _a, string memory _b) internal pure returns (bool) {
        return keccak256(bytes(_a)) == keccak256(bytes(_b));
    }

    // ==================== 权限管理函数 ====================
    // 更新基础最低质押额（适配资产价格波动）
    function updateBaseMinStake(uint256 _newBaseMinStake) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(_newBaseMinStake > 0, "Base stake cannot be zero");
        uint256 oldBaseMinStake = baseMinStake;
        baseMinStake = _newBaseMinStake;
        emit BaseMinStakeUpdated(oldBaseMinStake, _newBaseMinStake, block.timestamp);
    }

    // 授权新的筛选合约（兼容方案迭代）
    function grantSelectionContractRole(address _newContract) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(_newContract != address(0), "Invalid selection contract (zero address)");
        grantRole(SELECTION_CONTRACT_ROLE, _newContract);
    }

    // ==================== 误转ETH处理 ====================
    // 接收误转的ETH并自动退还
    receive() external payable {
        (bool success, ) = msg.sender.call{value: msg.value}("");
        require(success, "Refund failed for accidental ETH transfer");
    }
}