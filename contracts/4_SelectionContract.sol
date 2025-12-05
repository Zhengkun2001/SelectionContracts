// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "./3_NodeIdentityRegistry.sol";

/**
 * @title SelectionContract
 * @dev Dynamic-EquiSelect核心筛选合约，整合链下算法结果+链上确权验证
 */
contract SelectionContract is ReentrancyGuard, AccessControl {
    // ==================== 核心配置 ====================
    bytes32 public constant CALCULATOR_ROLE = keccak256("CALCULATOR_ROLE"); // 链下计算节点角色
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    uint256 public constant EPOCH_DURATION = 7 days; // 筛选周期
    uint256 public currentEpoch; // 当前Epoch
    uint256 public baseIncentive; // 基础激励（ERC20代币）

    // ==================== 状态变量 ====================
    NodeIdentityRegistry public immutable nodeRegistry; // 节点确权合约
    IERC20 public immutable incentiveToken; // 激励代币

    // Epoch → 筛选结果Merkle Root
    mapping(uint256 => bytes32) public epochMerkleRoot;
    // Epoch → 最终选中的DID列表
    mapping(uint256 => string[]) public epochSelectedDIDs;
    // DID → Epoch → 是否领取激励
    mapping(string => mapping(uint256 => bool)) public incentiveClaimed;
    // AHP权重哈希（防篡改）
    mapping(uint256 => bytes32) public epochAHPWeightHash;

    // ==================== 事件 ====================
    event EpochStarted(uint256 indexed epoch, uint256 timestamp);
    event SelectionResultUpdated(uint256 indexed epoch, bytes32 merkleRoot, uint256 timestamp);
    event IncentiveClaimed(string indexed did, uint256 indexed epoch, uint256 amount, uint256 timestamp);
    event AHPWeightUpdated(uint256 indexed epoch, bytes32 weightHash, uint256 timestamp);

    // ==================== 构造函数 ====================
    constructor(
        address payable _nodeRegistry,
        address _incentiveToken,
        uint256 _baseIncentive,
        address _calculator
    ) {
        require(_nodeRegistry != address(0), "Invalid registry address");
        require(_incentiveToken != address(0), "Invalid token address");
        require(_baseIncentive > 0, "Base incentive cannot be zero");

        nodeRegistry = NodeIdentityRegistry(payable(_nodeRegistry));
        incentiveToken = IERC20(_incentiveToken);
        baseIncentive = _baseIncentive;

        _grantRole(CALCULATOR_ROLE, _calculator);
        _grantRole(ADMIN_ROLE, msg.sender);

        currentEpoch = 1;
        emit EpochStarted(currentEpoch, block.timestamp);
    }

    // ==================== 链下算法结果上链 ====================
    /**
     * @dev 上传Epoch筛选结果（链下计算节点调用）
     * @param _epoch 周期编号
     * @param _merkleRoot 最终选中节点的Merkle Root
     * @param _selectedDIDs 最终选中的DID列表
     * @param _ahpWeightHash AHP权重哈希（keccak256(权重数组)）
     */
    function uploadSelectionResult(
    uint256 _epoch,
    bytes32 _merkleRoot,
    string[] calldata _selectedDIDs,
    bytes32 _ahpWeightHash
    ) external onlyRole(CALCULATOR_ROLE) {
        require(_epoch == currentEpoch, "Invalid epoch");
        require(_merkleRoot != bytes32(0), "Invalid merkle root");
        require(_selectedDIDs.length > 0, "Empty selected DIDs");

        epochMerkleRoot[_epoch] = _merkleRoot;
        epochAHPWeightHash[_epoch] = _ahpWeightHash;
        
        for (uint256 i = 0; i < _selectedDIDs.length; i++) {
            string memory did = _selectedDIDs[i];
            // 正确引用：合约名.结构体名
            NodeIdentityRegistry.NodeInfo memory node = nodeRegistry.getNodeInfo(did);
            
            // 正确引用：合约名.枚举名.枚举值
            require(node.status == NodeIdentityRegistry.Status.Active, "Node not active");
            require(node.stakeAmount >= nodeRegistry.baseMinStake(), "Insufficient stake");
            
            epochSelectedDIDs[_epoch].push(did);
        }

        emit SelectionResultUpdated(_epoch, _merkleRoot, block.timestamp);
        emit AHPWeightUpdated(_epoch, _ahpWeightHash, block.timestamp);
    }

    // ==================== 激励发放 ====================
    /**
     * @dev 节点申领Epoch激励（梯度激励：baseIncentive * 综合分/10000）
     * @param _epoch 周期编号
     * @param _totalScore 链下计算的综合分（放大10000倍，如0.85→8500）
     * @param _merkleProof Merkle验证证明
     */
    function claimIncentive(
        uint256 _epoch,
        uint256 _totalScore,
        bytes32[] calldata _merkleProof
    ) external nonReentrant {
        // 1. 获取调用者的DID
        string memory did = nodeRegistry.getDIDBySender();
        require(!incentiveClaimed[did][_epoch], "Incentive already claimed");

        // 2. Merkle验证（是否在选中列表中）
        bytes32 leaf = keccak256(bytes(did));
        require(verifyMerkleProof(_merkleProof, epochMerkleRoot[_epoch], leaf), "Invalid merkle proof");

        // 3. 验证节点状态
        NodeIdentityRegistry.NodeInfo memory node = nodeRegistry.getNodeInfo(did);
        require(node.status == NodeIdentityRegistry.Status.Active, "Node not active");

        // 4. 计算梯度激励（baseIncentive * 综合分/10000）
        uint256 incentive = baseIncentive * _totalScore / 10000;
        require(incentive > 0, "Incentive is zero");

        // 5. 发放代币
        require(incentiveToken.transfer(msg.sender, incentive), "Token transfer failed");
        incentiveClaimed[did][_epoch] = true;

        emit IncentiveClaimed(did, _epoch, incentive, block.timestamp);
    }

    // ==================== 违规节点处理 ====================
    /**
     * @dev 罚没违规节点（调用确权合约的冻结+罚没）
     * @param _did 违规节点DID
     * @param _reason 违规原因
     */
    function punishViolation(string calldata _did, string calldata _reason) external onlyRole(ADMIN_ROLE) {
        nodeRegistry.freezeAndConfiscateStake(_did, _reason);
    }

    // ==================== 周期管理 ====================
    /**
     * @dev 启动新Epoch
     */
    function startNewEpoch() external onlyRole(ADMIN_ROLE) {
        currentEpoch += 1;
        emit EpochStarted(currentEpoch, block.timestamp);
    }

    // ==================== 辅助函数 ====================
    /**
     * @dev Merkle Proof验证（适配链下生成的Merkle树）
     */
    function verifyMerkleProof(
        bytes32[] calldata _proof,
        bytes32 _root,
        bytes32 _leaf
    ) internal pure returns (bool) {
        bytes32 computedHash = _leaf;
        for (uint256 i = 0; i < _proof.length; i++) {
            bytes32 proofElement = _proof[i];
            if (computedHash < proofElement) {
                computedHash = keccak256(abi.encodePacked(computedHash, proofElement));
            } else {
                computedHash = keccak256(abi.encodePacked(proofElement, computedHash));
            }
        }
        return computedHash == _root;
    }

    // ==================== 权限/配置管理 ====================
    function updateBaseIncentive(uint256 _newBaseIncentive) external onlyRole(ADMIN_ROLE) {
        require(_newBaseIncentive > 0, "Invalid base incentive");
        baseIncentive = _newBaseIncentive;
    }

    function grantCalculatorRole(address _calculator) external onlyRole(ADMIN_ROLE) {
        grantRole(CALCULATOR_ROLE, _calculator);
    }
}