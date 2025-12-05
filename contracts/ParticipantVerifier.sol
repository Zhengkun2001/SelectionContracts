// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library MerkleProof {
    function verify(bytes32[] memory proof, bytes32 root, bytes32 leaf) internal pure returns (bool) {
        bytes32 computedHash = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 proofElement = proof[i];
            if (computedHash < proofElement) {
                computedHash = keccak256(abi.encodePacked(computedHash, proofElement));
            } else {
                computedHash = keccak256(abi.encodePacked(proofElement, computedHash));
            }
        }
        return computedHash == root;
    }
}

contract ParticipantVerifier {
    bytes32 public finalMerkleRoot; // 最终参与者Merkle Root

    event MerkleRootUpdated(bytes32 newRoot);

    // 更新Merkle Root
    function updateMerkleRoot(bytes32 newRoot) external {
        finalMerkleRoot = newRoot;
        emit MerkleRootUpdated(newRoot);
    }

    // 验证是否为最终参与者
    function isFinalParticipant(address participant, bytes32[] calldata proof) external view returns (bool) {
        bytes32 leaf = keccak256(abi.encodePacked(participant));
        return MerkleProof.verify(proof, finalMerkleRoot, leaf);
    }
}