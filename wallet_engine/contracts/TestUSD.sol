// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title TestUSD (TUSD): a plain ERC-20 test token for the Sentinel Wallet demo.
/// @notice TEST MONEY ONLY. It has no value. It exists so we can demonstrate transfers,
///         approvals and attacks on a local Anvil chain and on the Sepolia testnet.
/// @dev Standard ERC-20 behaviour, written without dependencies so it is easy to read.
///      An allowance of type(uint256).max is "unlimited": it is never reduced by transferFrom,
///      which is exactly why unlimited approvals are dangerous (our APR-01 rule denies them).
contract TestUSD {
    string public constant name = "TestUSD";
    string public constant symbol = "TUSD";
    uint8 public constant decimals = 18;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    /// @notice Mints 1,000,000 TUSD to whoever deploys the contract.
    constructor() {
        _mint(msg.sender, 1_000_000 * 10 ** uint256(decimals));
    }

    function transfer(address to, uint256 value) external returns (bool) {
        _transfer(msg.sender, to, value);
        return true;
    }

    function approve(address spender, uint256 value) external returns (bool) {
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    function transferFrom(address from, address to, uint256 value) external returns (bool) {
        uint256 current = allowance[from][msg.sender];
        if (current != type(uint256).max) {
            require(current >= value, "TestUSD: insufficient allowance");
            allowance[from][msg.sender] = current - value;
            emit Approval(from, msg.sender, current - value);
        }
        _transfer(from, to, value);
        return true;
    }

    function _transfer(address from, address to, uint256 value) internal {
        require(to != address(0), "TestUSD: transfer to zero address");
        require(balanceOf[from] >= value, "TestUSD: insufficient balance");
        balanceOf[from] -= value;
        balanceOf[to] += value;
        emit Transfer(from, to, value);
    }

    function _mint(address to, uint256 value) internal {
        totalSupply += value;
        balanceOf[to] += value;
        emit Transfer(address(0), to, value);
    }
}
