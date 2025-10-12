// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract ModelNFT is ERC721URIStorage, Ownable {
    uint256 private _nextTokenId;
    address public registry;

    // Forward ERC721 args to ERC721 and forward msg.sender to Ownable(initialOwner)
    constructor(string memory name_, string memory symbol_) 
        ERC721(name_, symbol_) 
        Ownable(msg.sender)
    {}

    modifier onlyRegistry() {
        require(msg.sender == registry, "only registry");
        _;
    }

    function setRegistry(address _registry) external onlyOwner {
        registry = _registry;
    }

    function mintTo(address to, string calldata tokenURI_) external onlyRegistry returns (uint256) {
        uint256 id = ++_nextTokenId;
        _mint(to, id);
        _setTokenURI(id, tokenURI_);
        return id;
    }
}
