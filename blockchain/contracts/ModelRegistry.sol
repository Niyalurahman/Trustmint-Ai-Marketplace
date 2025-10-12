// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import "./ModelNFT.sol";

contract ModelRegistry is Ownable {
    // mapping developer wallet => cliEthereumAddress (address derived from CLI pubkey)
    mapping(address => address) public registeredCLI;

    ModelNFT public modelNFT;

    struct Model {
        uint256 id;
        address developer;
        string metadataCid; // e.g. ipfs://<CID>/metadata.json
        bytes cliSignature; // ecrecover signature over metadataHash
        uint256 tokenId; // minted token id
        uint256 timestamp;
    }

    Model[] public models;
    mapping(uint256 => uint256) public modelIndexByToken; // tokenId => models index

    event DeveloperRegistered(address indexed developer, address cliAddress);
    event ModelRegistered(uint256 indexed modelId, address indexed developer, string cid, uint256 tokenId);

    // Forward Ownable constructor with msg.sender
    constructor(address _modelNft) Ownable(msg.sender) {
        modelNFT = ModelNFT(_modelNft);
    }

    // Developers call this once to bind their wallet to a CLI (cliAddress = derived eth address of CLI pubkey)
    function registerDeveloper(address cliAddress) external {
        registeredCLI[msg.sender] = cliAddress;
        emit DeveloperRegistered(msg.sender, cliAddress);
    }

    // Single-call register + mint: user calls from their wallet
    // metadataHash: keccak256 hash of canonical metadata (32 bytes)
    // metadataCid: "ipfs://<CID>/metadata.json"
    // cliSignature: signature bytes (r||s||v)
    // tokenURI: ipfs uri or metadata json URL for the minted token
    function registerModelAndMint(
        bytes32 metadataHash,
        string calldata metadataCid,
        bytes calldata cliSignature,
        address to,
        string calldata tokenURI
    ) external returns (uint256) {
        address recovered = recoverSigner(metadataHash, cliSignature);
        require(recovered == registeredCLI[msg.sender], "cli signature mismatch");

        // mint NFT to 'to'
        uint256 tokenId = modelNFT.mintTo(to, tokenURI);

        // store model
        Model memory m = Model({
            id: models.length,
            developer: msg.sender,
            metadataCid: metadataCid,
            cliSignature: cliSignature,
            tokenId: tokenId,
            timestamp: block.timestamp
        });

        models.push(m);
        uint256 idx = models.length - 1;
        modelIndexByToken[tokenId] = idx;

        emit ModelRegistered(idx, msg.sender, metadataCid, tokenId);
        return tokenId;
    }

    function recoverSigner(bytes32 hashed, bytes memory signature) public pure returns (address) {
        require(signature.length == 65, "invalid sig length");
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
        }
        if (v < 27) { v += 27; }
        return ecrecover(hashed, v, r, s);
    }

    // helper read
    function getModel(uint256 id) external view returns (Model memory) {
        return models[id];
    }
}
