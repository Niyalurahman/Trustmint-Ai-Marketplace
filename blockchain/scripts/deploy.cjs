const hre = require("hardhat");
const fs = require("fs");
const path = require("path");
require("dotenv").config({ path: path.join(__dirname, "..", ".env") });

function waitForDeploy(contract) {
  if (typeof contract.waitForDeployment === "function") {
    return contract.waitForDeployment();
  } else if (typeof contract.deployed === "function") {
    return contract.deployed();
  } else if (contract.deployTransaction) {
    return contract.deployTransaction.wait();
  } else {
    return Promise.resolve();
  }
}

function contractAddress(contract) {
  return contract.target ?? contract.address;
}

function upsertEnv(envPath, key, value) {
  let content = "";
  if (fs.existsSync(envPath)) {
    content = fs.readFileSync(envPath, "utf8");
    const regex = new RegExp(`^${key}=.*$`, "m");
    if (regex.test(content)) {
      content = content.replace(regex, `${key}=${value}`);
      fs.writeFileSync(envPath, content, "utf8");
      return;
    }
  }
  // append
  const toWrite = `${content}${content && !content.endsWith("\n") ? "\n" : ""}${key}=${value}\n`;
  fs.writeFileSync(envPath, toWrite, "utf8");
}

async function main() {
  const [deployer] = await hre.ethers.getSigners();
  console.log("Deploying with", deployer.address);

  const ModelNFT = await hre.ethers.getContractFactory("ModelNFT");
  const nft = await ModelNFT.deploy("TrustMint Model", "TMODEL");
  await waitForDeploy(nft);
  const nftAddr = contractAddress(nft);
  console.log("ModelNFT deployed:", nftAddr);

  const ModelRegistry = await hre.ethers.getContractFactory("ModelRegistry");
  // pass nft address to constructor if your registry expects it (our registry constructor accepts address)
  const registry = await ModelRegistry.deploy(nftAddr);
  await waitForDeploy(registry);
  const registryAddr = contractAddress(registry);
  console.log("ModelRegistry deployed:", registryAddr);

  // Set registry in NFT (require owner)
  const nftWithSigner = nft.connect ? nft.connect(deployer) : nft;
  const tx = await nftWithSigner.setRegistry(registryAddr);
  if (tx.wait) await tx.wait();
  if (tx.waitForDeployment) await tx.waitForDeployment();
  console.log("Registry set in NFT.");

  // Write addresses to blockchain/.env
  const envPath = path.join(__dirname, "..", ".env");
  console.log("Writing addresses to", envPath);
  upsertEnv(envPath, "MODEL_NFT_ADDRESS", nftAddr);
  upsertEnv(envPath, "MODEL_REGISTRY_ADDRESS", registryAddr);

  console.log("\nDone. Addresses written to blockchain/.env:");
  console.log("MODEL_NFT_ADDRESS=" + nftAddr);
  console.log("MODEL_REGISTRY_ADDRESS=" + registryAddr);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});