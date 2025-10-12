const hre = require("hardhat");
const fs = require("fs");
const path = require("path");
require("dotenv").config({ path: path.join(__dirname, "..", ".env") });

const ethers = hre.ethers;

function getEnvVar(k, def) {
  return process.env[k] || def;
}

async function main() {
  const payloadPath = getEnvVar("PAYLOAD", path.join(process.cwd(), "..", "myoutput", "payload.json"));
  const registryAddr = getEnvVar("MODEL_REGISTRY_ADDRESS");
  const privateKey = getEnvVar("PRIVATE_KEY"); 
  const rpcUrl = getEnvVar("TRUSTMINT_RPC", "http://127.0.0.1:8545");

  // --- Load payload.json ---
  if (!fs.existsSync(payloadPath)) {
    console.error("❌ payload.json not found at", payloadPath);
    process.exit(1);
  }
  const payload = JSON.parse(fs.readFileSync(payloadPath, "utf8"));

  const metadataCid = payload.metadataCid;
  const metadataHash = payload.metadataHash || ethers.utils.keccak256(ethers.utils.toUtf8Bytes(metadataCid));
  const cliSignature = payload.cliSignature;

  if (!cliSignature || !metadataCid) {
    console.error("❌ payload.json must include metadataCid and cliSignature");
    process.exit(1);
  }

  // --- Setup provider and signer ---
  const provider = hre.ethers.provider ?? new ethers.JsonRpcProvider(rpcUrl);
  let signer;

  if (privateKey) {
    signer = new ethers.Wallet(privateKey, provider);
    console.log("🔑 Using PRIVATE_KEY signer:", await signer.getAddress());
  } else {
    const signers = await hre.ethers.getSigners();
    signer = signers[0];
    console.log("🧑 Using Hardhat signer:", await signer.getAddress());
  }

  if (!registryAddr) {
    console.error("❌ MODEL_REGISTRY_ADDRESS not set in .env");
    process.exit(1);
  }

  console.log("📜 Calling registerModelAndMint on registry:", registryAddr);

  // --- Contract setup ---
  const Registry = await hre.ethers.getContractFactory("ModelRegistry");
  const registry = await Registry.attach(registryAddr).connect(signer);

  const toAddr = getEnvVar("TO_ADDRESS", await signer.getAddress());
  const tokenURI = payload.tokenUri || metadataCid;

  try {
    const tx = await registry.registerModelAndMint(
      metadataHash,
      metadataCid,
      cliSignature,
      toAddr,
      tokenURI,
      { gasLimit: 800000 }
    );

    console.log("⛓️ Tx sent:", tx.hash);
    const receipt = await tx.wait();
    console.log("✅ Tx mined in block", receipt.blockNumber);

    // --- Parse ModelRegistered event safely ---
    const iface = registry.interface;
    let modelId = null;
    let tokenId = null;
    const regAddr = (registry.target ?? registry.address)?.toString?.().toLowerCase?.();

    for (const log of receipt.logs || []) {
      if (!log || !log.address || !regAddr) continue;

      try {
        if (log.address.toString().toLowerCase() !== regAddr) continue;
      } catch (e) {
        continue;
      }

      try {
        const parsed = iface.parseLog(log);
        if (parsed && parsed.name === "ModelRegistered") {
          modelId = parsed.args.modelId?.toString?.() || parsed.args[0]?.toString?.();
          tokenId = parsed.args.tokenId?.toString?.() || parsed.args[3]?.toString?.();
          console.log("🪶 ModelRegistered event:", parsed.args);
        }
      } catch (e) {
        // ignore unrelated logs
      }
    }

    if (modelId !== null) {
      console.log(`📦 Model registered successfully! modelId=${modelId}, tokenId=${tokenId}`);
    } else {
      console.log("⚠️ No ModelRegistered event detected (may still have succeeded)");
    }

    try {
      const nftAddr = await registry.modelNFT();
      console.log("🎨 ModelNFT address (from registry):", nftAddr);
    } catch {
      console.log("ℹ️ Could not fetch ModelNFT address.");
    }

  } catch (err) {
    console.error("❌ Transaction error:", err);
    process.exit(1);
  }

  console.log("✅ Done.");
}

main().catch((err) => {
  console.error("❌ Script failed:", err);
  process.exit(1);
});
