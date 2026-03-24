from flask import Flask, request, jsonify, send_file
import os
import hashlib
import zipfile
import shutil
import binascii
import json
import subprocess
import requests
import boto3
from botocore.client import Config
from datetime import datetime
from dotenv import load_dotenv
from ecdsa import VerifyingKey, NIST256p, BadSignatureError
from ecdsa.util import sigdecode_der
from eth_account.messages import encode_defunct
from web3 import Web3
from flask_cors import CORS

load_dotenv()  # Load variables from .env file into os.environ



UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Per-model artifact folder helper
def model_folder(model_hash: str) -> str:
    folder = os.path.join(UPLOAD_FOLDER, model_hash[:16])
    os.makedirs(folder, exist_ok=True)
    return folder

# Listing preferences store (simple JSON file on disk)
PREFS_FILE = os.path.join(UPLOAD_FOLDER, 'listing_prefs.json')

def load_prefs() -> dict:
    if os.path.exists(PREFS_FILE):
        with open(PREFS_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_prefs(prefs: dict):
    with open(PREFS_FILE, 'w') as f:
        json.dump(prefs, f, indent=2)

# ─── Configuration ────────────────────────────────────────────────────────────
GOLDEN_PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXVFGF4a7aEKlcaR20aOOJXUqvZbx
pdbOCm+grJkjQ56UdNvnQFOeytnFEh6f+JfjSQ0iYiMtDwdhMaMYkANwlA==
-----END PUBLIC KEY-----"""

# Hardhat node defaults — override via environment variables in production
RPC_URL           = os.getenv('RPC_URL', 'http://127.0.0.1:8545')
DEPLOYER_KEY      = os.getenv('DEPLOYER_PRIVATE_KEY',
                              'ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80')
NFT_ADDRESS       = os.getenv('NFT_CONTRACT',
                              '0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9')
MARKETPLACE_ADDR  = os.getenv('MARKETPLACE_CONTRACT',
                              '0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9')
PINATA_JWT        = os.getenv('PINATA_JWT', '')
DEFAULT_PRICE_WEI = int(os.getenv('DEFAULT_LISTING_PRICE_WEI', str(Web3.to_wei(0.01, 'ether'))))

# ─── Backblaze B2 Configuration ──────────────────────────────────────────────
B2_KEY_ID       = os.getenv('B2_KEY_ID', '')
B2_APP_KEY      = os.getenv('B2_APP_KEY', '')
B2_REGION       = os.getenv('B2_REGION', 'us-west-004')  # from your B2 bucket endpoint
B2_BUCKET_NAME  = os.getenv('B2_BUCKET_NAME', 'trustmint-datasets')

def get_b2_client():
    """Returns a boto3 S3 client configured for Backblaze B2, or None if not configured."""
    if not all([B2_KEY_ID, B2_APP_KEY]):
        return None
    return boto3.client(
        's3',
        endpoint_url=f'https://s3.{B2_REGION}.backblazeb2.com',
        aws_access_key_id=B2_KEY_ID,
        aws_secret_access_key=B2_APP_KEY,
        config=Config(signature_version='s3v4'),
        region_name=B2_REGION
    )

def upload_dataset_to_b2(file_path, wallet_address, model_hash):
    """Upload dataset zip to Backblaze B2. Returns public URL or None."""
    b2 = get_b2_client()
    if not b2:
        print("⚠️  B2 not configured — dataset saved locally only.")
        return None
    try:
        key = f"datasets/{wallet_address}/{model_hash[:8]}/dataset.zip"
        b2.upload_file(file_path, B2_BUCKET_NAME, key)
        url = f"https://s3.{B2_REGION}.backblazeb2.com/{B2_BUCKET_NAME}/{key}"
        print(f"   ✅ Dataset uploaded to B2 → {url}")
        return url
    except Exception as e:
        print(f"   ⚠️  B2 upload failed: {e}. Dataset kept locally.")
        return None

# ─── Load Contract ABIs ────────────────────────────────────────────────────────
BLOCKCHAIN_DIR = os.path.join(os.path.dirname(__file__), '..', 'blockchain')

def _load_abi(name):
    path = os.path.join(BLOCKCHAIN_DIR, 'artifacts', 'contracts',
                        f'{name}.sol', f'{name}.json')
    with open(path) as f:
        return json.load(f)['abi']

try:
    NFT_ABI         = _load_abi('TrustmintNFT')
    MARKETPLACE_ABI = _load_abi('TrustmintMarketplace')
    print("✅ Contract ABIs loaded.")
except Exception as e:
    print(f"⚠️  Could not load ABIs: {e}")
    NFT_ABI = MARKETPLACE_ABI = None

# ─── Web3 Setup ───────────────────────────────────────────────────────────────
w3 = Web3(Web3.HTTPProvider(RPC_URL))
deployer_account = w3.eth.account.from_key(DEPLOYER_KEY)

app = Flask(__name__)
CORS(app)


# ═══════════════════════════════════════════════════════════════════════════════
# Helper functions
# ═══════════════════════════════════════════════════════════════════════════════

def hash_directory(path):
    """Calculates a single SHA256 hash for all files in a directory."""
    hasher = hashlib.sha256()
    for root, dirs, files in sorted(os.walk(path)):
        for name in sorted(files):
            file_path = os.path.join(root, name)
            with open(file_path, 'rb') as f:
                while chunk := f.read(4096):
                    hasher.update(chunk)
    return hasher.hexdigest()

def hash_file(file_storage):
    """Calculates the SHA256 hash of a file received from the CLI."""
    hasher = hashlib.sha256()
    file_storage.seek(0)
    while chunk := file_storage.read(4096):
        hasher.update(chunk)
    file_storage.seek(0)
    return hasher.hexdigest()

def verify_signature(data_str, signature_hex):
    try:
        vk = VerifyingKey.from_pem(GOLDEN_PUBLIC_KEY_PEM)
        signature = binascii.unhexlify(signature_hex)
        data = data_str.encode('utf-8')
        return vk.verify(signature, data, hashfunc=hashlib.sha256, sigdecode=sigdecode_der)
    except (BadSignatureError, binascii.Error) as e:
        print(f"Signature Error: {e}")
        return False

def upload_to_pinata(file_path, name):
    """Upload a file to IPFS via Pinata. Returns the IPFS CID or None."""
    if not PINATA_JWT:
        print("⚠️  No Pinata JWT configured — skipping IPFS upload, using placeholder CID.")
        return f"QmPlaceholder{name.replace(' ', '')}"
    try:
        with open(file_path, 'rb') as f:
            headers = {'Authorization': f'Bearer {PINATA_JWT}'}
            files_payload = {'file': (os.path.basename(file_path), f)}
            metadata = json.dumps({'name': name})
            data_payload = {'pinataMetadata': metadata, 'pinataOptions': '{"cidVersion":1}'}
            resp = requests.post('https://api.pinata.cloud/pinning/pinFileToIPFS',
                                 headers=headers, files=files_payload, data=data_payload)
            resp.raise_for_status()
            return resp.json()['IpfsHash']
    except Exception as e:
        print(f"⚠️  Pinata upload failed: {e}. Using placeholder.")
        return f"QmPlaceholder{name.replace(' ', '')}"

def upload_json_to_pinata(data, name):
    """Upload JSON metadata to IPFS via Pinata. Returns the IPFS CID or None."""
    if not PINATA_JWT:
        return f"QmMetadata{name.replace(' ', '')}"
    try:
        headers = {
            'Authorization': f'Bearer {PINATA_JWT}',
            'Content-Type': 'application/json'
        }
        payload = {
            'pinataContent': data,
            'pinataMetadata': {'name': name},
            'pinataOptions': {'cidVersion': 1}
        }
        resp = requests.post('https://api.pinata.cloud/pinning/pinJSONToIPFS',
                             headers=headers, json=payload)
        resp.raise_for_status()
        return resp.json()['IpfsHash']
    except Exception as e:
        print(f"⚠️  Pinata JSON upload failed: {e}. Using placeholder.")
        return f"QmMetadata{name.replace(' ', '')}"

def mint_nft(model_hash, dataset_hash, ipfs_cid, metadata_uri, creator_address):
    """Mint a TrustmintNFT. Returns (token_id, tx_hash) or raises."""
    contract = w3.eth.contract(address=Web3.to_checksum_address(NFT_ADDRESS), abi=NFT_ABI)
    merkle_root = bytes.fromhex(model_hash[:64])  # Use model hash prefix as merkle root
    nonce = w3.eth.get_transaction_count(deployer_account.address, 'pending')
    tx = contract.functions.mintModel(
        model_hash, dataset_hash, merkle_root, ipfs_cid, metadata_uri
    ).build_transaction({
        'from': deployer_account.address,
        'nonce': nonce,
        'gas': 1000000,
        'gasPrice': int(w3.eth.gas_price * 1.5), # Add bit of buffer for Amoy
    })
    signed = w3.eth.account.sign_transaction(tx, DEPLOYER_KEY)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

    if receipt.status == 0:
        raise Exception("Minting transaction REVERTED by the blockchain! (Are you trying to publish the exact same model again?)")

    # Decode ModelMinted event to get token_id
    token_id = None
    for log in receipt.logs:
        try:
            decoded = contract.events.ModelMinted().process_log(log)
            token_id = decoded['args']['tokenId']
            break
        except Exception:
            continue

    if token_id is None:
        # Fallback: read totalSupply
        token_id = contract.functions.totalSupply().call()

    # Transfer NFT to the actual developer wallet
    if creator_address and creator_address.lower() != deployer_account.address.lower():
        try:
            transfer_nonce = w3.eth.get_transaction_count(deployer_account.address, 'pending')
            # Use transferFrom instead of safeTransferFrom to avoid overloaded fn issues in Web3.py
            transfer_tx = contract.functions.transferFrom(
                deployer_account.address,
                Web3.to_checksum_address(creator_address),
                token_id
            ).build_transaction({
                'from': deployer_account.address,
                'nonce': transfer_nonce,
                'gas': 200000,
                'gasPrice': int(w3.eth.gas_price * 1.5),
            })
            signed_transfer = w3.eth.account.sign_transaction(transfer_tx, DEPLOYER_KEY)
            tx_hash_transfer = w3.eth.send_raw_transaction(signed_transfer.raw_transaction)
            w3.eth.wait_for_transaction_receipt(tx_hash_transfer)
            print(f"   ✅ NFT #{token_id} transferred to {creator_address}")
        except Exception as e:
            print(f"   ⚠️  Transfer to developer failed (NFT stays with deployer): {e}")

    return token_id, '0x' + tx_hash.hex()

def list_on_marketplace(token_id, price_wei, seller_address):
    """Approve + list NFT on marketplace. Returns listing_id or raises."""
    nft_contract = w3.eth.contract(
        address=Web3.to_checksum_address(NFT_ADDRESS), abi=NFT_ABI)
    market_contract = w3.eth.contract(
        address=Web3.to_checksum_address(MARKETPLACE_ADDR), abi=MARKETPLACE_ABI)

    # Check NFT owner — only owner can approve
    owner = nft_contract.functions.ownerOf(token_id).call()
    print(f"   NFT #{token_id} owner: {owner}")

    # If the NFT is now owned by the developer, deployer can't list it directly.
    # Instead, list from deployer's perspective only if it still owns the token.
    if owner.lower() == deployer_account.address.lower():
        # Approve marketplace
        nonce = w3.eth.get_transaction_count(deployer_account.address, 'pending')
        approve_tx = nft_contract.functions.approve(
            Web3.to_checksum_address(MARKETPLACE_ADDR), token_id
        ).build_transaction({
            'from': deployer_account.address,
            'nonce': nonce,
            'gas': 100000,
            'gasPrice': int(w3.eth.gas_price * 1.5),
        })
        signed_approve = w3.eth.account.sign_transaction(approve_tx, DEPLOYER_KEY)
        tx_hash_approve = w3.eth.send_raw_transaction(signed_approve.raw_transaction)
        w3.eth.wait_for_transaction_receipt(tx_hash_approve)

        # List on marketplace
        list_nonce = w3.eth.get_transaction_count(deployer_account.address, 'pending')
        list_tx = market_contract.functions.listModel(
            Web3.to_checksum_address(NFT_ADDRESS), token_id, price_wei
        ).build_transaction({
            'from': deployer_account.address,
            'nonce': list_nonce,
            'gas': 200000,
            'gasPrice': int(w3.eth.gas_price * 1.5),
        })
        signed_list = w3.eth.account.sign_transaction(list_tx, DEPLOYER_KEY)
        list_tx_hash = w3.eth.send_raw_transaction(signed_list.raw_transaction)
        receipt = w3.eth.wait_for_transaction_receipt(list_tx_hash)

        if receipt.status == 0:
            raise Exception("Marketplace listing transaction REVERTED by the blockchain!")

        # Decode ListingCreated event
        for log in receipt.logs:
            try:
                decoded = market_contract.events.ListingCreated().process_log(log)
                return decoded['args']['listingId']
            except Exception:
                continue

        # Fallback
        return market_contract.functions.totalListings().call()
    else:
        print(f"   ⚠️  NFT owner is {owner}, not deployer. Skipping marketplace listing.")
        print(f"   The developer must manually list the NFT from their wallet.")
        return 0


# ═══════════════════════════════════════════════════════════════════════════════
# Routes
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/api/cli/download', methods=['POST'])
def download_cli():
    """Generate and serve wallet-bound CLI binary."""
    print("\n========================================")
    print("📥 CLI Download Request Received")
    print("========================================")

    try:
        data = request.json
        wallet_address = data.get('walletAddress')
        signature = data.get('signature')
        message = data.get('message')

        print(f"Wallet: {wallet_address}")

        # 1. Verify MetaMask signature
        message_hash = encode_defunct(text=message)
        recovered_address = w3.eth.account.recover_message(message_hash, signature=signature)

        if recovered_address.lower() != wallet_address.lower():
            print(f"❌ Signature verification failed.")
            return jsonify({'error': 'Invalid signature'}), 403

        print(f"✅ Signature verified for {wallet_address}")

        # 2. Path to CLI source and Precompiled template
        template_path = os.path.join(os.path.dirname(__file__), 'trustmint-template')
        cli_binary_src = '/tmp/trustmint'

        # 3. Patch the pre-compiled binary with the real wallet address (Replaces Go Compiler)
        print("🔨 Patching pre-compiled CLI binary with Wallet Address...")
        
        # If the template doesn't exist (e.g. running locally without Docker), build it first
        if not os.path.exists(template_path):
            cli_source_dir = os.path.join(os.path.dirname(__file__), '..', 'trustmint-cli')
            ldflags = '-X trustmint.com/cli/cmd.WalletAddress=0x0000000000000000000000000000000000000000 -X trustmint.com/cli/cmd.BackendURL=https://trustmint-ai-marketplace.onrender.com'
            subprocess.run(['go', 'build', '-ldflags', ldflags, '-o', template_path, '.'], cwd=cli_source_dir, check=True)

        with open(template_path, 'rb') as f:
            binary_data = f.read()

        dummy_addr = b"0x0000000000000000000000000000000000000000"
        real_addr  = wallet_address.lower().encode('utf-8')

        if len(real_addr) == 42:
            binary_data = binary_data.replace(dummy_addr, real_addr)
        else:
            print("⚠️ Wallet address length mismatch!")

        with open(cli_binary_src, 'wb') as f:
            f.write(binary_data)
        
        os.chmod(cli_binary_src, 0o755)

        # 4. Return the binary
        return send_file(
            cli_binary_src,
            as_attachment=True,
            download_name='trustmint',
            mimetype='application/octet-stream'
        )

    except Exception as e:
        print(f"❌ Error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@app.route('/publish', methods=['POST'])
def handle_publish():
    print("\n\n==============================================")
    print("--- ✅ INCOMING PUBLISH REQUEST ---")
    print("==============================================")

    temp_dir = os.path.join(UPLOAD_FOLDER, "temp_verification")
    os.makedirs(temp_dir, exist_ok=True)

    try:
        # ── 1. Receive Proofs ──────────────────────────────────────────────────
        print("▶️  1/5: Receiving proofs and files from the CLI...")
        wallet_address   = request.form.get('wallet_address', '')
        cli_config_hash  = request.form['config_hash']
        cli_dataset_hash = request.form['dataset_hash']
        cli_model_hash   = request.form['model_hash']
        cli_script_hash  = request.form['script_hash']

        config_file  = request.files['config_file']
        model_file   = request.files['model_file']
        dataset_zip  = request.files['dataset_zip']
        script_file  = request.files['script_file']
        print(f"   - Wallet: {wallet_address}")
        print("   ✅ Received all parts.")

        # ── 2. Verify Integrity ────────────────────────────────────────────────
        print("\n▶️  2/5: Verifying integrity of all submitted artifacts...")

        if 'signature_hex' in request.form:
            signature_hex  = request.form['signature_hex']
            data_to_verify = cli_config_hash + cli_dataset_hash + cli_model_hash + cli_script_hash
            if not verify_signature(data_to_verify, signature_hex):
                print("❌ REJECTED: Invalid Digital Signature. Tampering detected.")
                return jsonify({"status": "error", "message": "Invalid Digital Signature"}), 403
            print("   - ✅ Digital Signature VERIFIED.")
        else:
            print("   ⚠️  No signature provided — skipping signature check (dev mode).")

        backend_config_hash = hash_file(config_file)
        if backend_config_hash != cli_config_hash:
            return jsonify({"status": "error", "message": "Config hash mismatch"}), 400
        print("   - ✅ Config integrity VERIFIED.")

        backend_model_hash = hash_file(model_file)
        if backend_model_hash != cli_model_hash:
            return jsonify({"status": "error", "message": "Model hash mismatch"}), 400
        print("   - ✅ Model integrity VERIFIED.")

        dataset_zip_path   = os.path.join(temp_dir, 'dataset.zip')
        dataset_unzip_path = os.path.join(temp_dir, 'dataset')
        dataset_zip.save(dataset_zip_path)
        with zipfile.ZipFile(dataset_zip_path, 'r') as zip_ref:
            zip_ref.extractall(dataset_unzip_path)
        backend_dataset_hash = hash_directory(dataset_unzip_path)
        if backend_dataset_hash != cli_dataset_hash:
            return jsonify({"status": "error", "message": "Dataset hash mismatch"}), 400
        print("   - ✅ Dataset integrity VERIFIED.")

        backend_script_hash = hash_file(script_file)
        if backend_script_hash != cli_script_hash:
            return jsonify({"status": "error", "message": "Script hash mismatch"}), 400
        print("   - ✅ Training script integrity VERIFIED.")

    except KeyError as e:
        return jsonify({"status": "error", "message": f"Missing part: {e}"}), 400
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

    # ── 3. Save artifacts per model hash ─────────────────────────────────────
    print("\n▶️  3/5: Saving verified artifacts...")
    mfolder = model_folder(cli_model_hash)
    model_save_path     = os.path.join(mfolder, 'model.pkl')
    dataset_save_path   = os.path.join(mfolder, 'dataset.zip')
    config_file.save(os.path.join(mfolder, 'trustmint.yml'))
    model_file.save(model_save_path)
    dataset_zip.seek(0)
    dataset_zip.save(dataset_save_path)
    script_file.save(os.path.join(mfolder, 'train.py'))
    # Also keep flat copies for legacy compatibility
    model_file.seek(0); model_file.save(os.path.join(UPLOAD_FOLDER, 'model.pkl'))
    dataset_zip.seek(0); dataset_zip.save(os.path.join(UPLOAD_FOLDER, 'dataset.zip'))
    print("   ✅ All files saved.")

    # Upload dataset to Backblaze B2 (if configured)
    print("\n☁️  Uploading dataset to Backblaze B2...")
    b2_dataset_url = upload_dataset_to_b2(dataset_save_path, wallet_address, cli_model_hash)
    if b2_dataset_url:
        print(f"   ✅ Dataset stored at: {b2_dataset_url}")
    else:
        print("   ℹ️  Dataset stored locally only (set B2 env vars to enable cloud storage).")  


    # ── 4. Upload to IPFS ─────────────────────────────────────────────────────
    print("\n▶️  4/5: Uploading model to IPFS (Pinata)...")
    model_name   = f"trustmint-model-{cli_model_hash[:8]}"
    ipfs_cid     = upload_to_pinata(model_save_path, model_name)
    gateway_url  = f"https://gateway.pinata.cloud/ipfs/{ipfs_cid}"
    print(f"   ✅ Model uploaded → ipfs://{ipfs_cid}")

    # Build and upload metadata JSON
    metadata = {
        "name": model_name,
        "description": "A tamper-proof AI model minted on Trustmint",
        "image": gateway_url,
        "attributes": [
            {"trait_type": "model_hash",   "value": cli_model_hash},
            {"trait_type": "dataset_hash", "value": cli_dataset_hash},
            {"trait_type": "config_hash",  "value": cli_config_hash},
            {"trait_type": "creator",      "value": wallet_address},
            {"trait_type": "minted_at",    "value": datetime.now().isoformat()},
        ],
        "ipfs_cid":     ipfs_cid,
        "model_hash":   cli_model_hash,
        "dataset_hash": cli_dataset_hash,
    }
    metadata_cid  = upload_json_to_pinata(metadata, f"{model_name}-metadata")
    metadata_uri  = f"ipfs://{metadata_cid}"
    print(f"   ✅ Metadata uploaded → {metadata_uri}")

    # ── 5. Mint NFT + List on Marketplace ─────────────────────────────────────
    print("\n▶️  5/5: Minting NFT and listing on marketplace...")
    token_id   = 0
    listing_id = 0
    tx_hash    = "0x"

    if not w3.is_connected():
        print("   ⚠️  Blockchain node not reachable. Skipping on-chain steps.")
        return jsonify({
            "status":     "success",
            "message":    "Proofs verified, IPFS uploaded. Blockchain offline.",
            "token_id":   0,
            "listing_id": 0,
            "tx_hash":    "0x",
            "ipfs_cid":   ipfs_cid,
        }), 200

    if NFT_ABI is None:
        print("   ⚠️  ABIs not loaded. Skipping on-chain steps.")
        return jsonify({
            "status":     "success",
            "token_id":   0,
            "listing_id": 0,
            "tx_hash":    "0x",
            "ipfs_cid":   ipfs_cid,
        }), 200

    try:
        token_id, tx_hash = mint_nft(
            cli_model_hash, cli_dataset_hash,
            ipfs_cid, metadata_uri, wallet_address
        )
        print(f"   ✅ NFT minted! Token ID: #{token_id}  Tx: {tx_hash}")
    except Exception as e:
        print(f"   ❌ NFT minting failed: {e}")
        import traceback; traceback.print_exc()
        return jsonify({
            "status":   "error",
            "message":  f"NFT minting failed: {str(e)}",
            "ipfs_cid": ipfs_cid,
        }), 500

    try:
        listing_id = list_on_marketplace(token_id, DEFAULT_PRICE_WEI, wallet_address)
        print(f"   ✅ Listed on marketplace! Listing ID: #{listing_id}")
    except Exception as e:
        print(f"   ⚠️  Marketplace listing failed (NFT still minted): {e}")
        listing_id = 0

    print("\n🎉 MODEL PUBLISHED SUCCESSFULLY!")
    print("----------------------------------------------")
    print(f"  Wallet:       {wallet_address}")
    print(f"  Token ID:     #{token_id}")
    print(f"  Listing ID:   #{listing_id}")
    print(f"  Tx Hash:      {tx_hash}")
    print(f"  IPFS CID:     {ipfs_cid}")
    print(f"  Model Hash:   {cli_model_hash}")
    print(f"  Dataset Hash: {cli_dataset_hash}")
    print("----------------------------------------------")

    return jsonify({
        "status":     "success",
        "token_id":   token_id,
        "listing_id": listing_id,
        "tx_hash":    tx_hash,
        "ipfs_cid":   ipfs_cid,
    }), 200


@app.route('/api/models', methods=['GET'])
def get_models():
    """Read all active listings + their NFT metadata from the blockchain."""
    if not w3.is_connected() or NFT_ABI is None:
        return jsonify([]), 200

    try:
        nft_contract = w3.eth.contract(
            address=Web3.to_checksum_address(NFT_ADDRESS), abi=NFT_ABI)
        market_contract = w3.eth.contract(
            address=Web3.to_checksum_address(MARKETPLACE_ADDR), abi=MARKETPLACE_ABI)

        total = market_contract.functions.totalListings().call()
        models = []

        for listing_id in range(1, total + 1):
            listing = market_contract.functions.getListing(listing_id).call()
            # listing = (listingId, tokenId, nftContract, seller, price, active)
            if not listing[5]:  # skip inactive
                continue

            token_id = listing[1]
            seller   = listing[3]
            price    = listing[4]

            try:
                meta = nft_contract.functions.getModelMetadata(token_id).call()
                # meta = (modelHash, datasetHash, merkleRoot, ipfsCid, creator, timestamp, verified)
                models.append({
                    "listing_id":   listing_id,
                    "token_id":     token_id,
                    "name":         f"AI Model #{token_id}",
                    "seller":       seller,
                    "creator":      meta[4],
                    "price_wei":    str(price),
                    "price_eth":    float(Web3.from_wei(price, 'ether')),
                    "model_hash":   meta[0],
                    "dataset_hash": meta[1],
                    "ipfs_cid":     meta[3],
                    "verified":     meta[6],
                    "minted_at":    meta[5],
                })
            except Exception as e:
                print(f"   ⚠️  Could not fetch metadata for token {token_id}: {e}")

        return jsonify(models), 200

    except Exception as e:
        print(f"❌ /api/models error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/config', methods=['GET'])
def get_config():
    """Return current contract addresses so the frontend never needs hardcoded values."""
    return jsonify({
        'nftAddress':        NFT_ADDRESS,
        'marketplaceAddress': MARKETPLACE_ADDR,
    }), 200


@app.route('/api/listing-prefs/<model_hash>', methods=['GET'])
def get_listing_prefs(model_hash):
    prefs = load_prefs()
    return jsonify(prefs.get(model_hash, {'include_dataset': False})), 200


@app.route('/api/listing-prefs/<model_hash>', methods=['POST'])
def set_listing_prefs(model_hash):
    data = request.get_json()
    prefs = load_prefs()
    prefs[model_hash] = {'include_dataset': bool(data.get('include_dataset', False))}
    save_prefs(prefs)
    return jsonify({'status': 'ok'}), 200


@app.route('/api/artifacts/<model_hash>/download', methods=['GET'])
def download_artifacts(model_hash):
    """Serve a ZIP of model+script+config (and optionally dataset) to NFT owners.
    Ownership is verified by checking the wallet address against the NFT contract on-chain.
    The caller passes ?wallet=0x... as a query param.
    """
    import io
    wallet = request.args.get('wallet', '').lower()
    if not wallet:
        return jsonify({'error': 'wallet query param required'}), 400

    # Verify ownership on-chain
    try:
        nft_contract = w3.eth.contract(
            address=Web3.to_checksum_address(NFT_ADDRESS), abi=NFT_ABI)
        total = nft_contract.functions.totalSupply().call()
        owner_token = None
        for i in range(1, total + 1):
            meta = nft_contract.functions.getModelMetadata(i).call()
            stored_hash = meta[0]  # modelHash
            if stored_hash.lower() == model_hash.lower():
                owner = nft_contract.functions.ownerOf(i).call()
                if owner.lower() == wallet:
                    owner_token = i
                    break
        if owner_token is None:
            return jsonify({'error': 'You are not the owner of this model NFT'}), 403
    except Exception as e:
        return jsonify({'error': f'Blockchain verification failed: {e}'}), 500

    # Build ZIP with allowed files
    mfolder = os.path.join(UPLOAD_FOLDER, model_hash[:16])
    if not os.path.isdir(mfolder):
        mfolder = UPLOAD_FOLDER  # fallback for older publishes

    prefs = load_prefs()
    include_dataset = prefs.get(model_hash, {}).get('include_dataset', False)

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        for fname in ['model.pkl', 'train.py', 'trustmint.yml']:
            fpath = os.path.join(mfolder, fname)
            if os.path.exists(fpath):
                zf.write(fpath, fname)
        if include_dataset:
            dpath = os.path.join(mfolder, 'dataset.zip')
            if os.path.exists(dpath):
                zf.write(dpath, 'dataset.zip')
    zip_buffer.seek(0)

    return send_file(
        zip_buffer,
        mimetype='application/zip',
        as_attachment=True,
        download_name=f'trustmint-model-{model_hash[:8]}.zip'
    )


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=False)
