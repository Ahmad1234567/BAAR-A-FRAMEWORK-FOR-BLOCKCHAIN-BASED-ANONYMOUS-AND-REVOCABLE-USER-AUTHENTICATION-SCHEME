import os
import hashlib
import json
import time
from flask import Flask, request, jsonify, session, abort
from web3 import Web3
from solcx import compile_source
from hexbytes import HexBytes
from ecdsa import SigningKey, SECP256k1, VerifyingKey

# Zero Knowledge Proof (ZKP)
from ecdsa.util import sigencode_der, sigdecode_der

# Homomorphic Encryption
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Initialize Web3 instance
w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:7545"))

# Define the smart contract source code
contract_source_code = """
pragma solidity ^0.8.0;

contract AuthContract {
    struct User {
        string publicKey;
        string privateKey;
        bool isActive;
    }

    mapping(string => address) private users;
    mapping(address => User) private userDetails;
    mapping(address => bool) private admins;
    mapping(address => bool) private isAdmin;
    mapping(address => bool) private isSuspended;
    string[] private allUsernames;

    event UserRegistered(address indexed userAddress);
    event AdminAdded(address adminAddress);
    event AdminRemoved(address adminAddress);
    event UserAccessRevoked(address indexed userAddress);
    event UserSuspended(address indexed userAddress);
    event UserThawed(address indexed userAddress);

    modifier onlyAdmin() {
        require(isAdmin[msg.sender], "Only admins can perform this action");
        _;
    }

    modifier onlyAdminOrSelf(string memory username) {
        require(isAdmin[msg.sender] || msg.sender == users[username], "Unauthorized access");
        _;
    }

    constructor() {
        admins[msg.sender] = true;
        isAdmin[msg.sender] = true;
    }

    function registerUser(string memory username, string memory publicKey, string memory privateKey) public {
        require(users[username] == address(0), "User already exists");
        address userAddress = msg.sender;
        users[username] = userAddress;
        userDetails[userAddress] = User(publicKey, privateKey, true);
        allUsernames.push(username);
        emit UserRegistered(userAddress);
    }

    function addAdmin(address adminAddress) public onlyAdmin {
        admins[adminAddress] = true;
        isAdmin[adminAddress] = true;
        emit AdminAdded(adminAddress);
    }

    function removeAdmin(address adminAddress) public onlyAdmin {
        require(adminAddress != msg.sender, "You cannot remove yourself as admin");
        admins[adminAddress] = false;
        isAdmin[adminAddress] = false;
        emit AdminRemoved(adminAddress);
    }

    function getUserPublicKey(string memory username) public view returns (string memory) {
        address userAddress = users[username];
        require(userAddress != address(0), "User not found");
        return userDetails[userAddress].publicKey;
    }

    function getUserPrivateKeys(string memory username) public view onlyAdminOrSelf(username) returns (string memory) {
        address userAddress = users[username];
        require(userAddress != address(0), "User not found");
        return userDetails[userAddress].privateKey;
    }

    function revokeUserAccess(string memory username) public onlyAdmin {
        address userAddress = users[username];
        require(userAddress != address(0), "User not found");
        userDetails[userAddress].isActive = false;
        isAdmin[userAddress] = false;
        emit UserAccessRevoked(userAddress);
    }

    function suspendUser(string memory username) public onlyAdmin {
        address userAddress = users[username];
        require(userAddress != address(0), "User not found");
        isSuspended[userAddress] = true;
        emit UserSuspended(userAddress);
    }

    function thawUser(string memory username) public onlyAdmin {
        address userAddress = users[username];
        require(userAddress != address(0), "User not found");
        isSuspended[userAddress] = false;
        emit UserThawed(userAddress);
    }

    function getUserAddress(string memory username) public view returns (address) {
        return users[username];
    }

    function getAllUsernames() public view returns (string[] memory) {
        return allUsernames;
    }

    function isUserAdmin(address userAddress) public view returns (bool) {
        return isAdmin[userAddress];
    }

    function isUserSuspended(address userAddress) public view returns (bool) {
        return isSuspended[userAddress];
    }

    // Add additional functions as needed
}
"""

# Compile the smart contract source code
compiled_sol = compile_source(contract_source_code)
contract_interface = compiled_sol["<stdin>:AuthContract"]

# Deploy the compiled contract to Ganache
contract_address = None
auth_contract = None


def deploy_contract():
    global contract_address, auth_contract

    if contract_address is None:
        w3.eth.default_account = w3.eth.accounts[0]
        Contract = w3.eth.contract(abi=contract_interface["abi"], bytecode=contract_interface["bin"])
        tx_hash = Contract.constructor().transact()
        tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        contract_address = tx_receipt.contractAddress

        auth_contract = w3.eth.contract(address=contract_address, abi=contract_interface["abi"])

        register_default_admin()


# Function to generate key pairs for users
def generate_key_pair():
    start_time = time.time()
    sk = SigningKey.generate(curve=SECP256k1)
    vk = sk.verifying_key
    end_time = time.time()
    key_generation_time = end_time - start_time
    return sk.to_string().hex(), vk.to_string().hex(), key_generation_time


# Function to hash passwords
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


# Function to generate RSA key pair
def generate_rsa_key_pair():
    key = RSA.generate(2048)
    return key


# Function to encrypt data using RSA public key
def rsa_encrypt(data, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_data = cipher.encrypt(data.encode())
    return encrypted_data


# Function to decrypt data using RSA private key
def rsa_decrypt(encrypted_data, private_key):
    cipher = PKCS1_OAEP.new(private_key)
    decrypted_data = cipher.decrypt(encrypted_data)
    return decrypted_data.decode()


# Function to generate Schnorr's proof
def generate_schnorr_proof(private_key, public_key):
    # Sign a challenge (e.g., a nonce)
    sk = SigningKey.from_string(bytes.fromhex(private_key), curve=SECP256k1)
    vk = VerifyingKey.from_string(bytes.fromhex(public_key), curve=SECP256k1)
    nonce = os.urandom(32)
    signature = sk.sign(nonce, hashfunc=hashlib.sha256)

    # Return the proof components
    return nonce.hex(), signature.hex()


# Function to verify Schnorr's proof
def verify_schnorr_proof(public_key, nonce, signature):
    vk = VerifyingKey.from_string(bytes.fromhex(public_key), curve=SECP256k1)
    return vk.verify(bytes.fromhex(signature), bytes.fromhex(nonce), hashfunc=hashlib.sha256)


# Dictionary to store user keys
user_keys = {}
# Initialize with default admin
default_admin_username = "admin"
default_admin_password = "12345"
default_admin_sk, default_admin_vk, _ = generate_key_pair()
user_keys[default_admin_username] = {
    "public_key": default_admin_vk,
    "private_key": default_admin_sk,
    "hashed_password": hash_password(default_admin_password)
}


# Register the default admin in the smart contract
def register_default_admin():
    global default_admin_username

    user_address = auth_contract.functions.getUserAddress(default_admin_username).call()
    if user_address == "0x0000000000000000000000000000000000000000":
        tx_hash = auth_contract.functions.registerUser(default_admin_username, default_admin_vk,
                                                       default_admin_sk).transact({'from': w3.eth.accounts[0]})
        tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

        # Make the default admin an admin
        tx_hash = auth_contract.functions.addAdmin(w3.eth.accounts[0]).transact({'from': w3.eth.accounts[0]})
        tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)


@app.route("/anonymous_login", methods=["POST"])
def anonymous_login():
    start_time = time.time()
    private_key, public_key, _ = generate_key_pair()
    end_time = time.time()

    session_token = hashlib.sha256(os.urandom(24)).hexdigest()
    session["token"] = session_token
    session["type"] = "anonymous"
    session["public_key"] = public_key
    session["private_key"] = private_key

    return jsonify({
        "message": "Anonymous login successful",
        "public_key": public_key,
        "private_key": private_key,
        "token": session_token,
        "key generation time": end_time-start_time
    }), 200


# Generate RSA key pair for encryption/decryption
rsa_key_pair = generate_rsa_key_pair()


@app.route("/register", methods=["POST"])
def register_user():
    start_time = time.time()

    username = request.form.get("username")
    password = request.form.get("password")
    private_key = request.form.get("private_key")
    account_address = request.form.get("account_address")

    if not username or not password or not private_key or not account_address:
        return jsonify({"message": "Username, password, private key, and account address are required"}), 400

    user_address = auth_contract.functions.getUserAddress(username).call()
    if user_address != "0x0000000000000000000000000000000000000000":
        return jsonify({"message": "User already exists"}), 400

    if not Web3.is_checksum_address(account_address):
        return jsonify({"message": "Invalid account address"}), 400

    if private_key.startswith('0x'):
        private_key = private_key[2:]

    try:
        sk = SigningKey.from_string(bytes.fromhex(private_key), curve=SECP256k1)
    except ValueError:
        return jsonify({"message": "Invalid private key format"}), 400

    vk = sk.verifying_key
    public_key = vk.to_string().hex()

    # Generate keys and hash password
    private_key, public_key, _ = generate_key_pair()
    encrypted_private_key = rsa_encrypt(private_key, rsa_key_pair.publickey())

    # Store encrypted private key in database or contract
    user_keys[username] = {"public_key": public_key,
                           "encrypted_private_key": encrypted_private_key,
                           "hashed_password": hash_password(password)}

    # Check if the user is suspended
    if auth_contract.functions.isUserSuspended(account_address).call():
        return jsonify({"message": "User is suspended and cannot register"}), 400

    tx_hash = auth_contract.functions.registerUser(username, public_key, private_key).transact(
        {'from': account_address})
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    gas_used = tx_receipt.gasUsed

    end_time = time.time()
    total_time_taken = end_time - start_time

    return jsonify({
        "message": "User registered successfully",
        "username": username,
        "public_key": public_key,
        "private_key": private_key,
        "type": "user",  # New field indicating user type
        "account_address": account_address,
        "transaction_time": total_time_taken,
        "gas_used": gas_used
    }), 200


@app.route("/login", methods=["POST"])
def login():
    start_time = time.time()

    username = request.form.get("username")
    password = request.form.get("password")

    if not username or not password:
        return jsonify({"message": "Username and password are required"}), 400

    user_address = auth_contract.functions.getUserAddress(username).call()
    if user_address == "0x0000000000000000000000000000000000000000":
        return jsonify({"message": "User does not exist"}), 400

    hashed_password = user_keys[username]["hashed_password"]
    if hash_password(password) != hashed_password:
        return jsonify({"message": "Incorrect password"}), 400

    # Check if the user is suspended
    if auth_contract.functions.isUserSuspended(user_address).call():
        return jsonify({"message": "User is suspended and cannot login"}), 400

    # Determine user type
    is_admin = auth_contract.functions.isUserAdmin(user_address).call()
    user_type = "admin" if is_admin else "user"

    session["username"] = username
    session["type"] = user_type  # Store user type in session

    # Retrieve the decrypted private key
    if not is_admin:
        encrypted_private_key = user_keys[username]["encrypted_private_key"]
        private_key = rsa_decrypt(encrypted_private_key, rsa_key_pair)
    else:
        private_key = user_keys[username]["private_key"]


    start_time2 = time.time()
    # Generate and store Schnorr's proof
    nonce, signature = generate_schnorr_proof(private_key, user_keys[username]["public_key"])
    end_time2 = time.time()
    total_time_taken2 = end_time2 - start_time2

    end_time = time.time()
    total_time_taken = end_time - start_time

    return jsonify({
        "message": "Login successful",
        "username": username,
        "public_key": user_keys[username]["public_key"],
        "type": user_type,
        "transaction_time": total_time_taken,
        "Zero_Knowledge_Proof_time": total_time_taken2,
        "proof": {
            "nonce": nonce,
            "signature": signature
        }
    }), 200


@app.route("/add_admin", methods=["POST"])
def add_admin():
    start_time = time.time()
    if "username" not in session or session["type"] != "admin":
        return jsonify({"message": "Unauthorized access"}), 401

    admin_username = session["username"]

    username = request.form.get("username")

    if not username:
        return jsonify({"message": "Username is required"}), 400

    user_address = auth_contract.functions.getUserAddress(username).call()
    if user_address == "0x0000000000000000000000000000000000000000":
        return jsonify({"message": "User does not exist"}), 400

    admin_address = w3.eth.accounts[0]

    tx_hash = auth_contract.functions.addAdmin(user_address).transact({'from': admin_address})
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    gas_used = tx_receipt.gasUsed
    end_time = time.time()
    total_time_taken = end_time - start_time

    return jsonify({
        "message": f"User with public key {user_keys[username]['public_key']} added as admin",
        "username": username,
        "public_key": user_keys[username]["public_key"],
        "transaction_time": total_time_taken,
        "gas_used": gas_used
    }), 200


@app.route("/remove_admin", methods=["POST"])
def remove_admin():
    start_time = time.time()
    if "username" not in session or session["type"] != "admin":
        return jsonify({"message": "Unauthorized access"}), 401

    admin_username = session["username"]

    username = request.form.get("username")

    if not username:
        return jsonify({"message": "Username is required"}), 400

    user_address = auth_contract.functions.getUserAddress(username).call()
    if user_address == "0x0000000000000000000000000000000000000000":
        return jsonify({"message": "User does not exist"}), 400

    admin_address = w3.eth.accounts[0]

    tx_hash = auth_contract.functions.removeAdmin(user_address).transact({'from': admin_address})
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    gas_used = tx_receipt.gasUsed
    end_time = time.time()
    total_time_taken = end_time - start_time

    return jsonify({
        "message": f"User with public key {user_keys[username]['public_key']} removed from being an admin",
        "username": username,
        "public_key": user_keys[username]["public_key"],
        "transaction_time": total_time_taken,
        "gas_used": gas_used
    }), 200


@app.route("/get_all_users", methods=["GET"])
def get_all_users():
    start_time = time.time()
    if "username" not in session or session["type"] != "admin":
        return jsonify({"message": "Unauthorized access"}), 401

    admin_username = session["username"]

    all_usernames = auth_contract.functions.getAllUsernames().call()
    users_info = []

    for username in all_usernames:
        user_address = auth_contract.functions.getUserAddress(username).call()
        is_admin = auth_contract.functions.isUserAdmin(user_address).call()
        is_active = auth_contract.functions.getUserPublicKey(username).call() != ""
        is_suspended = auth_contract.functions.isUserSuspended(user_address).call()

        user_type = "admin" if is_admin else "user"
        public_key = user_keys[username]["public_key"]

        users_info.append({
            "username": username,
            "type": user_type,
            "account_address": user_address,
            "public_key": public_key,
            "is_active": is_active,
            "is_suspended": is_suspended
        })

    end_time = time.time()
    total_time_taken = end_time - start_time
    return jsonify({"users": users_info, "transaction_time": total_time_taken}), 200


@app.route("/suspend_user", methods=["POST"])
def suspend_user():
    start_time = time.time()
    if "username" not in session or session["type"] != "admin":
        return jsonify({"message": "Unauthorized access"}), 401

    admin_username = session["username"]

    username = request.form.get("username")

    if not username:
        return jsonify({"message": "Username is required"}), 400

    user_address = auth_contract.functions.getUserAddress(username).call()
    if user_address == "0x0000000000000000000000000000000000000000":
        return jsonify({"message": "User does not exist"}), 400

    admin_address = w3.eth.accounts[0]

    tx_hash = auth_contract.functions.suspendUser(username).transact({'from': admin_address})
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    gas_used = tx_receipt.gasUsed


    end_time = time.time()
    return jsonify(
        {
            "message": f"User {username} suspended successfully",
            "Gas Used": gas_used,
            "transaction time": end_time - start_time
        }), 200


@app.route("/get_user_info", methods=["GET"])
def get_user_info():
    start_time = time.time()
    if "type" not in session:
        return jsonify({"message": "Unauthorized access"}), 401

    user_type = session["type"]
    public_key = session.get("public_key")

    if user_type == "anonymous":
        return jsonify({
            "message": "Anonymous user information",
            "public_key": public_key
        }), 200
    else:
        # Regular user information retrieval logic
        username = session["username"]
        user_address = auth_contract.functions.getUserAddress(username).call()
        is_admin = auth_contract.functions.isUserAdmin(user_address).call()

        end_time = time.time()
        total_time_taken = end_time - start_time

        return jsonify({
            "message": "User information",
            "username": username,
            "public_key": user_keys[username]["public_key"],
            "type": "admin" if is_admin else "user",
            "transaction_time": total_time_taken,
        }), 200


@app.route("/thaw_user", methods=["POST"])
def thaw_user():
    start_time = time.time()
    if "username" not in session or session["type"] != "admin":
        return jsonify({"message": "Unauthorized access"}), 401

    admin_username = session["username"]
    username = request.form.get("username")

    if not username:
        return jsonify({"message": "Username is required"}), 400

    user_address = auth_contract.functions.getUserAddress(username).call()
    if user_address == "0x0000000000000000000000000000000000000000":
        return jsonify({"message": "User does not exist"}), 400

    admin_address = w3.eth.accounts[0]
    tx_hash = auth_contract.functions.thawUser(username).transact({'from': admin_address})
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    gas_used = tx_receipt.gasUsed

    return jsonify({
        "message": f"User {username} thawed successfully",
        "transaction_time": time.time() - start_time,
        "gas_used": gas_used
    }), 200


@app.route("/revoke_access", methods=["POST"])
def revoke_access():
    start_time = time.time()
    if "username" not in session or session["type"] != "admin":
        return jsonify({"message": "Unauthorized access"}), 401

    admin_username = session["username"]
    username = request.form.get("username")

    if not username:
        return jsonify({"message": "Username is required"}), 400

    user_address = auth_contract.functions.getUserAddress(username).call()
    if user_address == "0x0000000000000000000000000000000000000000":
        return jsonify({"message": "User does not exist"}), 400

    admin_address = w3.eth.accounts[0]
    tx_hash = auth_contract.functions.revokeUserAccess(username).transact({'from': admin_address})
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    gas_used = tx_receipt.gasUsed

    return jsonify({
        "message": f"User {username} access revoked successfully",
        "transaction_time": time.time() - start_time,
        "gas_used": gas_used
    }), 200


@app.route("/get_user_public_key", methods=["GET"])
def get_user_public_key():
    username = request.args.get("username")
    if not username:
        return jsonify({"message": "Username is required"}), 400

    user_address = auth_contract.functions.getUserAddress(username).call()
    if user_address == "0x0000000000000000000000000000000000000000":
        return jsonify({"message": "User does not exist"}), 400

    public_key = auth_contract.functions.getUserPublicKey(username).call()
    return jsonify({"username": username, "public_key": public_key}), 200


@app.route("/get_user_private_keys", methods=["POST"])
def get_user_private_keys():
    if "username" not in session:
        return jsonify({"message": "Unauthorized access"}), 401

    username = request.form.get("username")
    if not username:
        return jsonify({"message": "Username is required"}), 400

    user_address = auth_contract.functions.getUserAddress(username).call()
    if user_address == "0x0000000000000000000000000000000000000000":
        return jsonify({"message": "User does not exist"}), 400

    private_key = auth_contract.functions.getUserPrivateKeys(username).call({'from': w3.eth.accounts[0]})
    return jsonify({"username": username, "private_key": private_key}), 200


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"message": "Logged out successfully"}), 200


if __name__ == "__main__":
    deploy_contract()
    app.run(port=5001, debug=True)
