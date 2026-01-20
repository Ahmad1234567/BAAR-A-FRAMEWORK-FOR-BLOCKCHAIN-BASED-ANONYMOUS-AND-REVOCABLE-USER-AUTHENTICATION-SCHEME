from web3 import Web3
import time

# Connect to the local node (Ganache)
web3 = Web3(Web3.HTTPProvider('http://127.0.0.1:7545'))

# Check if connected to the Ethereum network
if web3.is_connected():
    print("Connected to Ethereum network via Ganache")
else:
    print("Failed to connect to Ethereum network")
    exit()

# Start mining on one account (you can select any account)
miner_account = web3.eth.accounts[0]

# Start mining
try:
    # Enable mining (this should be configured in Ganache)
    web3.provider.make_request('evm_setMining', [True])
    print(f"Started mining on account {miner_account}")
except Exception as e:
    print(f"Mining error: {e}")

# Initial block height
initial_block_height = web3.eth.block_number
print(f"Initial Block Height: {initial_block_height}")

# Example double-spend (Stop mining before confirming the first transaction)
try:
    # Send the first transaction
    tx_hash = web3.eth.send_transaction({
        'from': miner_account,
        'to': web3.eth.accounts[1],
        'value': web3.to_wei(5, 'ether')
    })
    print(f"Transaction hash: {tx_hash.hex()}")

    # Wait for a short duration before stopping the miner
    time.sleep(1)  # Allow some time for the transaction to be picked up
    
    # Stop mining
    web3.provider.make_request('evm_setMining', [False])
    print("Mining stopped to simulate a double-spend attack")

    # Check block height after stopping mining
    current_block_height = web3.eth.block_number
    print(f"Current Block Height: {current_block_height}")

    # Check if the transaction is confirmed
    receipt = web3.eth.get_transaction_receipt(tx_hash)
    if receipt and receipt['status'] == 1:
        print("Transaction confirmed: Attack failed")
    else:
        print("Transaction not confirmed: Attack might be successful")

    # Additional check for double-spend
    if current_block_height > initial_block_height:
        print("Block height increased: Target might still be connected to the network.")
    else:
        print("Block height unchanged: Target might be isolated.")

except Exception as e:
    print(f"Error during double-spend attack: {e}")
