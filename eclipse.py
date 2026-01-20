from web3 import Web3
import time

# Connect to Ganache
web3 = Web3(Web3.HTTPProvider('http://127.0.0.1:7545'))

# Check if connected to the Ethereum network
if web3.is_connected():
    print("Connected to Ethereum network via Ganache")
else:
    print("Failed to connect to Ethereum network")

# Use Ganache accounts as 'malicious peers'
ganache_accounts = web3.eth.accounts  # Ganache provides a list of accounts

# Select the first account as the target and the rest as malicious peers
target_account = ganache_accounts[0]
malicious_peers = ganache_accounts[1:]  # All accounts except the first one

print(f"Target account: {target_account}")
print(f"Malicious peers: {malicious_peers}")

# Monitoring: Get the current block height for reference
initial_block_height = web3.eth.block_number
print(f"Initial Block Height: {initial_block_height}")

# Function to monitor the attack status
def monitor_attack():
    # Check the target account block height periodically
    current_block_height = web3.eth.block_number
    print(f"Current Block Height: {current_block_height}")

    # If block height has stalled (i.e., not changing), the target might be isolated
    if current_block_height == initial_block_height:
        print("Block height stalled: Possible isolation.")
    else:
        print("Block height increasing: Target might still be connected to the network.")

    # Check the number of peers (if possible) or track transaction status
    # Not all web3 providers offer direct peer count checks, but in a real scenario,
    # this would be a way to see if only malicious peers are connected.
    
    print(f"Target node block height: {current_block_height}")
    print(f"Target is {'' if current_block_height == initial_block_height else 'NOT '}isolated from the network")

# Overload the target account with transactions from malicious peers
for peer in malicious_peers:
    try:
        tx_hash = web3.eth.send_transaction({
            'from': peer,
            'to': target_account,
            'value': web3.to_wei(1, 'ether')  # Sending 1 Ether from each peer
        })
        print(f"Transaction sent from {peer} to {target_account}: {tx_hash.hex()}")
    except Exception as e:
        print(f"Error with peer {peer}: {e}")

# Monitor attack after some time to evaluate success
time.sleep(10)  # Wait 10 seconds before monitoring the attack status
monitor_attack()
