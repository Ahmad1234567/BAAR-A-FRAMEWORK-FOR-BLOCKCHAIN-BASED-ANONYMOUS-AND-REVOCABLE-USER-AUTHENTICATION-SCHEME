from web3 import Web3

# Connect to Ganache
ganache_url = "http://127.0.0.1:7545"  # Adjust according to your Ganache settings
web3 = Web3(Web3.HTTPProvider(ganache_url))

# Check if the connection is successful
if web3.is_connected():
    print("Connected to Ethereum network via Ganache")
else:
    print("Failed to connect to the Ethereum network")
    exit()  # Exit if connection fails

# Set the target account
target_account = "0xCD9959DFC2831Cd7cA1DeE85F790d2A059833661"

# Example function to send Ether from one account to another
def send_transaction(from_account, to_account, value):
    try:
        # Convert the value to Wei
        value_in_wei = web3.to_wei(value, 'ether')
        
        # Get the correct nonce
        nonce = web3.eth.get_transaction_count(from_account, 'pending')

        print(f"Nonce for {from_account}: {nonce}")

        # Set gas parameters to low values
        gas_limit = 21000  # Minimum for basic transactions
        gas_price = web3.to_wei('1', 'gwei')  # Set a low gas price (1 Gwei)

        # Calculate total cost for the transaction
        total_cost = value_in_wei + (gas_limit * gas_price)

        # Check if the account has sufficient funds
        balance = web3.eth.get_balance(from_account)
        if balance < total_cost:
            print(f"Insufficient funds in {from_account}. Required: {web3.from_wei(total_cost, 'ether')} Ether, Available: {web3.from_wei(balance, 'ether')} Ether")
            return

        # Create the transaction
        transaction = {
            'to': to_account,
            'value': value_in_wei,
            'gas': gas_limit,
            'gasPrice': gas_price,
            'nonce': nonce,  # Using correct nonce
        }

        # Sign the transaction
        private_key = '0x39cd8c6a2766bd42211241687e42c011ff7c581c0166d8c707c02183b5fe8fac'  # Replace with actual private key
        signed_txn = web3.eth.account.sign_transaction(transaction, private_key=private_key)
        
        # Send the transaction
        txn_hash = web3.eth.send_raw_transaction(signed_txn.raw_transaction)
        print(f"Transaction sent from {from_account} to {to_account}: {txn_hash.hex()}")
    
    except Exception as e:
        print(f"Error sending transaction from {from_account} to {to_account}: {str(e)}")

# Example usage: Using funded accounts from Ganache
fake_accounts = [
    "0x93e90543d21A4553A85CeB9eaB3EcBA2379c619E",
]

# Check and print balances of fake accounts
for fake_account in fake_accounts:
    balance = web3.eth.get_balance(fake_account)
    print(f"Balance of {fake_account}: {web3.from_wei(balance, 'ether')} Ether")

# Sending transactions from each fake account to the target account
for fake_account in fake_accounts:
    # Ensure the fake account has sufficient Ether before attempting to send
    balance = web3.eth.get_balance(fake_account)
    if balance > web3.to_wei(0.01, 'ether'):
        send_transaction(fake_account, target_account, 0.01)  # Sending 0.01 Ether
    else:
        print(f"Insufficient funds in {fake_account} to send Ether.")
