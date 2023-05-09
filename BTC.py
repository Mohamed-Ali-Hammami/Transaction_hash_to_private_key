import hashlib
import base58
import binascii
import ecdsa
import requests

# Define the curve used for Bitcoin
curve = ecdsa.SECP256k1

# Define the transaction hash
transaction_hash = "00312169b2a68d3b12886a5abb667872daf8241623df86ef2694f58bf19c82bb"

# Fetch the transaction data from the Blockchain.com API
url = f"https://blockchain.info/rawtx/{transaction_hash}"
response = requests.get(url)
if response.status_code != 200:
    print(f"Error: {response.status_code}")
    exit()
all_data = response.json()
print([all_data])


# Extract witness from the inputs
witness = all_data['inputs'][0]['witness']

# Print the witness
print("witness :",witness)


witness_hex = witness

# Convert hex to bytes
witness_bytes = bytes.fromhex(witness_hex)
print("witness :" ,witness_bytes)

# Extract public key from witness bytes
public_key_bytes = witness_bytes[-33:]
print("public_key_bytes :",public_key_bytes)

#public_key_hex
hex_public_key = public_key_bytes.hex()
print("hex_public_key :" ,hex_public_key) # prints "0300966a501218a8476bfe5145ec3230c983a54c85c7ed4e7040b2d8ee591cb24a"

# Convert public key x coordinate to int
public_key_x = int.from_bytes(public_key_bytes[:32], 'big')
print("public_key_x:" ,public_key_x)

# Compute public key y coordinate using x coordinate and curve equation
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
y_squared = (public_key_x**3 + 7) % p
public_key_y = pow(y_squared, (p+1)//4, p)
print("public_key_y :" , public_key_y)

# Convert public key x and y coordinates to hexadecimal
public_key_x_hex = hex(public_key_x)[2:] # exclude the '0x' prefix
public_key_y_hex = hex(public_key_y)[2:] # exclude the '0x' prefix
print("public_key_x_hex :" , public_key_x_hex)
print("public_key_y_hex :" ,public_key_y_hex)

# If the hexadecimal string is odd, add a leading zero to make it even
if len(public_key_x_hex) % 2 == 1:
    public_key_x_hex = '0' + public_key_x_hex
if len(public_key_y_hex) % 2 == 1:
    public_key_y_hex = '0' + public_key_y_hex

# Convert public key x and y hexadecimal to bytes
public_key_x_bytes = bytes.fromhex(public_key_x_hex)
public_key_y_bytes = bytes.fromhex(public_key_y_hex)
print("public_key_x_bytes :" ,public_key_x_bytes)
print("public_key_y_bytes ;", public_key_y_bytes)

# Combine the X and Y coordinates into a public key
public_key = b'\x04' + public_key_x_bytes + public_key_y_bytes
print("public_key :" ,public_key)
print("public_key_hex :" ,binascii.hexlify(public_key))

# Create a public key object from the public key bytes
public_key = ecdsa.VerifyingKey.from_string(public_key_bytes, curve=curve)

# Extract the y-coordinate from the public key
y = int(public_key_y_bytes.hex(), 16)
print("y ; ",y)

# Convert the transaction hash to an integer
n = int(transaction_hash, 16)
print("n :" ,n)

# Calculate the private key
order = curve.order

# Calculate the private key
private_key = (n + 1 - y) % order
print("private_key_int : " ,private_key)
print("private_key : " ,hex(private_key)[2:])  # exclude the '0x' prefix

def private_key_to_wif(private_key):
    # Add prefix "80" to indicate a private key
    extended_key = "80" + private_key

    # Perform SHA-256 hash on the extended key
    first_sha256 = hashlib.sha256(bytes.fromhex(extended_key)).hexdigest()

    # Perform SHA-256 hash on the result of the first SHA-256 hash
    second_sha256 = hashlib.sha256(bytes.fromhex(first_sha256)).hexdigest()

    # Take the first 4 bytes of the second SHA-256 hash as the checksum
    checksum = second_sha256[:8]

    # Concatenate the extended key and the checksum
    final_key = extended_key + checksum

    # Convert the final key to base58 encoding
    wif = base58.b58encode(bytes.fromhex(final_key)).decode()
    
    return wif

# Convert the private key to WIF format and print it
wif = private_key_to_wif(hex(private_key)[2:])
print("WIF format of private key: ", wif)

# Convert the private key from hexadecimal to bytes
private_key_bytes = bytes.fromhex(hex(private_key)[2:])

# Create a signing key object from the private key bytes
signing_key = ecdsa.SigningKey.from_string(private_key_bytes, curve=curve)

# Get the corresponding verifying key object
verifying_key = signing_key.get_verifying_key()

# Get the public key (in bytes format)
public_key_bytes = verifying_key.to_string()

# Convert the public key bytes to hexadecimal
cpublic_key_hex = public_key_bytes.hex()

print("cPublic key:", cpublic_key_hex)

# Get the compressed public key
compressed_public_key_bytes = verifying_key.to_string("compressed")

# Convert the compressed public key bytes to hexadecimal
compressed_public_key_hex = compressed_public_key_bytes.hex()

print("Compressed public key:", compressed_public_key_hex)

