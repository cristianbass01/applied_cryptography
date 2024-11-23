# this file shows you how to interact with a script running remotely
# especially if you want to interact multiple times, this is much easier
# than doing it by hand.

# this package is required for everything, you can install it with
# 'pip install pwntools'
from pwn import *
import re
from Crypto.Hash import SHA3_256

modulus = 43156202150929343997204023690237148570191681940132577320374036808463240350882583048133407947064555839575112876002816227754056201929511529594423304196966617850624037811420032104728851930464693039613322475780195848729674846527655365879679078451495188227754101669668167688339861070729531263596514109718240053728887995295522349061627732545083926038985187692231898746079262120114964297005399587664178930260025038474302247096209888692518107068724001569615212092665409734376056960785115028373796416656188001131171958339297433047206918144535328608819092203454976824419428933920601592396035248631882572207311154100883811864507
public_key = 65533

# Function to parse the encrypted query from the output
def parse_encrypted_query(output):
    # Use regular expressions to extract the encrypted query
    match = re.search(
        r".*Here it is:\n(\d+)\n.*", 
        output, 
        re.DOTALL
    )
    
    encrypted_query = None
    if match:
        encrypted_query = int(match.group(1))
    return encrypted_query

def create_query_to_decrypt(encryption_query):
    # Get the decryption query based on the encryption query
    decryption_query = encryption_query * pow(2, public_key, modulus) % modulus
    return decryption_query

def parse_decrypted_query(output):
    # Use regular expressions to extract the decrypted query
    match = re.search(
        r".*Decrypted:  (\d+)\n.*", 
        output, 
        re.DOTALL
    )
    
    decrypted_query = None
    if match:
        decrypted_query = int(match.group(1))
    else:
        print("Could not find decrypted query in output: ", output)
    return decrypted_query

def get_symm_key_from_decrypted_query(decrypted_query):
    # Get the message from the decrypted query
    message = decrypted_query // 2 % modulus
    return message

# we need to connect to the remote server (this requires us to be in
# the Radboud network) we do so by setting up a remote process
r = remote('appliedcrypto.cs.ru.nl', 4143)

# this allows us to read the bits we've received
output = r.recv().decode()
encryption_query = parse_encrypted_query(output)
print(f"Encrypted query: {encryption_query}")

query_to_decrypt = create_query_to_decrypt(encryption_query)
print(f"Query to decrypt: {query_to_decrypt}")

# send the decryption query
r.sendline(str(query_to_decrypt).encode())

# get the decrypted query
output = r.recv().decode()
decrypted_query = parse_decrypted_query(output)
print(f"Decrypted query: {decrypted_query}")

symm_key = get_symm_key_from_decrypted_query(decrypted_query)
print(f"Guess: {symm_key}")

r.sendline(str(symm_key).encode())

# Capture any remaining data from the server after the loop
try:
    final_output = r.recvall().decode()
    print(final_output)
except EOFError:
    print("No more data from server.")

# we can also send bits just as easy. For assignment 5, exercise 2
# we want to send either '0' or '1'
#r.sendline('0')

# what did we get back?
#output = str(r.recv())
#result = output.rfind("The challenge was")
#print(output[2:result])

# in exercise 1 you need to apply a hash function, you can take it from
# PyCryptodome

#hash_function = SHA3_256.new()
#hash_function.update(b'Here we are hashing some bytestring')
#print(hash_function.hexdigest())
