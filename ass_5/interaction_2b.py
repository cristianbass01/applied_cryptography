from pwn import *
import re

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
print(output)
encryption_query = parse_encrypted_query(output)

# create the decryption query based on the encryption query
query_to_decrypt = create_query_to_decrypt(encryption_query)
print(query_to_decrypt)

# send the decryption query to the server
r.sendline(str(query_to_decrypt).encode())

# get the decrypted query from the server
output = r.recv().decode()
print(output)
decrypted_query = parse_decrypted_query(output)

# retrieve the symmetric key
symm_key = get_symm_key_from_decrypted_query(decrypted_query)
print(symm_key)

r.sendline(str(symm_key).encode())

# Capture the final output
final_output = r.recv().decode()
print(final_output)

r.close()