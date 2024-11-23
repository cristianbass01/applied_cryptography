import random
import math
from cryptography.hazmat.primitives.asymmetric import rsa
from Crypto.Hash import SHA3_256

# key generation
def KGen(lenght):
    generated_keys = rsa.generate_private_key(
        public_exponent=65537,
        key_size=lenght
    )

    e = generated_keys.public_key().public_numbers().e
    d = generated_keys.private_numbers().d
    n = generated_keys.public_key().public_numbers().n
    return e, d, n

# key derivation function
def KDF(chars):
    ascii_values = []
    for char in chars:
        ascii_values.append(str(ord(char)))

    return int(''.join(ascii_values))

def get_hash(chars):
    hash_function = SHA3_256.new()
    hash_function.update(chars.encode())
    return int(hash_function.hexdigest(), 16)

def encrypt(plaintext, public_key, modulus):
    return pow(plaintext, public_key, modulus)

def decryption_oracle(ciphertext):
    return pow(ciphertext, sk, N)

def Encaps(deterministic_value, pk, N):
    r = get_hash(deterministic_value)
    
    message_key = random.getrandbits(128)
    

    c = encrypt(message_key, pk, N)

    k = KDF(deterministic_value)
    return c, k

pk, sk, N = KGen(2048)
print(f"{pk = }")
print(f"{N = }")

name = input("What is your name : ")
c, k = Encaps(name, pk, N)

# SEND ENCRYPTED KEY
print("The encryption of the symmetric key is : ")
print(c)

def create_query_to_decrypt(encryption_query):
    # Get the decryption query based on the encryption query
    decryption_query = encryption_query * pow(2, pk, N) % N
    return decryption_query

def get_symm_key_from_decrypted_query(decrypted_query):
    # Get the message from the decrypted query
    message = decrypted_query // 2 % N
    return message

# DECRYPTION QUERY
#decryption_query = int(input("You get ONE try! What do you want to decrypt: "))
decryption_query = create_query_to_decrypt(c)

if decryption_query == c:
    print("Your ciphertext must be different than my ciphertext!")
else:
    decrypted = decryption_oracle(decryption_query)
    print("Decrypted: ", decrypted)

    # GUESS THE KEY FROM THE DECRYPTED QUERY
    #flag_guess = int(input("What is Alice's key? One query: "))
    flag_guess = get_symm_key_from_decrypted_query(decrypted)

    print(f"{flag_guess = }")
    if k == flag_guess:
        print("Win!")
    else:
        print("Go fish.")



