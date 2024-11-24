import random
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from Crypto.Hash import SHA3_256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

############ HELP FUNCTIONS ################

#  generate a random salt
salt = get_random_bytes(16)

# calculate the maximum length of the hash based on the its max value (256 bits)
max_hash_length = len(str(int("FF" * (256 // 8), 16)))

# transform the name into a number
def name_encoder(name):
    ascii_values = []
    for char in name:
        ascii_values.append(str(ord(char)))

    return int(''.join(ascii_values))

# get the bytes of a value
def get_bytes(value: int):
    return value.to_bytes((value.bit_length() + 7) // 8, byteorder='big')   

# get the hash of a value
def get_hash(value: int):    
    value = get_bytes(value)
    hash_function = SHA3_256.new()
    hash_function.update(value)
    return int(hash_function.hexdigest(), 16)

def concatenate(name, R):
    R = str(R).zfill(max_hash_length)
    return int(str(name) + R)

def split(value):
    name = int(str(value)[:-max_hash_length])
    R = int(str(value)[-max_hash_length:])
    return name, R


############ KGEN, ENC, DEC ################

# key generation function
def KGen(length = 2048, load_private=False):
    if length < 1024:
        raise ValueError("Key length must be at least 1024 bits.")

    if load_private:
        file_name = f"private_key_{length}.pem"
        if os.path.exists(file_name):
            with open(file_name, "rb") as file:
                private_key = serialization.load_pem_private_key(
                    file.read(),
                    password=None
                )
        else:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=length
            )
            with open(file_name, "wb") as file:
                file.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))
    else:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=length
        )

    pk = private_key.public_key().public_numbers().e
    sk = private_key.private_numbers().d
    N = private_key.public_key().public_numbers().n
    
    return pk, sk, N

def encrypt(plaintext, public_key, modulus):
    return pow(plaintext, public_key, modulus)

def decryption_oracle(ciphertext):
    return pow(ciphertext, sk, N)

############ KEM ################

# key derivation function
def KDF(X):
    return PBKDF2(str(X), salt, dkLen=32)

# Encapsulation function
def Encapsulate(name, pk, N):
    X = name_encoder(name)
    R = get_hash(X)
    message = concatenate(X, R)

    c = encrypt(message, pk, N)

    k = KDF(X)
    return c, k

# Decapsulation function
def Decapsulate(c):
    message = decryption_oracle(c)

    try:
        X, R = split(message)
    except:
        return None

    if get_hash(X) == R:
        return KDF(X)
    else:
        return None

############ MAIN ################
attack = False

pk, sk, N = KGen(load_private=True)
print(f"{pk = }")
print(f"{N = }")

name = input("What is your name : ")

c, k = Encapsulate(name, pk, N)

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

    X, R = split(message)
    return KDF(X)
    
# DECRYPTION QUERY
if attack:
    print("You get ONE try! What do you want to decrypt:")
    decryption_query = create_query_to_decrypt(c)
    print(decryption_query)
else:
    decryption_query = int(input("You get ONE try! What do you want to decrypt: "))


if decryption_query == c:
    print("Your ciphertext must be different than my ciphertext!")
else:
    decrypted = Decapsulate(decryption_query)
    if decrypted is None:
        print("Decryption failed.")
    else:
        print("Decrypted: ", decrypted)
        

    # GUESS THE KEY FROM THE DECRYPTED QUERY
    #flag_guess = int(input("What is Alice's key? One query: "))
    print("What is Alice's key? One query: ")
    flag_guess = get_symm_key_from_decrypted_query(decrypted) if decrypted else None
    
    print(f"{flag_guess = }")
    if k == flag_guess:
        print("Win!")
    else:
        print("Go fish.")



