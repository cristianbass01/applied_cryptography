import os
import random
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from Crypto.Hash import SHA3_256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import string

from tqdm import tqdm

salt = get_random_bytes(16)

############ HELP FUNCTIONS ################

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

############ KGEN, ENC, DEC ################

# key generation function
def KGen(length, load_private=False):
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

    sk = private_key.private_numbers().d
    N = private_key.public_key().public_numbers().n
    
    g_1 = 11
    g_2 = pow(g_1, sk, N)
    
    pk = (N, g_1, g_2)
    return pk, sk

# Encryption function
def Enc(X: int, R: int, pk: tuple):
    N, g_1, g_2 = pk
    
    # Compute mask
    g_2_R = pow(g_2, R, N)
    mask = get_hash(g_2_R)

    c_1 = pow(g_1, R, N)
    c_2 = mask ^ X

    return (c_1, c_2)
    
# Decryption function
def Dec(c, sk, pk):
    c_1, c_2 = c  
    N, _, _ = pk

    # Compute mask
    g_1_sk = pow(c_1, sk, N)
    mask = get_hash(g_1_sk)
    
    # Compute X
    X = mask ^ c_2
    
    return X

############ ENCAPS and DECAPS ################

# key derivation function
def KDF(X):
    return PBKDF2(str(X), salt, dkLen=32)

# Encapsulation function
def Encaps(X, pk):
    # generate random r
    R = get_hash(X)

    # Encrypt the key
    c = Enc(X, R, pk)

    k = KDF(X)

    return c, k

# Decapsulation function
def Decaps(c: int, sk: int, pk: tuple):
    # Decrypt the key
    X = Dec(c, sk, pk)
    
    R = get_hash(X)

    C_prime = Enc(X, R, pk)

    if c == C_prime:
        return KDF(X)
    else:
        return None

############ MAIN PROGRAM ################

def one_try_only():
    pk, sk = KGen(2048)
    print(f"{pk = }")

    name = None
    while name is None: # Security check
        name = input("What is your name : ")
        if len(name) > 24:
            print("Name too long. Retry.")
            name = None

    name = name_encoder(name)

    c, k = Encaps(name, pk)

    # SEND ENCRYPTED KEY
    print("The encryption of the symmetric key is : ")
    print(f"c_1 = {c[0]}")
    print(f"c_2 = {c[1]}")

    # DECRYPTION QUERY
    print("You get ONE try! What do you want to decrypt:")
    c_1 = int(input("c_1: "))
    c_2 = int(input("c_2: "))
    decryption_query = (c_1, c_2)

    if decryption_query == c:
        print("Your ciphertext must be different than my ciphertext!")
    else:
        decrypted = Decaps(decryption_query, sk, pk)
        if decrypted is None:
            print("Decryption failed.")
        else:
            print("Decrypted: ", decrypted)
        
        # GUESS THE KEY FROM THE DECRYPTED QUERY
        flag_guess = int(input("What is Alice's key? One query: "))
        
        if k == flag_guess:
            print("Win!")
        else:
            print("Go fish.")

def save_encaps_cyphers(n = 1000):
    pk, sk = KGen(2048, load_private= True)

    random_values = [int(''.join(random.choices(string.digits, k=77))) for _ in range(n)]

    file_name = "encaps_cyphers.txt"

    with open(file_name, "w") as file:
        for random_value in tqdm(random_values):
            c, k = Encaps(random_value, pk)
            file.write(f"{c}\n")

            k_prime = Decaps(c, sk, pk)

            if k != k_prime:
                print(f'Random value: {random_value}')
                print(f'Error: {k} != {k_prime}')

def test_encaps_cyphers():
    pk, sk = KGen(2048, load_private = True)

    file_name = "encaps_cyphers.txt"

    with open(file_name, "r") as file:
        lines = file.readlines()
        
        for line in tqdm(lines):
            c = eval(line.strip())
            k = Decaps(c, sk, pk)

            if k is None:
                print(f'Error in decryption of cypher: {c}')

def multiple_tries():
    pk, sk = KGen(2048)
    print(f"{pk = }")

    name = None
    while name is None: # Security check
        name = input("What is your name : ")
        if len(name) > 24:
            print("Name too long. Retry.")
            name = None

    name = name_encoder(name)

    c, k = Encaps(name, pk)

    # SEND ENCRYPTED KEY
    print("The encryption of the symmetric key is : ")
    print(f"c_1 = {c[0]}")
    print(f"c_2 = {c[1]}")

    # DECRYPTION QUERY
    print("You get 1000 tries! What do you want to decrypt:")
    
    for _ in range(1000):
        print(f"Try {_ + 1}")
        c_1 = int(input("c_1: "))
        c_2 = int(input("c_2: "))
        decryption_query = (c_1, c_2)

        if decryption_query == c:
            print("Your ciphertext must be different than my ciphertext!")
        else:
            decrypted = Decaps(decryption_query, sk, pk)
            if decrypted is None:
                print("Decryption failed.")
            else:
                print("Decrypted: ", decrypted)
            
            # GUESS THE KEY FROM THE DECRYPTED QUERY
            flag_guess = int(input("What is Alice's key? One query: "))
            
            if k == flag_guess:
                print("Win!")
            else:
                print("Go fish.")
    
