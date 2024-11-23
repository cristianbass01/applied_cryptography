import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from Crypto.Hash import SHA3_256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

salt = get_random_bytes(16)

# transform the name into a number
def name_encoder(name):
    ascii_values = []
    for char in name:
        ascii_values.append(str(ord(char)))

    return int(''.join(ascii_values))

def merge_cipher(c_1, c_2):
    c_1 = str(c_1)
    c_2 = str(c_2).zfill(77)
    return  int(c_1 + c_2)

def split_cipher(c):
    c = str(c)
    c_1 = int(c[:-77])
    c_2 = int(c[-77:])
    return c_1, c_2

# get the bytes of a value
def get_bytes(value):
    return str(value).encode()

# get the hash of a value
def get_hash(value):
    if type(value) != bytes:
        value = get_bytes(value)

    hash_function = SHA3_256.new()
    hash_function.update(value)
    return int(hash_function.hexdigest(), 16)

# key generation function
def KGen(length):
    if length < 1024:
        raise ValueError("Key length must be at least 1024 bits.")

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

    sk = private_key.private_numbers().d
    N = private_key.public_key().public_numbers().n
    
    g_1 = 11
    g_2 = pow(g_1, sk, N)
    
    pk = (N, g_1, g_2)
    return pk, sk

# Encryption function
def Enc(X, R, pk):
    N, g_1, g_2 = pk
    
    # Compute mask
    g_2_R = pow(g_2, R, N)
    mask = get_hash(g_2_R)

    c_1 = pow(g_1, R, N)
    c_2 = mask ^ X

    return merge_cipher(c_1, c_2)
    
# Decryption function
def Dec(c, sk, pk):
    c_1, c_2 = split_cipher(c)    
    N, _, _ = pk

    # Compute mask
    g_1_sk = pow(c_1, sk, N)
    mask = get_hash(g_1_sk)
    
    # Compute X
    X = mask ^ c_2
    
    return X

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
def Decaps(c, sk, pk):
    # Decrypt the key
    X = Dec(c, sk, pk)
    
    R = get_hash(X)

    C_prime = Enc(X, R, pk)

    if c == C_prime:
        return KDF(X)
    else:
        return None

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
print(c)

# DECRYPTION QUERY
while True:
    decryption_query = int(input("You get ONE try! What do you want to decrypt: "))

    if decryption_query == c:
        print("Your ciphertext must be different than my ciphertext!")
    else:
        if len(str(decryption_query)) < 78:
            print("Query too short. Retry.")
            continue

        decrypted = Decaps(decryption_query, sk, pk)

        if decrypted is None:
            print("Decryption failed. Retry.")
            continue

        print("Decrypted: ", decrypted)

        # GUESS THE KEY FROM THE DECRYPTED QUERY
        flag_guess = int(input("What is Alice's key? One query: "))
        if k == flag_guess:
            print("Win!")
        else:
            print("Go fish.")
        
        break