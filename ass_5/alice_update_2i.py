from alice_update import *

# Apply your attack from exercise 2b (but this time you are allowed 1000 queries) and
# write down whether it succeeded.

n_queries = 1000

pk, sk, N = KGen(load_private=True)
print(f"{pk = }")
print(f"{N = }")

query = random.randint(1, 100)

c, k = Encapsulate(query, pk, N)

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
print("You get 1000 try! What do you want to decrypt:")
successful_decryption_count = 0
successful_key_guess_count = 0

for _ in tqdm(range(n_queries)):
    decryption_query = create_query_to_decrypt(c)

    if decryption_query == c:
        print("Your ciphertext must be different than my ciphertext!")
    else:
        decrypted = Decapsulate(decryption_query, sk, N)
    
        if decrypted is not None:
            successful_decryption_count += 1
            
        # GUESS THE KEY FROM THE DECRYPTED QUERY
        flag_guess = get_symm_key_from_decrypted_query(decrypted) if decrypted else None

        if k == flag_guess:
            successful_key_guess_count += 1
            
        
print()
print(f"Successful decryptions: {successful_decryption_count} ({successful_decryption_count / n_queries * 100}%)")
print(f"Unsuccessful decryptions: {n_queries - successful_decryption_count} ({(n_queries - successful_decryption_count) / n_queries * 100}%)")
print()
print(f"Successful key guesses: {successful_key_guess_count} ({successful_key_guess_count / n_queries * 100}%)")
print(f"Unsuccessful key guesses: {n_queries - successful_key_guess_count} ({(n_queries - successful_key_guess_count) / n_queries * 100}%)")