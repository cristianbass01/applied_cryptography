from alice_update import *

# Modify Alice’s script to include the FO second transform. Write the script and test it
# on your own computer. You will need to additionally implement key generation and
# the decryption oracle. For the encoding you can use your own ideas for generating
# deterministically a key from one’s name. You should submit your script together with
# the rest of the answers (in the pdf or separately).

# GENERATE KEYS
pk, sk, N = KGen(load_private=True)

# TEST IMPLEMENTATION
print("Testing implementation...")
test_implementation(sk, pk, N, n=1000)
print("All tests passed.")
#

print(f"{pk = }")
print(f"{N = }")

# RANDOM SEED FROM USER
name = input("What is your name : ")
X = name_encoder(name)

# ENCAPSULATE
c, k = Encapsulate(X, pk, N)

# SEND ENCRYPTED KEY
print("The encryption of the symmetric key is : ")
print(c)
    
# DECRYPTION QUERY
decryption_query = int(input("You get ONE try! What do you want to decrypt: "))

if decryption_query == c:
    print("Your ciphertext must be different than my ciphertext!")
else:
    decrypted = Decapsulate(decryption_query, sk, N)

    if decrypted is None:
        print("Decryption not valid due to hash mismatch or invalid format of decrypted message.")
    else:
        print("Decrypted: ", decrypted)

    # GUESS THE KEY FROM THE DECRYPTED QUERY
    flag_guess = int(input("What is Alice's key? One query: "))
    
    # print(f"{flag_guess = }")
    if k == flag_guess:
        print("Win!")
    else:
        print("Go fish.")



