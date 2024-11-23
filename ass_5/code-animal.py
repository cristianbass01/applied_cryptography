import random
import math
from secret import secret_key, decryption_oracle

modulus = 43156202150929343997204023690237148570191681940132577320374036808463240350882583048133407947064555839575112876002816227754056201929511529594423304196966617850624037811420032104728851930464693039613322475780195848729674846527655365879679078451495188227754101669668167688339861070729531263596514109718240053728887995295522349061627732545083926038985187692231898746079262120114964297005399587664178930260025038474302247096209888692518107068724001569615212092665409734376056960785115028373796416656188001131171958339297433047206918144535328608819092203454976824419428933920601592396035248631882572207311154100883811864507
public_key = 65533


#def animal_encoder(animal):
#    ascii_values = []
#    for char in animal:
#        ascii_values.append(str(ord(char)))
#
#    return int(''.join(ascii_values))

def encrypt(plaintext, public_key, modulus):
    return pow(plaintext, public_key, modulus)

#query_string = input("What's your query: ")
#query = int(query_string)
#query = 805113737

query=random.randint(1,100)
# print(f"{modulus = }")
# print(f"{public_key = }")
# print(f"{query = }")


print("Alice is generating a key to share with Bob...")
print("Alice is encrypting this key...")
print("Eve (you) has captured the encrypted key! Here it is:")
encrypted_query = encrypt(query, public_key, modulus)
print(encrypted_query)

decryption_query = int(input("You get ONE try! What do you want to decrypt: "))
if decryption_query == encrypted_query:
    print("Your ciphertext must be different than my ciphertext!")
else:
    decrypted = decryption_oracle(decryption_query)
    print("Decrypted: ", decrypted)

    flag_guess = int(input("What is Alice's key? One query: "))
    # print(f"{flag_guess = }")
    if query == flag_guess:
        print("Win!")
    else:
        print("Go fish.")



