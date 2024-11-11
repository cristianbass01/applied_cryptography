# this file shows you how to interact with a script running remotely
# especially if you want to interact multiple times, this is much easier 
# than doing it by hand.

# this package is required for everything, you can install it with 
# 'pip install pwntools'
from pwn import *
import re
from time import sleep

# Secure group from RFC 3526
prime = int("""
FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
15728E5A 8AACAA68 FFFFFFFF FFFFFFFF""".replace('\n', '').replace(' ', ''), 
16)


# Function to parse the server response and retrieve values
def parse_values(output):
    # Use regular expressions to extract A, B, and the challenge value with more flexibility
    match = re.search(
        r".*Here is A=g\^a: (\d+),\s*and\s*B=g\^b: (\d+),\s*(\d+)\.\s*What is the following, g\^ab or a random group element\?\s*(\d+)", 
        output, 
        re.DOTALL
    )
    
    if match:
        A = int(match.group(1))
        B = int(match.group(3))
        challenge_value = int(match.group(4))
        return A, B, challenge_value
    return None, None, None

def update_balance(output):
    match = re.search(r"Your current balance is (\d+) points", output)
    if match:
        return int(match.group(1))
    return None

def init_balance(output):
    match = re.search(r"You will start with (\d+) points.", output)
    if match:
        return int(match.group(1))
    return None


def x_p_function(x, p):
    return pow(x, (p-1)//2, p)

def distinguisher(g_a, g_b, challenge_value):
    # Distinguish between g^ab and a random group element
    x_p_g_a = x_p_function(g_a, prime)
    x_p_g_b = x_p_function(g_b, prime)

    x_p_g_x = x_p_function(challenge_value, prime)
    
    if x_p_g_a == 1 or x_p_g_b == 1:
        if x_p_g_x == prime - 1:
            return 0
    elif x_p_g_a == prime - 1 and x_p_g_b == prime - 1:
        if x_p_g_x == 1:
            return 0
        
    return 1


# we need to connect to the remote server (this requires us to be in
# the Radboud network) we do so by setting up a remote process
r = remote('appliedcrypto.cs.ru.nl', 4145)

# Define the target score to win
TARGET_SCORE = 120
balance = 0

total_challenges = 0
total_challenges_random = 0
total_challenges_gab = 0

correct_guesses = 0
correct_guesses_random = 0
correct_guesses_gab = 0

# Receive output and decode it
output = r.recvuntil(b">").decode()
balance = init_balance(output)

# Game loop
while balance < TARGET_SCORE:
    # Parse A, B, and the challenge value from the output
    A, B, challenge_value = parse_values(output)
    
    if A is None or B is None:
        print("Failed to parse values from output.")
        break

    # Use the distinguisher to guess if the value is g^ab (1) or random (0)
    guess = distinguisher(A, B, challenge_value)
    
    # Increment total
    total_challenges += 1
    
    # Send the guess to the server
    r.sendline(str(guess).encode())
    
    try:
        # Attempt to receive until prompt or timeout
        output = r.recvuntil(b">").decode()
    except EOFError:
        # Check if we've reached the target balance
        print("You've reached the target balance (or the server is crushed)!")
        break

    # Update balance by parsing the output for the balance line
    new_balance = update_balance(output)
    if new_balance is not None:
        balance = new_balance
    
    # Check if the guess was correct
    if "Correct!" in output:
        correct_guesses += 1
        if guess == 0:
            correct_guesses_random += 1
            total_challenges_random += 1
        else:
            correct_guesses_gab += 1
            total_challenges_gab += 1
    else:
        if guess == 0:
            total_challenges_gab += 1
        else:
            total_challenges_random += 1
    
    # Display the updated balance
    print(f"Current balance: {balance}")
    
# Capture any remaining data from the server after the loop
try:
    final_output = r.recvall().decode()
    print(final_output)
except EOFError:
    print("No more data from server.")


# Print the total challenges, correct guesses, and probabilities
print(f"Total challenges: {total_challenges}")
print(f"Correct guesses: {correct_guesses}")
print(f"Probability of correct guesses: {correct_guesses / total_challenges:.2f}")
print(f"Total challenges (random): {total_challenges_random}")
print(f"Correct guesses (random): {correct_guesses_random}")
print(f"Probability of correct guesses (random): {correct_guesses_random / total_challenges_random:.2f}")
print(f"Total challenges (g^ab): {total_challenges_gab}")
print(f"Correct guesses (g^ab): {correct_guesses_gab}")
print(f"Probability of correct guesses (g^ab): {correct_guesses_gab / total_challenges_gab:.2f}")

# Close the connection
r.close()

# FLAG: flag_24563844526613476