from flag import FLAG, WITTYCOMMENT
import random

rng = random.SystemRandom()

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

generator = 11

def play():
    challenge = rng.randint(0, 1)

    a = rng.randint(1, prime-1)
    b = rng.randint(1, prime-1)
    z = rng.randint(1, prime-1)

    A = pow(generator, a, prime)
    B = pow(generator, b, prime)
    C = pow(generator, a*b, prime)
    Z = pow(generator, z, prime)

    print(f"""Here is A=g^a: {A}, and B=g^b: {A}, {B}.
What is the following, g^ab or a random group element?
{C if challenge == 1 else Z}

Choose 1 if you think it's g^ab and 0 if you think it's random.""")


    guess = int(input("> ").strip())

    if guess == challenge:
        print(f"""Correct! 
It was indeed {"g^ab" if challenge == 1 else "a random element"}.
You can check for yourself with a: {a}, and b: {b}""")
        return 1
    else:
        print(f"""Wrong! 
It was actually {"g^ab" if challenge == 1 else "a random element"}.
You can check for yourself with a: {a}, and b: {b}""")
        return -1



def main():
    balance = 100

    print(f"""Welcome to our Radboud Random Game: 
We have picked a great group for Diffie-Hellman so that our 
Decisional problem is definitely unbreakable! 
Try it, we are sure you will not be able to get 120 points! 
You will start with {balance} points. Good luck!
    """)

    while True:
        balance += play()

        if balance <= 0:
            print(WITTYCOMMENT)
            exit(0)

        if balance >= 120:
            print(FLAG)
            exit(0)

        print(f"Your current balance is {balance} points.\n")

if __name__ == '__main__':
    main()