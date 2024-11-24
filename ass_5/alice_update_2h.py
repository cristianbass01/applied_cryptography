from alice_update import *

# Construct 1000 decryption oracle queries (more accurately, decapsulation oracle queries)
# at random and test for how many of them you can get an answer from the decryption
# oracle.

n_queries = 1000

pk, sk, N = KGen(load_private=True)
print(f"{pk = }")
print(f"{N = }")

random_values = generate_random_cyphertexts(1, N, n_queries)

counter_valid_cyphers = 0

for value in tqdm(random_values):

    decrypted = Decapsulate(value, sk, N)

    if decrypted is not None:
        counter_valid_cyphers += 1

print(f"Valid cyphers: {counter_valid_cyphers} ({counter_valid_cyphers / n_queries * 100}%)")
print(f"Invalid cyphers: {n_queries - counter_valid_cyphers} ({(n_queries - counter_valid_cyphers) / n_queries * 100}%)")





