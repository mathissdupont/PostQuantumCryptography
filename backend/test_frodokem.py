import time
import csv
import os
from statistics import mean
import oqs

NUM_TESTS = 400
ALGO = "FrodoKEM-640-AES"

os.makedirs("results", exist_ok=True)
csv_file = "results/frodo_results.csv"

keygen_times = []
encrypt_times = []
decrypt_times = []

for i in range(NUM_TESTS):
    server = oqs.KeyEncapsulation(ALGO)
    start = time.perf_counter()
    public_key = server.generate_keypair()
    keygen_times.append(time.perf_counter() - start)

    client = oqs.KeyEncapsulation(ALGO)
    start = time.perf_counter()
    ciphertext, shared_secret_client = client.encap_secret(public_key)
    encrypt_times.append(time.perf_counter() - start)

    start = time.perf_counter()
    shared_secret_server = server.decap_secret(ciphertext)
    decrypt_times.append(time.perf_counter() - start)

    if shared_secret_client != shared_secret_server:
        raise Exception(f"[ERROR] Iteration {i}: Shared secrets do not match!")

with open(csv_file, mode="w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["Iteration", "KeyGenTime(ms)", "EncryptTime(ms)", "DecryptTime(ms)"])
    for i in range(NUM_TESTS):
        writer.writerow([
            i + 1,
            round(keygen_times[i] * 1000, 4),
            round(encrypt_times[i] * 1000, 4),
            round(decrypt_times[i] * 1000, 4)
        ])

print("✅ Test completed: FrodoKEM-640-AES")
print(f"🔐 Average Key Generation Time:   {mean(keygen_times) * 1000:.2f} ms")
print(f"✉️  Average Encryption Time:      {mean(encrypt_times) * 1000:.2f} ms")
print(f"🔓 Average Decryption Time:      {mean(decrypt_times) * 1000:.2f} ms")
print(f"📄 Results saved to: {csv_file}")
