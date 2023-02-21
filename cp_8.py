from binascii import hexlify, unhexlify
from Crypto.Cipher.AES import block_size


def count_aes_ecb_repetitions(ciphertext):
    chunks = [ciphertext[i:i + block_size] for i in range(0, len(ciphertext), block_size)]
    number_of_duplicates = len(chunks) - len(set(chunks))
    return number_of_duplicates


def detect_ecb_encrypted_ciphertext(ciphertexts):
    best = (-1,0)

    for i in range(len(ciphertexts)):
        repetitions = count_aes_ecb_repetitions(ciphertexts[i])
        best = max(best, (i, repetitions), key=lambda t: t[1])
    return best


def main():
    ciphertexts = [bytes.fromhex(line.strip()) for line in open('data/input-4.txt')]
    result = detect_ecb_encrypted_ciphertext(ciphertexts)

    print(f"The ciphertext encrypted in ECB mode is the one at position {result[0]} which contains {result[1]} repetitions")

    assert result[0] == 132


if __name__ == "__main__":
    main()
