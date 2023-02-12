from binascii import unhexlify

CIPHERTEXT = unhexlify("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")

def bxor(a,b):
    return bytes([x^y for (x,y) in zip(a,b)])

def brute_force_single_byte(CIPHERTEXT):
    for i in range(255):
        candidate_key = bytes([i])
        keystream = candidate_key*len(CIPHERTEXT)
        print(bxor(CIPHERTEXT, keystream))

brute_force_single_byte(CIPHERTEXT)
#output needs '| grep "bacon"'
