from binascii import hexlify, unhexlify
from Crypto.Cipher.AES import block_size

def count_aes_ecb_repetitions(ciphertext):
    chunks = [ciphertext[i:i + block_size] for i in range(0, len(ciphertext), block_size)]
    number_of_duplicates = len(chunks) - len(set(chunks))
    return number_of_duplicates


with open('data/input-4.txt') as f:
    ctxts = [unhexlify(line.strip()) for line in f]

def has_repeated_blocks(ctxt, blocksize=16):
    '''blocksize is in bytes'''
    if len(ctxt) % blocksize != 0:
        raise Exception('ciphertext length is not a multiple of block size')
    else:
        num_blocks = len(ctxt) // blocksize
        
    blocks = [ctxt[i*blocksize:(i+1)*blocksize] for i in range(num_blocks)]
    
    if len(set(blocks)) != num_blocks:
        return True
    else:
        return False

hits = [ctxt for ctxt in ctxts if has_repeated_blocks(ctxt)]
print(hits)
