from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from random import randint
import os
from math import ceil
from itertools import zip_longest
import random
backend = default_backend()

def test_ecb_128(ctxt):
    """test wether ctxt is a ECB mode ciphertext"""
    num_blocks = len(ctxt)//16
    return len(set([ctxt[i*16:(i+1)*16] for i in range(num_blocks)])) < num_blocks


def encrypt_aes_128_block(msg, key):
    '''unpadded AES block encryption'''
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    encryptor = cipher.encryptor()
    return encryptor.update(msg) + encryptor.finalize()

def decrypt_aes_128_block(ctxt, key):
    '''unpadded AES block decryption'''
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    decryptor = cipher.decryptor()
    decrypted_data =  decryptor.update(ctxt) + decryptor.finalize()
    return decrypted_data

def bxor(a, b, longest=True):
    if longest:
        return bytes([ x^y for (x, y) in zip_longest(a, b, fillvalue=0)])
    else:
        return bytes([ x^y for (x, y) in zip(a, b)])


def split_bytes_in_blocks(x, blocksize):
    nb_blocks = ceil(len(x)/blocksize)
    return [x[blocksize*i:blocksize*(i+1)] for i in range(nb_blocks)]

def pkcs7_padding(message, block_size):
    padding_length = block_size - ( len(message) % block_size )
    # the message length is a multiple of the block size
    # we add *a whole new block of padding*
    # (otherwise it would be difficult when removing the padding
    # to guess the padding length)
    if padding_length == 0:
        padding_length = block_size
    padding = bytes([padding_length]) * padding_length
    return message + padding

def pkcs7_strip(data):
    padding_length = data[-1]
    return data[:- padding_length]

def encrypt_aes_128_cbc(msg, iv, key):
    result = b''
    previous_ctxt_block = iv
    padded_ptxt = pkcs7_padding(msg, block_size=16)
    blocks = split_bytes_in_blocks(padded_ptxt, blocksize=16)
                        
    for block in blocks:
        to_encrypt = bxor(block, previous_ctxt_block)
        new_ctxt_block = encrypt_aes_128_block(to_encrypt, key)
        result += new_ctxt_block
        # for the next iteration
        previous_ctxt_block = new_ctxt_block
                                                                            
        return result

def decrypt_aes_128_cbc(ctxt, iv, key):
    result = b''
    previous_ctxt_block = iv
    blocks = split_bytes_in_blocks(ctxt, blocksize=16)
                                                                                                
    for block in blocks:
        to_xor = decrypt_aes_128_block(block, key)
        result += bxor(to_xor, previous_ctxt_block)
        assert len(result) != 0
        # for the next iteration
        previous_ctxt_block = block
    return pkcs7_strip(result)

def encrypt_aes_128_ecb(msg,key):
    padded_msg = pkcs7_padding(msg, block_size=16)
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    encryptor = cipher.encryptor()
    return encryptor.update(padded_msg) + encryptor.finalize()

def decrypt_aes_128_ecb(ctxt, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    decryptor = cipher.decryptor()
    decrypted_data =  decryptor.update(ctxt) + decryptor.finalize()
    message = pkcs7_strip(decrypted_data)
    return message

for _ in range(5):
    length = randint(5,50)
    msg = os.urandom(length)
    key = os.urandom(16)
    iv = os.urandom(16)
    ctxt = encrypt_aes_128_cbc(msg, iv, key)
    #assert decrypt_aes_128_cbc(ctxt, iv, key) == msg

def encryption_oracle(message, mode=None):
    key = os.urandom(16)
    random_header = os.urandom(randint(5, 10))
    random_footer = os.urandom(randint(5, 10))
    to_encrypt = random_header + message + random_footer

    if mode==None:
        mode = random.choice(['ECB', 'CBC'])
    if mode == 'ECB':
        return encrypt_aes_128_ecb(to_encrypt, key)
    elif mode == 'CBC':
        iv = os.urandom(16)
        return encrypt_aes_128_cbc(to_encrypt, iv, key)

for _ in range(10):
    mode = random.choice(['ECB', 'CBC'])
    # because of the random header and footer we need more that just 2 blocks of plaintext
    message = b'A'*50
    ctxt = encryption_oracle(message, mode)
    detected_mode = 'ECB' if test_ecb_128(ctxt) else 'CBC'
    assert detected_mode == mode
