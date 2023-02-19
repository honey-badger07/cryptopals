import random
from random import randint
import os


def pkcs7_padding(message, block_size):
    padding_length = block_size - ( len(message) % block_size )
    if padding_length == 0:
        padding_length = block_size
    padding = bytes([padding_length]) * padding_length
    return message + padding


def pkcs7_strip(data):
    padding_length = data[-1]
    return data[:- padding_length]


def pkcs7_pad(message, block_size):
    if len(message) == block_size:
        return message

    ch = block_size - len(message) % block_size
    return message + bytes([ch] * ch)


def is_pkcs7_padded(binary_data):
    padding = binary_data[-binary_data[-1]:]

    return all(padding[b] == len(padding) for b in range(0, len(padding)))


def pkcs7_unpad(data):
    if len(data) == 0:
        raise Exception("The input data must contain at least one byte")

    if not is_pkcs7_padded(data):
        return data

    padding_len = data[len(data) - 1]
    return data[:-padding_len]



print(pkcs7_padding(b'YELLOW SUBMARINE', 20))
