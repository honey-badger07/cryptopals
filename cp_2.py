from binascii import unhexlify

input_str = "1c0111001f010100061a024b53535009181c"
input_two = "686974207468652062756c6c277320657965"
expected_output = "746865206b696420646f6e277420706c6179"


def bxor(a,b):
    return bytes([x^y for (x,y) in zip(a,b)])

assert bxor(unhexlify(input_str),unhexlify(input_two)) == unhexlify(expected_output) 
