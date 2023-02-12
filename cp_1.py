from binascii import hexlify, unhexlify
from base64 import b64encode, b64decode

input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"

expected_output = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

b64_string = b64encode(unhexlify(input))

decoded = b64_string.decode('ASCII')

assert decoded == expected_output

