from binascii import unhexlify


with open('data/input-1.txt') as data_file:
    ciphertext_list = [ unhexlify(line.strip()) for line in data_file ]


def bxor(a, b):
    "bitwise XOR of bytestrings"
    return bytes([ x^y for (x,y) in zip(a, b)])


def brute_force_sing_char_attack(ciphertext):
    best = None
    for i in range(2**8):
        candidate_key = i.to_bytes(1,byteorder='big')
        keystream = candidate_key*len(ciphertext)
        candidate_message = bxor(ciphertext,keystream)
        ascii_text_chars = list(range(97, 122)) + [32]
        nb_letters = sum([ x in ascii_text_chars for x in candidate_message ])
        if best == None or nb_letters > best['nb_letters']:
            best = {"message": candidate_message, 'nb_letters': nb_letters, 'key': candidate_key}
    return best

result = []
for byte in ciphertext_list:
    result.append(brute_force_sing_char_attack(byte))


# sort list by the field nb_letters
new_result = sorted(result, key=lambda k: k['nb_letters'], reverse=True)
print(new_result[0])

