from cp_10 import aes_ecb_encrypt, aes_ecb_decrypt
from Crypto import Random
from Crypto.Cipher import AES


class ECBOracle:    
    def __init__(self):
        self._key = Random.new().read(AES.key_size[0])


    def encrypt(self, email):
        encoded = kv_encode(profile_for(email))
        bytes_to_encrypt = encoded.encode()
        return aes_ecb_encrypt(bytes_to_encrypt, self._key)

    def decrypt(self, ciphertext):
        return aes_ecb_decrypt(ciphertext, self._key)


def kv_encode(dict_object):
    encoded_text = ''
    for item in dict_object.items():
        encoded_text += item[0] + '=' + str(item[1]) + '&'

    return encoded_text[:-1]


def kv_parse(encoded_text):
    output = {}
    attributes = encoded_text.split('&')

    for attribute in attributes:
        values = attribute.split('=')
        key = int(values[0]) if values[0].isdigit() else values[0]
        value = int(values[1]) if values[1].isdigit() else values[1]

        output[key] = value
    return output


def profile_for(email):
    email = email.replace('&', '').replace('=', '')
    return {
            'email': email,
            'uid': 10,
            'role': 'user'
            }


def ecb_cut_and_paste(encryption_oracle):
    prefix_len = AES.block_size - len("email=")
    suffix_len = AES.block_size - len("admin")
    email1 = 'x' * prefix_len + "admin" + (chr(suffix_len) * suffix_len)
    encrypted1 = encryption_oracle.encrypt(email1)

    email2 = "master@me.com"
    encrypted2 = encryption_oracle.encrypt(email2)
    forced = encrypted2[:32] + encrypted1[16:32]

    return forced


def main():
    oracle = ECBOracle()
    forced_ciphertext = ecb_cut_and_paste(oracle)

    decrypted = oracle.decrypt(forced_ciphertext)

    parsed = kv_parse(decrypted.decode())
    assert parsed['role'] == 'admin'


if __name__ == '__main__':
    main()

