
from base64 import b64encode
from binascii import hexlify, unhexlify

def convert_hex_to_base64(input):
    return b64encode(unhexlify(input)).decode("utf-8")

# encoding adds a newline after ever 76 bytes for some reason, so we need to strip that
assert convert_hex_to_base64('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d')  == 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'


def fixed_xor(buf1, buf2):
    buf1, buf2 = unhexlify(buf1), unhexlify(buf2)
    return hexlify(bytes([(buf1[i] ^ buf2[i]) for i in range(len(buf1))])).decode("utf-8")

assert fixed_xor('1c0111001f010100061a024b53535009181c', '686974207468652062756c6c277320657965') == '746865206b696420646f6e277420706c6179'
