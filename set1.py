
from base64 import b64encode
from binascii import hexlify, unhexlify

#####################
###  Challenge 1  ###
#####################
def convert_hex_to_base64(input):
    return b64encode(unhexlify(input)).decode("utf-8")

assert convert_hex_to_base64('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d')  == 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'


#####################
###  Challenge 2  ###
#####################
def fixed_xor(buf1, buf2):
    buf1, buf2 = unhexlify(buf1), unhexlify(buf2)
    return hexlify(bytes([(buf1[i] ^ buf2[i]) for i in range(len(buf1))])).decode("utf-8")

assert fixed_xor('1c0111001f010100061a024b53535009181c', '686974207468652062756c6c277320657965') == '746865206b696420646f6e277420706c6179'

#####################
###  Challenge 3  ###
#####################
import string
def single_byte_xor_cipher(input):
    LETTER_FREQUENCIES = {
            'a': 0.0651738, 'b': 0.0124248, 'c': 0.0217339,
            'd': 0.0349835, 'e': 0.1041442, 'f': 0.0197881,
            'g': 0.0158610, 'h': 0.0492888, 'i': 0.0558094,
            'j': 0.0009033, 'k': 0.0050529, 'l': 0.0331490,
            'm': 0.0202124, 'n': 0.0564513, 'o': 0.0596302,
            'p': 0.0137645, 'q': 0.0008606, 'r': 0.0497563,
            's': 0.0515760, 't': 0.0729357, 'u': 0.0225134,
            'v': 0.0082903, 'w': 0.0171272, 'x': 0.0013692,
            'y': 0.0145984, 'z': 0.0007836, ' ': 0.1918182}
    input_as_bytes = unhexlify(input)
    best_score = float('-inf')
    likely_string = None
    likely_key = None
    for char in string.printable:
        decrypted_str = bytes([byte ^ ord(char) for byte in input_as_bytes]).decode("latin-1")
        score = sum([LETTER_FREQUENCIES[char.lower()] if char in string.ascii_letters or char == ' ' else -0.25 for char in decrypted_str ]) / len(decrypted_str)
        if score > best_score:
            best_score = score
            likely_string = decrypted_str
            likely_key  = char
    return (likely_string, likely_key, score)
#assert(single_byte_xor_cipher('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736') == ("Cooking MC's like a pound of bacon", 'X', 0.014387947058823528))


#####################
###  Challenge 4  ###
#####################
def find_encrypted_string():
    highest_score = float('-inf')
    probable_decoded_str = None
    probable_key = None
    input_with_highest_score = None
    with open("4.txt") as f:
        for line in f:
            # Need to strip the newline from end of str
            decoded_str, key, score = single_byte_xor_cipher(line.strip())
            if score > highest_score:
                highest_score = score
                probable_decoded_str = decoded_str
                probable_key = key
                input_with_highest_score = line

    return input_with_highest_score
