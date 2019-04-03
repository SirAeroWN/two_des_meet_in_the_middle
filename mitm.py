#!/usr/bin/env python3
from multiprocessing import Pool
from functools import partial
from pyDes import des
import array
# import sys


# The texts, these should be hexcode representations of the known plaintext and ciphertext
PLAIN_TEXT = '89504E470D0A1A0A'
CIPHER_TEXT = '89A3F4E3A99337A4'


# encrypt given plaintext with key
def encrypt(key, plain_text):
    cipher = des(key)
    return cipher.encrypt(plain_text)


# decrypt given plaintext with key
def decrypt(key, cipher_text):
    cipher = des(key)
    return cipher.decrypt(cipher_text)


# perform a full 2DES encryption (not used in cracking)
def two_des_encrypt(k1, k2, plain_text):
    return encrypt(k2, encrypt(k1, plain_text))


# perform a full 2DES decryption (not used in cracking)
def two_des_decrypt(k1, k2, cipher_text):
    return decrypt(k1, decrypt(k2, cipher_text))


def generate_keys(num):
    for n in range(num):
        arr = [0] * 8
        powers = [7, 6, 5, 4, 3, 2, 1, 0]
        for i, p in enumerate(powers):
            arr[i] = n // (128 ** p)
            n = n - (arr[i] * (128 ** p)) if n >= (128 ** p) else n
        yield array.array('B', arr).tostring()


def to_byte_string(arr):
	return array.array('B', arr).tostring()


# convert a bytes string into something more human readable
def hex_formating(bs):
    return ''.join([format(b, '02x') for b in bs])


# convert a bytes string into something more human readable
def int_formating(bs):
    return [int(b) for b in bs]


# convert human readable text into hex pairs
def string_to_hex(s):
    return ''.join([format(ord(c), '02x') for c in s])


# basically just a helper for multi threading
def composed_encrypt(plain_text, key):
    return (encrypt(key, plain_text), key)


# convert a regular string with hex pairs into a format pyDes can play nice with
def convert_string_to_bytes(s):
    # string needs to be an even number in length
    if len(s) % 2 != 0:
        raise ValueError
    else:
        ls = [s[i:i + 2] for i in range(0, len(s), 2)]
        return array.array('B', [int(c, 16) for c in ls]).tostring()


# perform the actual meet in the middle attack
# meet in the middle is a special form of plain text attack
# first, you generate a table of all the keys and the ciphertext that corresponds to
#   encrypting the plaintext with that key
# then you iterate through all the keys again, this time decrypting the given
#   ciphertext and checking if the result is in the table
# if one of the results is in the table then you have found your key pair
def mitm(nkeys, plain_text, cipher_text, pool=None):
    # build table in serial if we didn't get the multiprocessing pool
    if pool is None:
        table = {}
        # generate all the encryption
        for k in generate_keys(nkeys):
            c = encrypt(k, plain_text)
            table[c] = k
    else:
        table = dict(pool.map(partial(composed_encrypt, plain_text), generate_keys(nkeys)))  # partial composes a function with standard args

    # iterate each decryption and quit if we find a match
    for k in generate_keys(nkeys):
        p = decrypt(k, cipher_text)
        if p in table.keys():
            k1 = int_formating(table[p])
            k2 = int_formating(k)
            print('found keys: (k1:{}, k2:{})'.format(k1, k2))
            print('apply k2 then k1 to decrypt')
            print('use a tool such as this one (http://des.online-domain-tools.com/) to decrypt the whole file with the keys')
            return (k1, k2)

    # if here then we didn't find anything
    print('did not find keys')


if __name__ == '__main__':
    p = PLAIN_TEXT
    cho = CIPHER_TEXT

    # convert the hex strings we were given to a more pyDes friendly format
    ph = convert_string_to_bytes(p)
    ch = convert_string_to_bytes(cho)

    print('plain text:', ph)
    print('cipher text:', ch)

    # make sure our text samples are the same size
    if len(ph) != len(ch):
        print('please provide plain and cipher text with matching lengths')
        print('the current lengths are:\n\tplain: {}\n\tcipher: {}'.format(len(ph), len(ch)))
    else:
        # create a processes pool, will grab all processors by default
        with Pool() as p:
            keys = mitm(127**2, ph, ch, p)
            print(f"k1:{hex_formating(keys[0])}, k2{hex_formating(keys[1])}")
