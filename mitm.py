from multiprocessing import Pool
from functools import partial
from pyDes import des
import array


PLAIN_TEXT = '89504E470D0A1A0A'
CIPHER_TEXT = '89A3F4E3A99337A4'


def encrypt(key, plain_text):
    cipher = des(key)
    return cipher.encrypt(plain_text)


def decrypt(key, cipher_text):
    cipher = des(key)
    return cipher.decrypt(cipher_text)


def two_des_encrypt(k1, k2, plain_text):
    return encrypt(k2, encrypt(k1, plain_text))


def two_des_decrypt(k1, k2, cipher_text):
    return decrypt(k1, decrypt(k2, cipher_text))


def generate_keys(num):
    for i in range(num):
        arr = [0] * 8
        ind = -1
        for j in range(i // 127):  # pyDes can only handle byte values in range 0-127
            arr[ind] = 127
            ind -= 1
        arr[ind] = i % 127
        yield array.array('B', arr).tostring()


def hex_formating(bs):
    return ''.join([format(b, '02x') for b in bs])


def composed_encrypt(plain_text, key):
    return (encrypt(key, plain_text), key)


def convert_string_to_bytes(s):
    # string needs to be an even number in length
    if len(s) % 2 != 0:
        raise ValueError
    else:
        ls = [s[i:i + 2] for i in range(0, len(s), 2)]
        return array.array('B', [int(c, 16) for c in ls]).tostring()


def mitm(nkeys, plain_text, cipher_text, pool=None):
    # we'll start off with serial and maybe do multi threaded later
    if pool is None:
        table = {}
        # generate all the encryptions
        for k in generate_keys(nkeys):
            c = encrypt(k, plain_text)
            table[c] = k
    else:
        table = dict(pool.map(partial(composed_encrypt, plain_text), generate_keys(nkeys)))

    # iterate each decryption and quit if we find a match
    for k in generate_keys(nkeys):
        p = decrypt(k, cipher_text)
        if p in table.keys():
            k1 = hex_formating(table[p])
            k2 = hex_formating(k)
            print('found keys: (k1:{}, k2:{})'.format(k1, k2))
            print('apply k2 then k1 to decrypt')
            # print('intermediate is ', p)
            return

    # if here then we didn't find anything
    print('did not find keys')


p = PLAIN_TEXT
cho = CIPHER_TEXT

ph = convert_string_to_bytes(p)
ch = convert_string_to_bytes(cho)

print('plain text:', ph)
print('cipher text:', ch)

if len(ph) != len(ch):
    print('please provide plain and cipher text with matching lengths')
    print('the current lenths are:\n\tplain: {}\n\tcipher: {}'.format(len(ph), len(ch)))
else:
    with Pool() as p:
        mitm(1015, ph, ch, p)
