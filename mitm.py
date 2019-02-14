from multiprocessing import Pool
from functools import partial
from pyDes import des
import array


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


key = '\x00\x00\x00\x00\x00\x00\x00\x0f'
key2 = '\x00\x00\x00\x00\x00\x00\x7f\x7f'
# p = 'hello___'
# ph = ['\\x' + hex(ord(c))[2:] for c in p]
# print(ph)
# ph = ''.join(['\\x%02x' % ord(c) for c in p])
p = ['89', '50', '4E', '47', '0D', '0A', '1A', '0A']
ph = array.array('B', [int(c, 16) for c in p]).tostring()
print('plain text:', ph)
ph = convert_string_to_bytes(''.join(p))
cho = ['89', 'A3', 'F4', 'E3', 'A9', '93', '37', 'A4']
ch = array.array('B', [int(c, 16) for c in cho]).tostring()
print('cipher text:', ch)
ch = convert_string_to_bytes(''.join(cho))
# c = encrypt(key, ph)
# print(type(c), c)
# p2 = decrypt(key, c)
# print(p2 == bytes(ph, 'utf-8'), p2)

# 2des
# c = two_des_encrypt(key, key2, ph)
# p2 = two_des_decrypt(key, key2, c)
# print(c)
# print(p2 == bytes(ph, 'utf-8'), p2)

# mitm test
# print('test')
# c = encrypt(key, ph)
# ch = two_des_encrypt(key, key2, ph)
# print(type(ph), type(ch))
# cd = decrypt(key2, ch)
# print(c == cd, c, cd)
print(len(ph), len(ch))
with Pool() as p:
    mitm(1015, ph, ch, p)
