import codecs
import hmac
import os
import sys
from hashlib import sha256, sha512
from textwrap import wrap
import ecdsa


def importMnenmonic(mnemonic):
    f = open('words.txt', 'r')
    all_words = f.readlines()

    seed_tot = []
    for word in mnemonic:
        for i in range(len(all_words)):
            if word == all_words[i].strip():
                seed_tot.append(bin(i)[2:].zfill(11))
                break
    seed_tot = ''.join(seed_tot)
    check_first = seed_tot[128:]
    seed_bin = seed_tot[:128]

    data = bytearray.fromhex(hex(int(seed_bin, 2))[2:])
    checksum = sha256(data).hexdigest()
    if bin(int(checksum, 16))[2:].zfill(256)[:4] == check_first:
        print('Valid seed')
    else:
        print('Invalid seed')
        exit(1)

    return seed_bin


def generateMnemonic():
    seed = os.urandom(16)
    seed_bin = bin(int.from_bytes(seed, byteorder=sys.byteorder, signed=False))[2:]
    data = bytearray.fromhex(hex(int(seed_bin, 2))[2:])
    checksum = sha256(data).hexdigest()
    seed_tot = seed_bin.zfill(128) + bin(int(checksum, 16))[2:].zfill(256)[:4]

    words_bin = wrap(seed_tot, 11)

    f = open('words.txt', 'r')
    all_words = f.readlines()
    words = []
    for word_bin in words_bin:
        index = int(word_bin, 2)
        words.append(all_words[index].strip())

    return seed_bin, words


def getMPrivK_MCC(root_seed):
    # print(hex(int(root_seed, 2))[2:])
    hashed = hmac.new(bytes("Bitcoin seed", 'ascii'), bytearray.fromhex(hex(int(root_seed, 2))[2:]),
                      sha512).hexdigest()
    hashed_bin = bin(int(hashed, 16))[2:].zfill(512)
    hash_split = wrap(hashed_bin, 256)

    mpk = hash_split[0]
    mcc = hash_split[1]

    return mpk, mcc


def generateMpubK(priv_key):
    priv_key_hex = hex(int(priv_key, 2))[2:]
    private_key_bytes = codecs.decode(priv_key_hex, 'hex')

    pub_key = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1).verifying_key
    pub_key_bytes = pub_key.to_string()
    pub_key_hex = codecs.encode(pub_key_bytes, 'hex')
    pub_key_hex2 = hex(int(pub_key_hex, 16))[2:]
    XY = wrap(pub_key_hex2, 64)
    X = XY[0]
    Y = XY[1]
    Y_bin = bin(int(Y, 16))
    if Y_bin[len(Y_bin) - 1] == "1":
        X = '03' + X
    else:
        X = '02' + X

    return X  # master public key


def generateKeyAtIndex(ppk, pcc, index):
    print(ppk + pcc + bin(index)[2:])
    return getMPrivK_MCC(ppk + pcc + bin(index)[2:])


if __name__ == '__main__':
    print('Bonjour, que voulez vous faire ?')
    print('1) Générer une mnemonic phrase')
    print('2) Importer une mnemonic phrase')
    root_seed, mnemonic = '', ''
    choix = int(input())
    if choix == 1:
        root_seed, mnemonic = generateMnemonic()
        print('Votre mnemonic :')
        print(" ".join(mnemonic))
    else:
        print('Insérez votre mnenmonic phrase :')
        mnemonic = input().split(' ')
        root_seed = importMnenmonic(mnemonic)

    while True:
        print('Faites un choix')
        print('1) Afficher Master Private Key & Chain Code')
        print('2) Afficher Master Public Key')
        print('3) Sortie')
        choix = int(input())
        master_private_key, master_chain_code = getMPrivK_MCC(root_seed)
        master_pub_key = generateMpubK(master_private_key)

        if choix == 1:
            print('Votre master private key:', hex(int(master_private_key, 2)))
            print('Votre master chain code:', hex(int(master_chain_code, 2)))
        elif choix == 2:
            print('Votre Master Public Key:','0x' + master_pub_key)
        else:
            exit(0)
