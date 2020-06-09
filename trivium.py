# %%
import binascii
from random import SystemRandom
# %%


def text_to_bits(text, encoding='utf-8', errors='surrogatepass'):
    bits = bin(int(binascii.hexlify(text.encode(encoding, errors)), 16))[2:]
    return bits.zfill(8 * ((len(bits) + 7) // 8))

# %%


def text_from_bits(bits, encoding='utf-8', errors='surrogatepass'):
    n = int(bits, 2)
    return int2bytes(n).decode(encoding, errors)

# %%


def int2bytes(i):
    hex_string = '%x' % i
    n = len(hex_string)
    return binascii.unhexlify(hex_string.zfill(n + (n & 1)))
# %%


def shahiXOR(a, b):
    if a == '0' and b == '0':
        return '0'
    elif a == '0' and b == '1':
        return '1'
    elif a == '1' and b == '0':
        return '1'
    elif a == '1' and b == '1':
        return '0'
# %%


def shahiAND(a, b):
    if a == '0' and b == '0':
        return '0'
    elif a == '0' and b == '1':
        return '0'
    elif a == '1' and b == '0':
        return '0'
    elif a == '1' and b == '1':
        return '1'
# %%


def initShifts(shiftA, shiftB, shiftC, key, IV):
    for i in range(80):
        IV[i] = str(IV[i])
        key[i] = str(IV[i])
    for i in range(80):
        shiftA.insert(0, key[i])
        shiftA.pop()
        shiftB.insert(0, IV[i])
        shiftB.pop()
    shiftC[110] = shiftC[109] = shiftC[108] = '1'
    for i in range(4*288):
        t1 = shahiXOR(shiftB[77], shahiXOR(
            shahiAND(shiftA[90], shiftA[91]), shahiXOR(shiftA[65], shiftA[92])))
        t2 = shahiXOR(shiftC[86], shahiXOR(
            shahiAND(shiftB[81], shiftB[82]), shahiXOR(shiftB[68], shiftB[83])))
        t3 = shahiXOR(shiftA[68], shahiXOR(
            shahiAND(shiftC[108], shiftC[109]), shahiXOR(shiftC[65], shiftC[110])))
        shiftA.insert(0, t3)
        shiftB.insert(0, t1)
        shiftC.insert(0, t2)
        shiftA.pop()
        shiftB.pop()
        shiftC.pop()
    return shiftA, shiftB, shiftC
# %%


def keyGeneration(shiftA, shiftB, shiftC, key, IV, size):
    z = []
    for i in range(size):
        t1 = shahiXOR(shiftA[65], shiftA[92])
        t2 = shahiXOR(shiftB[68], shiftB[83])
        t3 = shahiXOR(shiftC[65], shiftC[110])
        z.append(shahiXOR(t1, shahiXOR(t2, t3)))
        t1 = shahiXOR(shahiXOR(t1, shiftB[77]),
                      shahiAND(shiftA[90], shiftA[91]))
        t1 = shahiXOR(shahiXOR(t2, shiftC[86]),
                      shahiAND(shiftB[81], shiftB[82]))
        t1 = shahiXOR(shahiXOR(t3, shiftA[68]),
                      shahiAND(shiftC[108], shiftC[109]))
        shiftA.insert(0, t3)
        shiftB.insert(0, t1)
        shiftC.insert(0, t2)
        shiftA.pop()
        shiftB.pop()
        shiftC.pop()
    return z
# %%


def encryption(plainText, key, IV, size):

    binaryText = list(text_to_bits(plainText))

    # shift registers
    shiftA = ['0' for x in range(93)]
    shiftB = ['0' for x in range(84)]
    shiftC = ['0' for x in range(111)]

    # setting key and IV
    shiftA, shiftB, shiftC = initShifts(shiftA, shiftB, shiftC, key, IV)
    # key stream generation
    keyStream = keyGeneration(shiftA, shiftB, shiftC, key, IV, size)
    encryptedText = []
    for i in range(size):
        encryptedText.append(shahiXOR(keyStream[i], binaryText[i]))
    return encryptedText
# %%


def decryption(encryptedText, key, IV, size):
    # shift registers
    shiftA = ['0' for x in range(93)]
    shiftB = ['0' for x in range(84)]
    shiftC = ['0' for x in range(111)]

    # setting key and IV
    shiftA, shiftB, shiftC = initShifts(shiftA, shiftB, shiftC, key, IV)
    # key stream generation
    keyStream = keyGeneration(shiftA, shiftB, shiftC, key, IV, size)

    plainText = []
    for i in range(size):
        plainText.append(shahiXOR(keyStream[i], list(encryptedText)[i]))
    return plainText


def main():
    # random IV and key
    x = SystemRandom()
    IV = [x.randrange(2) for i in range(80)]
    key = [x.randrange(2) for i in range(80)]
    plainText = input("Enter plaintext: ")

    encryptedText = ''.join(encryption(plainText, key, IV, len(plainText)*8))
    print('Encrypted Binary: '+encryptedText)
    decryptedText = ''.join(decryption(
        encryptedText, key, IV, len(plainText)*8))
    print('Decryted Text: '+text_from_bits(decryptedText))


if __name__ == "__main__":
    main()


# %%
