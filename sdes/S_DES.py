import time

P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
P8 = [6, 3, 7, 4, 8, 5, 10, 9]
LeftShift1 = [2, 3, 4, 5, 1]
LeftShift2 = [3, 4, 5, 1, 2]
IP = [2, 6, 3, 1, 4, 8, 5, 7]
IP_INVERSE = [4, 1, 3, 5, 7, 2, 8, 6]
EP = [4, 1, 2, 3, 2, 3, 4, 1]

SBox1 = [[1, 0, 3, 2],
         [3, 2, 1, 0],
         [0, 2, 1, 3],
         [3, 1, 0, 2]]

SBox2 = [[0, 1, 2, 3],
         [2, 3, 1, 0],
         [3, 0, 1, 2],
         [2, 1, 0, 3]]

P4 = [2, 4, 3, 1]


# 置换函数
def permute(bits, perm):
    return [bits[i - 1] for i in perm]


# 左移函数
def shift_left(bits, n):
    return bits[n:] + bits[:n]


# 生成子密钥
def generate_subkey(key):
    key = permute(key, P10)
    k1 = permute(shift_left(key[:5], 1) + shift_left(key[5:], 1), P8)
    k2 = permute(shift_left(shift_left(key[:5], 1) + shift_left(key[5:], 1), 2), P8)
    return k1, k2


# SBox替换
def sbox_substitution(bits, sbox):
    row = int(str(bits[0]) + str(bits[3]), 2)
    col = int(str(bits[1]) + str(bits[2]), 2)
    return '{0:02b}'.format(sbox[row][col])


# 异或函数
def xor(bits1, bits2):
    return [bits1[i] ^ bits2[i] for i in range(len(bits1))]


# 轮函数
def f_k(bits, key):
    left = bits[:4]
    right = bits[4:]
    # 扩展置换
    bits = permute(right, EP)
    # 用轮密钥异或
    bits = xor(bits, key)
    # SBox置换
    bits = sbox_substitution(bits[:4], SBox1) + sbox_substitution(bits[4:], SBox2)
    bits = [int(i) for i in bits]
    # 直接置换
    bits = permute(bits, P4)
    # 返回轮转后的左半部分
    return xor(bits, left)


# 加密函数
def encrypt(plain_text, key):
    # print(plain_text, key)
    # 生成子密钥
    k1, k2 = generate_subkey(key)
    # 初始IP置换
    bits = permute(plain_text, IP)
    # 第一轮fk
    temp = f_k(bits, k1)
    # 合并
    bits = bits[4:] + temp
    # 第二轮
    bits = f_k(bits, k2)
    # 合并
    bits = bits + temp
    # 最终置换
    cipher_text = permute(bits, IP_INVERSE)
    # print(cipher_text)
    return cipher_text


# 解密函数
def decrypt(cipher_text, key):
    # print(cipher_text, key)
    # 生成子密钥
    k1, k2 = generate_subkey(key)
    # 初始IP置换
    bits = permute(cipher_text, IP)
    # 第一轮fk
    temp = f_k(bits, k2)
    # 合并
    bits = bits[4:] + temp
    # 第二轮
    bits = f_k(bits, k1)
    # 合并
    bits = bits + temp
    # 最终置换
    plain_text = permute(bits, IP_INVERSE)
    # print(plain_text)
    return plain_text


# 字符串转换成二进制列表
def string_to_bits(s):
    return [int(bit) for char in s for bit in format(ord(char), '08b')]


# 二进制列表转换成字符串
def bits_to_string(bits):
    chars = []
    for i in range(0, len(bits), 8):
        byte = bits[i:i + 8]
        chars.append(chr(int(''.join(map(str, byte)), 2)))
    return ''.join(chars)


def encrypt_string(plain_text, key):
    # print(plain_text,key)
    key = [int(char) for char in key]
    # 判断输入的明文是否为二进制格式
    if all(char in '01' for char in plain_text) and len(plain_text) == 8:
        bits = [int(char) for char in plain_text]
        return ''.join(map(str, encrypt(bits, key)))
    else:
        bits = string_to_bits(plain_text)
        cipher_bits = []
        for i in range(0, len(bits), 8):
            block = bits[i:i + 8]
            cipher_block = encrypt(block, key)
            cipher_bits.extend(cipher_block)
        return bits_to_string(cipher_bits)


def decrypt_string(cipher_text, key):
    # print(cipher_text,key)
    key = [int(char) for char in key]
    # 判断输入的密文是否为二进制格式
    if all(char in '01' for char in cipher_text) and len(cipher_text) == 8:
        bits = [int(char) for char in cipher_text]
        return ''.join(map(str, decrypt(bits, key)))
    else:
        bits = string_to_bits(cipher_text)
        plain_bits = []
        for i in range(0, len(bits), 8):
            block = bits[i:i + 8]
            plain_block = decrypt(block, key)
            plain_bits.extend(plain_block)
        return bits_to_string(plain_bits)


# 暴力破解
def key_crack(plain_text, cipher_text):
    start_time = time.time()
    possible_keys = []
    for i in range(1024):
        # 将整数i转换为10位二进制字符串
        key = f'{i:010b}'
        encrypted = encrypt_string(plain_text, key)
        if encrypted == cipher_text:
            possible_keys.append(key)

    end_time = time.time()
    if possible_keys:
        return ', '.join(possible_keys), end_time - start_time
    else:
        return "未找到匹配的密钥", end_time - start_time


if __name__ == '__main__':
    plain_text = '11101010'
    key = '0110110010'
    cipher_text = '11100011'
    print(f'加密得到密文为:{encrypt_string(plain_text, key)}')
    print(f'解密得到明文为:{decrypt_string(cipher_text, key)}')
    print(f'破解得到密钥为:{key_crack(plain_text,cipher_text)[0]};  耗时{key_crack(plain_text,cipher_text)[1]}秒')

    plain_text = 'hello world'
    cipher_text = 'I77M!7'
    print(f'加密得到密文为:{encrypt_string(plain_text, key)}')
    print(f'解密得到明文为:{decrypt_string(cipher_text, key)}')
