# S-DES
信息安全导论作业1：S-DES算法实现   
# 一、S-DES算法介绍：  
S-DES是一种简化版的 DES 加密算法。它包括加密和解密两个主要操作。S-DES 使用了一个 10 位的密钥，并对 8 位的明文数据块进行操作。  

## S-DES 算法步骤  
子密钥生成：  

密钥 K 是一个 10 位的二进制字符串，经过 P10（置换10）和 P8（置换8）的操作生成两个子密钥 K1 和 K2。  
P10：将 10 位密钥重新排列，选取新顺序。  
左循环移位：将密钥左右两部分各左移1位。  
P8：从10位中挑选8位生成 K1。  
左循环移位：将密钥再次左右两部分左移2位。  
P8：生成 K2。 
```python
# 生成子密钥
def generate_subkey(key):
    key = permute(key, P10)
    k1 = permute(shift_left(key[:5], 1) + shift_left(key[5:], 1), P8)
    k2 = permute(shift_left(shift_left(key[:5], 1) + shift_left(key[5:], 1), 2), P8)
    return k1, k2
```

加密过程:  

初始置换 (IP): 将 8 位明文数据重新排列。  
使用子密钥 K1 进行 Fk 函数处理。  
交换左半部分和右半部分。  
使用子密钥 K2 进行 Fk 函数处理。  
逆初始置换 (IP⁻¹): 将数据进行逆置换，得到最终密文。
```python
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
```

f_k 函数:  

将 8 位数据块分成左右两部分 (L 和 R)。  
对右半部分 R 进行扩展置换 (E/P)，得到 8 位数据。  
将结果与子密钥进行异或操作。  
结果通过 S盒替代 (S0 和 S1)。  
最后经过 P4 置换，与左半部分异或，得到新数据块。
```python
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
```
# 二、S-DES算法实现功能
## 第1关：基本测试  
根据S-DES算法编写和调试程序，提供GUI解密支持用户交互。输入可以是8bit的数据和10bit的密钥，输出是8bit的密文。 

在app.py文件中编写实现提供GUI解密支持用户交互  

![](./image/1.png)

## 第2关：交叉测试  
考虑到是算法标准，所有人在编写程序的时候需要使用相同算法流程和转换单元(P-Box、S-Box等)，以保证算法和程序在异构的系统或平台上都可以正常运行。设有A和B两组位同学(选择相同的密钥K)；则A、B组同学编写的程序对明文P进行加密得到相同的密文C；或者B组同学接收到A组程序加密的密文C，使用B组程序进行解密可得到与A相同的P。 

“这是什么组”的与我们组的交叉测试  

![](./image/4.png)  

![](./image/5.png)
## 第3关：扩展功能  
考虑到向实用性扩展，加密算法的数据输入可以是ASII编码字符串(分组为1 Byte)，对应地输出也可以是ACII字符串(很可能是乱码)。   

![](./image/2.png)
## 第4关：暴力破解  
假设你找到了使用相同密钥的明、密文对(一个或多个)，请尝试使用暴力破解的方法找到正确的密钥Key。在编写程序时，你也可以考虑使用多线程的方式提升破解的效率。请设定时间戳，用视频或动图展示你在多长时间内完成了暴力破解。  

![](./image/3.png)
## 第5关：封闭测试  
根据第4关的结果，进一步分析，对于你随机选择的一个明密文对，是不是有不止一个密钥Key？进一步扩展，对应明文空间任意给定的明文分组P_{n}，是否会出现选择不同的密钥K_{i}!=K_{j}加密得到相同密文C_n的情况？  

根据第四关的结果可得，随机选择的一个明密文对，不止有一个密钥Key。  

给定一个固定的明文分组P_{n}，使用不同的密钥 K_{i}!=K_{j}，有可能得到相同的密 C_n。 通过查询和检验可得这种情况称为密钥碰撞，原因是因为有限的密钥空间和密文空间；同时也是S-DES的结构非常简单，加密过程仅有两轮加密。

# 三、S-DES算法拓展：  
作为简化版的 DES，虽然可以帮助理解对称加密算法的基本原理，但其设计存在一些明显的缺点，主要在安全性和实用性方面。以下是 S-DES 算法的几个主要缺点
1. 密钥长度较短，易受暴力破解。对于现代计算机来说，暴力破解非常简单且快速。2. 数据块长度过小。3. 加密轮数太少。4. S-box（替换盒）结构过于简单。
 
所以拓展 S-DES 算法可以从多个方面进行深入研究和扩展，包括改进加密的强度、增加数据块长度、密钥长度、改进子密钥生成方式、以及结合其他加密方法。 

---
<small> 注释：本次实验项目开发环境为python，基于 Tkinter 的 GUI 应用程序，如需修改或更新，请联系3328856646@qq.com。 </small>
