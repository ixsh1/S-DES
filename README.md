# S-DES
信息安全导论作业1：S-DES算法实现
S-DES是一种简化版的 DES 加密算法。它包括加密和解密两个主要操作。S-DES 使用了一个 10 位的密钥，并对 8 位的明文数据块进行操作。

S-DES 算法步骤
子密钥生成：
密钥 K 是一个 10 位的二进制字符串，经过 P10（置换10）和 P8（置换8）的操作生成两个子密钥 K1 和 K2。
P10：将 10 位密钥重新排列，选取新顺序。
左循环移位：将密钥左右两部分各左移1位。
P8：从10位中挑选8位生成 K1。
左循环移位：将密钥再次左右两部分左移2位。
P8：生成 K2。
加密过程:
初始置换 (IP): 将 8 位明文数据重新排列。
使用子密钥 K1 进行 Fk 函数处理。
交换左半部分和右半部分。
使用子密钥 K2 进行 Fk 函数处理。
逆初始置换 (IP⁻¹): 将数据进行逆置换，得到最终密文。
Fk 函数:
将 8 位数据块分成左右两部分 (L 和 R)。
对右半部分 R 进行扩展置换 (E/P)，得到 8 位数据。
将结果与子密钥进行异或操作。
结果通过 S盒替代 (S0 和 S1)。
最后经过 P4 置换，与左半部分异或，得到新数据块。
