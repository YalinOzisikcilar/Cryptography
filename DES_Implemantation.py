
def bin_xor(bin1,bin2):
    """
    >>> bin_xor('1011','0000')
    '1011'
    >>> bin_xor('1','0000')
    '0001'
    >>> bin_xor('1101','1011')
    '0110'
    >>> bin_xor('10101010','01010101')
    '11111111'
    """
    larger_len=max(len(bin1),len(bin2))
    bin1=bin1.rjust(larger_len,"0")
    bin2=bin2.rjust(larger_len,"0")

    result=""
    for i in range(larger_len):
        bit=int(bin1[i])^int(bin2[i])
        result=result+str(bit)
    return result


def binaryToDecimal(binary):
    power=0
    total=0
    for i in range(len(binary)-1,-1,-1):
        total=total+(int(binary[i])*(2**power))
        power+=1
    return total

def decimalToBinary(n):
    return bin(n).replace("0b", "")


def bytes2binary(bytes_input):
    """

    >>> bytes2binary(b'\\x01')
    '00000001'
    >>> bytes2binary(b'\\x03')
    '00000011'
    >>> bytes2binary(b'\\xf0')
    '11110000'
    >>> bytes2binary(b'\\xf0\\x80')
    '1111000010000000'
    """
    int_val = int.from_bytes(bytes_input, "big")
    bin_value=decimalToBinary(int_val)

    x=len(bin_value)%8
    if(x != 0):
        a=bin_value.rjust(len(bin_value)+(8-x),"0")
        return a
    else:
        return bin_value


def binary2bytes(binary):
    """
    >>> binary2bytes('00000001')
    b'\\x01'
    >>> binary2bytes('00000011')
    b'\\x03'
    >>> binary2bytes('11110000')
    b'\\xf0'
    >>> binary2bytes('1111000010000000')
    b'\\xf0\\x80'
    """
    bytearrays = []
    result = []
    while binary:
        bytearrays.append(binary[:8])
        binary = binary[8:]
    for i in range(len(bytearrays)):
        result.append(binaryToDecimal(bytearrays[i]))
    return bytes(result)


def left_shift_rot(inp, count=1):
    '''
    >>> left_shift_rot('010')
    '100'
    >>> left_shift_rot('111')
    '111'
    >>> left_shift_rot('1010111001')
    '0101110011'
    >>> left_shift_rot('0101110011')
    '1011100110'
    >>> left_shift_rot('1010111001',2)
    '1011100110'
    >>> left_shift_rot('0001',3)
    '1000'
    '''
    outputlist = []
    inputlist = []
    inputlist[:0] = inp  # string to array
    # adding the last element to the start
    for i in range(len(inputlist)):
        outputlist.append(inputlist[(i + count) % (len(inputlist))])

    str1 = ''.join(outputlist)  # convert to string
    return str1
def create_DES_subkeys(binary):
    '''
    >>> create_DES_subkeys('0001001100110100010101110111100110011011101111001101111111110001')
    ['000110110000001011101111111111000111000001110010', '011110011010111011011001110110111100100111100101', '010101011111110010001010010000101100111110011001', '011100101010110111010110110110110011010100011101', '011111001110110000000111111010110101001110101000', '011000111010010100111110010100000111101100101111', '111011001000010010110111111101100001100010111100', '111101111000101000111010110000010011101111111011', '111000001101101111101011111011011110011110000001', '101100011111001101000111101110100100011001001111', '001000010101111111010011110111101101001110000110', '011101010111000111110101100101000110011111101001', '100101111100010111010001111110101011101001000001', '010111110100001110110111111100101110011100111010', '101111111001000110001101001111010011111100001010', '110010110011110110001011000011100001011111110101']
    '''
    PC1 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
           63,
           55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4]
    key_shifts = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

    k=list(binary)

    kplus = ""
    for i in range(56):
        a=PC1[i] - 1
        kplus = kplus + k[a]

    c0=kplus[0:28]    #splitting
    d0=kplus[28:56]

    cdList=[]
    for i in range(16):          #creating c and d list
        newC=left_shift_rot(c0,key_shifts[i])
        newD = left_shift_rot(d0, key_shifts[i])
        cdList.append(newC+newD)
        c0 = newC
        d0 = newD

    kList=[]

    PC2 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47,
           55,
           30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]
    for i in range(16):
        k = list(cdList[i])
        ki = ""
        for i in range(48):
            a = PC2[i] - 1
            ki = ki + k[a]
        kList.append(ki)
    return kList

def f(r0,k1):
    """
    >>> f('11110000101010101111000010101010','000110110000001011101111111111000111000001110010')
    '00100011010010101010100110111011'
    >>> f('11110000100101110101011111101010','000101010101111010110101111000010110111010101011')
    '00101010011111001000010101011010'
    >>> f('11010110111010100001101010110100','010101101000000000000001010101000101010101010110')
    '00101101011001110010100110011110'
    >>> f('11110000100110101010101010001010','000101010101111010110101111000010110111010101011')
    '10011000011110011011000010011110'
    >>> f('11010110111010100001101001010100','111111111111111111111111111111111111111111111111')
    '11011000100000110100000000111100'
    """
    E = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20,
         21,
         22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]
    S = \
        [
            [
                [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
                [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
                [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
                [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
            ],
            [
                [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
                [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
                [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
                [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
            ],
            [
                [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
                [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
                [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
                [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
            ],
            [
                [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
                [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
                [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
                [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
            ],
            [
                [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
                [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
                [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
                [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
            ],
            [
                [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
                [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
                [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
                [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
            ],
            [
                [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
                [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
                [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
                [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
            ],
            [
                [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
                [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
                [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
                [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
            ]
        ]
    P = [
        16, 7, 20, 21, 29, 12, 28, 17,
        1, 15, 23, 26, 5, 18, 31, 10,
        2, 8, 24, 14, 32, 27, 3, 9,
        19, 13, 30, 6, 22, 11, 4, 25]


    r0=list(r0)
    ER0 = ""
    for i in range(48):
        a = E[i] - 1
        ER0 = ER0 + r0[a]

    k1xorEr0=bin_xor(k1,ER0)
    n=0
    output=""
    for i in range(0,len(k1xorEr0),6):
        Bn=k1xorEr0[i:i+6]
        row=findcolumnrow(Bn)[0]
        column = findcolumnrow(Bn)[1]
        SnBn=S[n][row][column]
        SnBnbinary=decimalToBinary(SnBn).rjust(4,"0")
        output=output+SnBnbinary
        n+=1

    output = list(output)

    f = ""
    for i in range(32):
        a = P[i] - 1
        f = f + output[a]

    return f

def findcolumnrow(b):
    rowbinary=""
    columnbinary=""
    rowbinary= rowbinary + b[0]+b[5]

    columnbinary = columnbinary+b[1]+b[2]+b[3]+b[4]
    row=(binaryToDecimal(rowbinary))
    column=(binaryToDecimal(columnbinary))
    return row,column
f("11110000101010101111000010101010","000110110000001011101111111111000111000001110010")



def encrypt_DES(bytes1,bytes2):
    """
    >>> encrypt_DES(b'\\x13\\x34\\x57\\x79\\x9b\\xbc\\xdf\\xf1', b'\\x01\\x23\\x45\\x67\\x89\\xab\\xcd\\xef')
    b'\\x85\\xe8\\x13T\\x0f\\n\\xb4\\x05'
    """
    # tables for encryption
    IP = [58, 50, 42, 34, 26, 18, 10, 2,
          60, 52, 44, 36, 28, 20, 12, 4,
          62, 54, 46, 38, 30, 22, 14, 6,
          64, 56, 48, 40, 32, 24, 16, 8,
          57, 49, 41, 33, 25, 17, 9, 1,
          59, 51, 43, 35, 27, 19, 11, 3,
          61, 53, 45, 37, 29, 21, 13, 5,
          63, 55, 47, 39, 31, 23, 15, 7]
    IP_inverse = [40, 8, 48, 16, 56, 24, 64, 32,
                  39, 7, 47, 15, 55, 23, 63, 31,
                  38, 6, 46, 14, 54, 22, 62, 30,
                  37, 5, 45, 13, 53, 21, 61, 29,
                  36, 4, 44, 12, 52, 20, 60, 28,
                  35, 3, 43, 11, 51, 19, 59, 27,
                  34, 2, 42, 10, 50, 18, 58, 26,
                  33, 1, 41, 9, 49, 17, 57, 25]
    K_ = bytes2binary(bytes1)
    K=K_.rjust(64,"0")          #there was a minor error caused by 0 bit at the start ex: b'\x00\x07\xe7PA\xa1\xc8\xe7'
    M_ = bytes2binary(bytes2)
    M = M_.rjust(64,"0")
    Kn=create_DES_subkeys(K)

    m = list(M)
    KIP = ""
    for i in range(64):         # M----->IP
        a = IP[i] - 1
        KIP = KIP + m[a]

    L0=KIP[0:32]
    R0=KIP[32:64]

    for i in range(16):         #16 iteration to find R16 and L16
        Ln=R0
        fresult=f(R0,Kn[i])
        Rn=bin_xor(L0,fresult)
        R0=Rn
        L0=Ln

    R16L16=R0+L0

    R16L16 = list(R16L16)
    IP_inverse_result = ""
    for i in range(64):
        a = IP_inverse[i] - 1
        IP_inverse_result = IP_inverse_result + R16L16[a]

    return binary2bytes(IP_inverse_result)

import os
from Crypto.Cipher import DES
def are_random_tests_all_passes(testCount):
    """
    >>> are_random_tests_all_passes(100)
    True
    """
    test_result=True
    for i in range(testCount):
            key = os.urandom(8)
            message = os.urandom(8)
            cipher = DES.new(key, DES.MODE_ECB)
            result=cipher.encrypt(message)
            manuel_result = encrypt_DES(key, message)
            if(manuel_result != result):
                test_result = False
                return test_result
    return test_result

print(are_random_tests_all_passes(1000))
