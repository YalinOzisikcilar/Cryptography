from Crypto.Cipher import AES


def xor_byte_arrays(array1, array2):
    '''
    >>> xor_byte_arrays(bytes([1,2,3,4]),bytes([2,3,4,5]))
    b'\\x03\\x01\\x07\\x01'
    >>> xor_byte_arrays(bytes([1,2,3,4]),bytes([]))
    b'\\x01\\x02\\x03\\x04'
    >>> xor_byte_arrays(bytes([1,2,3,4]),bytes([1,2]))
    b'\\x01\\x02\\x02\\x06'
    >>> xor_byte_arrays(bytes([1,2,4,8,16,32,64,128]),bytes([1,1,1,1,1,1,1,1]))
    b'\\x00\\x03\\x05\\t\\x11!A\\x81'
    '''

    result = bytearray([])  # bytes are immutable but we can append to bytearray
    dif = len(array1) - len(array2)
    for i in range(dif):
        result.append(array1[i])
    for i in range(len(array2)):
        result.append(array1[i + dif] ^ array2[i % len(array2)])

    return bytes(result)
def decrypt_aes_ecb(input_bytearray,key):
    '''
    >>> key = bytes([57, 226, 240, 61, 125, 240, 75, 68, 22, 35, 124, 205, 144, 27, 118, 220])
    >>> decrypt_aes_ecb(bytes([215, 221, 59, 138, 96, 94, 155, 69, 52, 90, 212, 108, 49, 65, 138, 179]), key)
    b'lovecryptography'
    >>> decrypt_aes_ecb(bytes([147, 140, 44, 177, 97, 209, 42, 239, 152, 124, 241, 175, 202, 164, 183, 18]), key)
    b'!!really  love!!'
    '''
    aes2 = AES.new(key, AES.MODE_ECB)
    origi = aes2.decrypt(input_bytearray)
    return origi


def decrypt_aes_cbc_with_ecb(input_bytearray,key,iv):
    """
    >>> key = bytes([57, 226, 240, 61, 125, 240, 75, 68, 22, 35, 124, 205, 144, 27, 118, 220])
    >>> iv = bytes([241, 147, 66, 129, 194, 34, 37, 51, 236, 69, 188, 205, 64, 140, 244, 204])
    >>> encrypt_aes_cbc_with_ecb(b'hello world 1234', key, iv)
    >>> decrypt_aes_cbc_with_ecb(bytes([171, 218, 160, 96, 193, 134, 73, 81, 221, 149, 19, 180, 31, 247, 106, 64]),key,iv)
    b'lovecryptography
    """
    aes2 = AES.new(key, AES.MODE_ECB)
    origi = aes2.decrypt(input_bytearray)
    return xor_byte_arrays(origi,iv)

def encrypt_aes_cbc_with_ecb(input_bytearray,key,iv):
    """
    >>> key = bytes([57, 226, 240, 61, 125, 240, 75, 68, 22, 35, 124, 205, 144, 27, 118, 220])
    >>> iv = bytes([241, 147, 66, 129, 194, 34, 37, 51, 236, 69, 188, 205, 64, 140, 244, 204])
    >>> encrypt_aes_cbc_with_ecb(b'hello world 1234',key,iv)
    b'\\xff\\x12Cs\\xacu\\xf2\\xe9\\xf6EQ\\x9c4\\x9a{\\xab'
    >>> encrypt_aes_cbc_with_ecb(bytes(b'lovecryptography'),key,iv)
    b'\\xab\\xda\\xa0`\\xc1\\x86IQ\\xdd\\x95\\x13\\xb4\\x1f\\xf7j@'
    """
    input=xor_byte_arrays(input_bytearray,iv)
    aes2 = AES.new(key, AES.MODE_ECB)
    ciphertext = aes2.encrypt(input)
    return ciphertext

key = bytes([57, 226, 240, 61, 125, 240, 75, 68, 22, 35, 124, 205, 144, 27, 118, 220])
iv = bytes([241, 147, 66, 129, 194, 34, 37, 51, 236, 69, 188, 205, 64, 140, 244, 204])
print(encrypt_aes_cbc_with_ecb(b'hello world 1234',key,iv))
print(encrypt_aes_cbc_with_ecb(bytes(b'lovecryptography'),key,iv))