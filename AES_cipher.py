from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import time
import json
from base64 import b64encode
from base64 import b64decode
from difflib import SequenceMatcher


from Crypto.Util.Padding import pad, unpad

propagate_error = True
block_num = 4
def generate_data():
    i=0
    data=""
    while i<block_num:
        data += "secretsecretsecr"
        i +=1
    return data
def generate_error(cipher_text):
    if not propagate_error:
        return cipher_text
    barray = bytearray(cipher_text)
    for i in range(16):
        barray[i] = (barray[i] + 1) % 255
    cipher_text = bytes(barray)
    return cipher_text
def check_error_propagation(text1 , text2 , mode):
    error = 0
    for i in range(len(text1)):
        if text1[i] != text2[i]:
            error += 1
    error_ratio =  error/len(text1) * 100

    print('error for' , mode , error_ratio , '%')
    


data = generate_data().encode('ASCII')


def AES_CBC():
    start_time = time.time()
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    ct_bytes = generate_error(ct_bytes)
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    result = json.dumps({'iv':iv, 'ciphertext':ct})

    try:
        b64 = json.loads(result)
        iv = b64decode(b64['iv'])
        ct = b64decode(b64['ciphertext'])
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        check_error_propagation(data , pt , 'AES.MODE_CBC')
    except (ValueError, KeyError):
        print("Incorrect decryption")
    # print(result)
    end_time = time.time()
    print('time taken for CBC ', (end_time - start_time), ' sec')
def AES_ECB():
    mode = AES.MODE_ECB 
    start_time = time.time()
    key = get_random_bytes(16)
    cipher = AES.new(key, mode)
    ciphertext = cipher.encrypt(data)
    ciphertext= generate_error(ciphertext)
    # nonce = cipher.nonce


    cipher = AES.new(key, mode)
    decipher_data = cipher.decrypt(ciphertext)
    check_error_propagation(data , decipher_data , 'AES.MODE_ECB')

    # print("data: ", decipher_data)

    end_time = time.time()

    print('time taken for ECB:' ,  (end_time - start_time), ' sec')
def AES_CFB():
    start_time = time.time()

    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CFB)
    ct_bytes = cipher.encrypt(data)
    ct_bytes= generate_error(ct_bytes)

    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    result = json.dumps({'iv':iv, 'ciphertext':ct})


    try:
        b64 = json.loads(result)
        iv = b64decode(b64['iv'])
        ct = b64decode(b64['ciphertext'])
        cipher = AES.new(key, AES.MODE_CFB, iv=iv)
        pt = cipher.decrypt(ct)
        check_error_propagation(data , pt , 'AES.MODE_CFB')

    except (ValueError, KeyError):
        print("Incorrect decryption")
    
    end_time = time.time()
    print('time taken for CFB:' ,  (end_time - start_time), ' sec')

def AES_OFB():
    start_time = time.time()

    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_OFB)
    ct_bytes = cipher.encrypt(data)
    ct_bytes = generate_error(ct_bytes)
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    result = json.dumps({'iv':iv, 'ciphertext':ct})

    try:
        b64 = json.loads(result)
        iv = b64decode(b64['iv'])
        ct = b64decode(b64['ciphertext'])
        cipher = AES.new(key, AES.MODE_OFB, iv=iv)
        pt = cipher.decrypt(ct)
        check_error_propagation(data , pt , 'AES.MODE_OFB')

    except (ValueError, KeyError):
        print("Incorrect decryption")

    end_time = time.time()
    print('time taken for OFB:' ,  (end_time - start_time), ' sec')
def AES_CTR():
    start_time = time.time()

    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CTR)
    ct_bytes = cipher.encrypt(data)
    ct_bytes = generate_error(ct_bytes)
    nonce = b64encode(cipher.nonce).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    result = json.dumps({'nonce':nonce, 'ciphertext':ct})

    try:
        b64 = json.loads(result)
        nonce = b64decode(b64['nonce'])
        ct = b64decode(b64['ciphertext'])
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
        pt = cipher.decrypt(ct)
        check_error_propagation(data , pt , 'AES.MODE_CTR')

    except (ValueError, KeyError):
        print("Incorrect decryption")
    end_time = time.time()
    print('time taken for CTR:' ,  (end_time - start_time), ' sec')

AES_ECB()
AES_CBC()
AES_CFB()
AES_OFB()
AES_CTR()
