from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import time

data = b'secret datasecret datasecret datasecret datasecret datasecret datasecret datasecret datasecret datasecret data'


def AES_with_mode(mode):
    start_time = time.time()
    key = get_random_bytes(16)
    cipher = AES.new(key, mode)
    ciphertext = cipher.encrypt(data)
    nonce = cipher.nonce


    cipher = AES.new(key, mode, nonce)
    decipher_data = cipher.decrypt(ciphertext)

    print("data: ", decipher_data)

    end_time = time.time()

    print('time taken for ' , mode , ':', (end_time - start_time), ' sec')

def AES_ECB():
    AES_with_mode(AES.MODE_ECB)
def AES_CBC():
    AES_with_mode(AES.MODE_CBC)
def AES_CFB():
    AES_with_mode(AES.MODE_CFB)
def AES_OFB():
    AES_with_mode(AES.MODE_OFB)
def AES_CTR():
    AES_with_mode(AES.MODE_CTR)

AES_ECB()
AES_CBC()
AES_CFB()
AES_OFB()
AES_CTR()


# not working. will have to check for every every mode
