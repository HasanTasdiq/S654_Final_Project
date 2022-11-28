import rsa
from AES_cipher import generate_data
import time
import json



data = generate_data()



def RSA_encryption(txt , public_key):
    txt = json.dumps(txt)
    result = []
    for n in range(0,len(txt),245):
        part = txt[n:n+245]
        result.append( rsa.encrypt(part.encode("ascii"), public_key) )
    return b''.join(result)


def RSA_decryption(RSA_content , private_key):
    result = []
    for n in range(0,len(RSA_content),256):
        part = RSA_content[n:n+256]
        result.append( rsa.decrypt(part, private_key).decode("ascii") )
    result = json.loads(''.join(result))
    return result




def test_RSA():
    (publicKey, privateKey) = rsa.newkeys(2048)
    start_time = time.time()

    r = RSA_encryption( data , publicKey)
    RSA_decryption( r  , privateKey)

    end_time = time.time()
    print('time taken for RSA: ',  (end_time - start_time), ' sec')

test_RSA()