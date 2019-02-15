import zlib
import os
import sys
from Crypto.PublicKey import RSA
from Crypto import Random
import ast
from base64 import b64decode
import logging
import binascii
from Crypto.PublicKey.RSA import generate, importKey
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_PKCS1_v1_5

from rsawrapper import RSAWrapper 


logging.basicConfig(level=logging.DEBUG)

def test_rsa_key(pub_key, priv_key):
	private_key = RSA.importKey(priv_key) # import the private key
	public_key = RSA.importKey(pub_key) # import the public key
	message_text = 'test_message'
	cipher = Cipher_PKCS1_v1_5.new(public_key)
	cipher_text = cipher.encrypt(message_text.encode()) # now we have the cipher	
	cipher = Cipher_PKCS1_v1_5.new(private_key)
	decrypt_text = cipher.decrypt(cipher_text, None).decode()
	
	print("raw message_text->", message_text)
	print("decrypted message_text->", decrypt_text)
	assert message_text == decrypt_text # check that
	print("test passed")


def read_key(filepath):
	result = None
	with open(out_path, 'rb') as fread:
	   result = fread.read()
	   fread.close()
	return result


rsa = RSAWrapper()
prv_key, pub_key = rsa.generate_RSA()
rsa.generateRSAKey();

out_path = './m2you/zhenqiang/pubKey/roland-frei.data'
pub_key = read_key(out_path) 
out_path = './m2you/roland-frei/privateKey/roland-frei.data'		
prv_key = read_key(out_path)
test_rsa_key(pub_key, prv_key)

out_path = './m2you/roland-frei/pubKey/zhenqiang.data'
pub_key = read_key(out_path) 
out_path = './m2you/zhenqiang/privateKey/zhenqiang.data'		
prv_key = read_key(out_path)

test_rsa_key(pub_key, prv_key)


message_text = 'test_messagetest_messagetest_messagetest_messagetest_messagetest_messagetest_messagetest_messagetest_messagetest_messagetest_messagetest_messagetestaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaa aaaaa atest_messagetest_messagetest_messagetest_messagetest_messagetest_messagetest_messagetest_messagetest_messagetest_messagetest_messagetest_messagetestaaaaaaaaaaaaaaaaaaaaaaaaaatest_messagetest_messagetest_messagetest_messagetest_messagetest_messagetest_messagetest_messagetest_messagetest_messagetest_messagetest_messagetestaaaaaaaaaaaaaaaaaaaaaaaaaatest_messagetest_messagetest_messagetest_messagetest_messagetest_messagetest_messagetest_messagetest_messagetest_messagetest_messagetest_messagetestaaaaaaaaaaaaaaaaaaaaaaaaaatest_messagetest_messagetest_messagetest_messagetest_messagetest_messagetest_messagetest_messagetest_messagetest_messagetest_messagetest_messagetestaaaaaaaaaaaaaaaaaaaaaaaaaa'

pub_path = './m2you/zhenqiang/pubKey/roland-frei.data'
encrypt_text = rsa.encryptJTS(message_text, pub_path)
print('len = ', len(encrypt_text))
priv_path = './m2you/roland-frei/privateKey/roland-frei.data'		
decrypt_text = rsa.decryptJTS(encrypt_text, priv_path)

print(len(message_text))
print(len(decrypt_text))
assert message_text == decrypt_text # check that
print("test passed")

