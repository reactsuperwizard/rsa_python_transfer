from base64 import b64decode
from Crypto import Random
from Crypto.Cipher import PKCS1_v1_5 as Cipher_PKCS1_v1_5
from Crypto.PublicKey import RSA
from collections import OrderedDict

import ast
import base64
import binascii
import logging
import os
import sys
import zlib
import json

logging.basicConfig(level=logging.DEBUG)
STR_SPLIT_LEN = 64

class RSAWrapper:

	def write_keys_to_file(self, out_path, value):      
		with open(out_path, 'wb') as fwrite:
		   fwrite.write(value)
		   fwrite.close()

	def read_key_from_file(self, filepath):
		result = None
		try:
			with open(filepath, 'rb') as fread:
			   result = fread.read()
			   fread.close()
		except Exception as e:
			result = None
		return result

	def generate_RSA(self, bits=2048):
		random_generator = Random.new().read
		new_key = RSA.generate(bits, random_generator) 
		public_key = new_key.publickey().exportKey("PEM") 
		private_key = new_key.exportKey("PEM") 
		return private_key, public_key
	
	def generateRSAKey(self):
		try:
			if not os.path.exists('./m2you/zhenqiang/privateKey'):
				os.makedirs('./m2you/zhenqiang/privateKey')
			if not os.path.exists('./m2you/zhenqiang/pubKey'):
				os.makedirs('./m2you/zhenqiang/pubKey')
			if not os.path.exists('./m2you/roland-frei/privateKey'):
				os.makedirs('./m2you/roland-frei/privateKey')
			if not os.path.exists('./m2you/roland-frei/pubKey'):
				os.makedirs('./m2you/roland-frei/pubKey')
		except Exception as ex:
			ex = None;

		priv, pub = self.generate_RSA()     
		print('priv : ', priv); 
		print('pub : ', pub); 
		
		out_path = './m2you/roland-frei/privateKey/roland-frei.data'        
		self.write_keys_to_file(out_path, priv) 
		
		out_path = './m2you/zhenqiang/pubKey/roland-frei.data'
		self.write_keys_to_file(out_path, pub)

		priv, pub = self.generate_RSA()     
		print('priv : ', priv)
		print('pub : ', pub)

		out_path = './m2you/roland-frei/pubKey/zhenqiang.data'
		self.write_keys_to_file(out_path, priv) 
	 
		out_path = './m2you/zhenqiang/privateKey/zhenqiang.data'
		self.write_keys_to_file(out_path, priv) 
	
	def encryptJTS(self, toEncrypt, relativeOrAbsolutePathToPublicKey):
		try:
			pub_key = self.read_key_from_file(relativeOrAbsolutePathToPublicKey)            
			public_key = RSA.importKey(pub_key)         
			i = 0
			len_enc = len(toEncrypt)
			cipher_text = bytearray()
			while(i < len_enc):
				start_pos = i
				end_pos = min(i + STR_SPLIT_LEN, len_enc)
				sub_str = toEncrypt[start_pos:end_pos]
				cipher_text.extend(public_key.encrypt(sub_str.encode(), STR_SPLIT_LEN)[0])                
				i += STR_SPLIT_LEN
			return cipher_text
		except Exception as e:
			logging.exception(e)            
		return None

	def decryptJTS(self, toDecrypt, relativeOrAbsolutePathtoPrivateKey):
		try:        
			private_key = self.read_key_from_file(relativeOrAbsolutePathtoPrivateKey) 
			private_key_object = RSA.importKey(private_key)
			i = 0
			len_enc = len(toDecrypt)
			result = bytearray()
			STEP = 256
			while(i < len_enc):
				start_pos = i
				end_pos = min(i + STEP, len_enc)
				array = (bytes(toDecrypt[start_pos:end_pos]))
				decrypted_message = private_key_object.decrypt(array)
				result.extend(decrypted_message)
				i += STEP           
			return bytes(result).decode()
		except Exception as e:
			logging.exception(e)            
		return None

	def getCRCCode(self, str_data):
		# print('okkk' + str_data)
		return zlib.crc32(bytearray(str_data, 'utf8'))

	def checkMetaData(self,  metaData):
		clientCRC = metaData['metaCRC']
		metaData['metaCRC'] = ''
		# print(metaData)
		checkSum = self.getCRCCode(json.dumps(metaData, sort_keys=True))

		print("crc compare : ", str(clientCRC) + " : " + str(checkSum))
		if checkSum != int(clientCRC):
			print("Failed in CRC check!")
			return False
		return True

	def int_of_string(self, s):
		return int(binascii.hexlify(s), 16)

	def make_key(self, origin_key):
		return bytes("{: <32}".format(origin_key), 'utf8')

	# Print iterations progress
	def printProgressBar (self, iteration, total, prefix = '', suffix = '', decimals = 1, length = 100, fill = '█'):		
		percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
		filledLength = int(length * iteration // total)
		bar = fill * filledLength + '-' * (length - filledLength)
		print('\r%s |%s| %s%% %s' % (prefix, bar, percent, suffix), end = '\r')
		# Print New Line on Completels
		if iteration == total: 
			print()

def checkFileExist(filePath):	
	if os.path.isfile(filePath) == None:
		print("Can't find", filePath)		
		return None
	return filePath

def makeDirPath(filePath):
	if os.path.isdir(filePath):
		return 
	print(filePath)
	try :
		os.makedirs(filePath)
	except Exception as e :		
		sys.exit()

class RSAFtpHeader:
	meta_len = 0
	from_user = 0
	to_user	 = 0