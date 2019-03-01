from base64 import b64decode
from Crypto import Random
from Crypto.Cipher import PKCS1_v1_5 as Cipher_PKCS1_v1_5
from Crypto.PublicKey import RSA
from collections import OrderedDict

import hashlib
import ast
import base64
import binascii
import logging
import os
import sys
import zlib
import json
import configparser

logging.basicConfig(level=logging.DEBUG)
STR_SPLIT_LEN = 128

############### Functions Block #################
### Config Read File
def read_configFile(conf_path):
	config = configparser.ConfigParser(allow_no_value=True)
	config.optionxform=str
	config.read(conf_path)	
	return config

### Check Path
def checkFileExist(filePath):	
	if os.path.isfile(filePath):
		return filePath
	print("Can't exists", filePath)		
	return None

### printStep
def printStep(stepnumber):
	print('\n##########  step ' + str(stepnumber) + ' #############')
	pass

### Make file Directory Path
def makeDirPath(filePath):
	if os.path.isdir(filePath):
		return 
	print(filePath)
	try :
		os.makedirs(filePath)
	except Exception as e :		
		sys.exit()

### encrypt SHA256 
def getEncrypt(toEncypt):
	if type(toEncypt) == str:
		toEncypt = bytes(toEncypt, 'utf8')
	sha256 = hashlib.sha256()
	sha256.update(toEncypt)                
	return sha256.digest()

	
################# Object Block
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
	
	def generateRSAKey(self, user_name):
		try:
			config = read_configFile('./m2y.ini')
			LOG_PATH = config.get('LOGFILE','PATH')
			SCRIPT_PATH = config.get('PATHS','SCRIPT')
			M2Y_USERPATH = config.get('PATHS','M2YUSERPATH') + os.sep
			PRIVATE_DIRNAME = config.get('PATHS','PRIVATEDIRNAME')
			PUBLIC_DIRNAME = config.get('PATHS','PUBLICDIRNAME')
			CONFIG_FILENAME = config.get('PATHS','CONFIGFILENAME')
			KEYFILE_EXT = config.get('PATHS','KEYFILEEXT')

			privKey, pubKey = self.generate_RSA()				

			prv_dirpath = M2Y_USERPATH + user_name + os.sep + PRIVATE_DIRNAME
			if not checkFileExist(prv_dirpath):
				os.makedirs(prv_dirpath)			
			out_path = prv_dirpath + os.sep + user_name + KEYFILE_EXT
			self.write_keys_to_file(out_path, privKey)

			pub_dirpath = M2Y_USERPATH + user_name + os.sep + PUBLIC_DIRNAME
			if not checkFileExist(pub_dirpath):
				os.makedirs(pub_dirpath)
			out_path = pub_dirpath + os.sep + user_name + KEYFILE_EXT
		except Exception as ex:
			print(ex)
		out_path = M2Y_USERPATH + user_name + os.sep + PRIVATE_DIRNAME + os.sep + user_name + KEYFILE_EXT
		self.write_keys_to_file(out_path, privKey) 
	
	def encryptJTS(self, toEncrypt, relativeOrAbsolutePathToPublicKey):
		try:			
			pub_key = self.read_key_from_file(relativeOrAbsolutePathToPublicKey)
			public_key = RSA.importKey(pub_key)
			len_enc = len(toEncrypt)
			cipher_text = bytearray()
			for start_pos in range(0, len_enc, STR_SPLIT_LEN):
				end_pos = min(start_pos + STR_SPLIT_LEN, len_enc)
				sub_str = toEncrypt[start_pos:end_pos]
				cipher_text.extend(public_key.encrypt(sub_str.encode(), STR_SPLIT_LEN)[0])                
				start_pos += STR_SPLIT_LEN
			return cipher_text
		except Exception as e:
			logging.exception(e)            
		return None

	def decryptJTS(self, toDecrypt, relativeOrAbsolutePathtoPrivateKey):
		try:			
			private_key = self.read_key_from_file(relativeOrAbsolutePathtoPrivateKey) 		
			private_key_object = RSA.importKey(private_key)
			len_enc = len(toDecrypt)
			result = bytearray()
			STEP = 256
			for start_pos in range(0, len_enc, STEP):				
				end_pos = min(start_pos + STEP, len_enc)
				array = (bytes(toDecrypt[start_pos:end_pos]))
				decrypted_message = private_key_object.decrypt(array)
				result.extend(decrypted_message)							
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

class RSAFtpHeader:
	meta_len = 0
	from_user = 0
	to_user	 = 0


