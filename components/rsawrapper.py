import zlib
import os
import sys
from Crypto.PublicKey import RSA
from Crypto import Random
import ast
from base64 import b64decode

path = require('path')
fs = require('fs')
NodeRSA = require('node-rsa')
crypto = require('crypto')
mkdirp = require('mkdirp')
crc = require('crc')
crc = require('node-crc')

class RSAWrapper:

	def write_keys_to_file(out_path, value):		
		with open(out_path, 'w') as fwrite:
		   fwrite.write(value)
		   fwrite.close()

	def generate_RSA(bits=512):
		# random_generator = Random.new().read
		random_generator = 32
		new_key = RSA.generate(bits, random_generator) 
		public_key = new_key.publickey().exportKey("pkcs1-public") 
		private_key = new_key.exportKey("pkcs1-private") 
		return private_key, public_key

	def generateRSAKey():
		os.makedirs('./m2you/zhenqiang/privateKey')
		os.makedirs('./m2you/zhenqiang/pubKey')
		os.makedirs('./m2you/roland-frei/privateKey')
		os.makedirs('./m2you/roland-frei/pubKey')

		priv, pub = generate_RSA(512)		
		print('priv : ', priv); 
		print('pub : ', pub); 
		
		out_path = './m2you/roland-frei/privateKey/roland-frei.data'		
		write_keys_to_file(out_path, priv)	
		
		out_path = './m2you/zhenqiang/pubKey/roland-frei.data'
		write_keys_to_file(out_path, pub)

	 	# key = NodeRSA({b: 512})
		priv, pub = generate_RSA(512)		
		print('priv : ', priv); 
		print('pub : ', pub); 

		key.generateKeyPair(512)
		out_path = './m2you/zhenqiang/privateKey/zhenqiang.data'
		write_keys_to_file(out_path, priv)	
	 
		out_path = './m2you/zhenqiang/pubKey/eric-brian.data'
		write_keys_to_file(out_path, priv)	

	def encryptJTS(toEncrypt, relativeOrAbsolutePathToPublicKey):
		absolutePath = relativeOrAbsolutePathToPublicKey
		# absolutePath = path.resolve(relativeOrAbsolutePathToPublicKey)
		try:
			with open(absolutePath, 'r') as fin:
				publickey = RSA.importKey(fin, 'pkcs1-public')
				return publickey.encrypt(toEncrypt)
		except Exception:
			publickey = None
		return publickey

	def decryptJTS(toDecrypt, relativeOrAbsolutePathtoPrivateKey):
		absolutePath = relativeOrAbsolutePathtoPrivateKey
		try:
			with open(absolutePath, 'r') as fin:
				privatekey = RSA.importKey(fin, 'pkcs1-public')
			return privatekey.decrypt(toDecrypt, 'utf8')
		except Exception:
			privatekey = None
		return privatekey

	def checkMetaData(metaData):
		clientCRC = metaData['metaCRC']
		metaData['metaCRC = ""']
		checkSum = zlib.crc32(json.dump(metaData))
		print("crc compare : ", clientCRC + " : " + checkSum)
		if checkSum != clientCRC:
			print("Failed in CRC check!")
			return None
		return metaData['filekey']
