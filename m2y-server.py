from Crypto.Cipher import AES
from Crypto.Util import Counter
from asyncio import Task, coroutine, get_event_loop
from components import m2yutils 
from components.m2yutils import RSAFtpHeader 
from components.m2yutils import RSAWrapper 
from enum import Enum
from socket import socket, SO_REUSEADDR, SOL_SOCKET


import configparser
import asyncio
import datetime
import json
import logging
import os
import struct
import sys
import traceback
import zlib

################ Initialize Application ##############
def init_app():
	try:
		global RsaFtpVar, SCRIPT_PATH	
		global SERVER_URL, SERVER_PORT, CRC_CHECK_LEN, IV_LEN, BLOCK_SIZE, FILE_KEY, LOG_PATH, M2Y_USERPATH 
		global PRIVATE_DIRNAME, PUBLIC_DIRNAME, CONFIG_FILENAME, KEYFILE_EXT, METAFILE_EXT
		global LogFileOutstream, RsaWrapperObj

		RsaFtpVar = FileTransferProtocal()	
		config = m2yutils.read_configFile('./m2y.ini')

		SERVER_URL = config.get('SERVER','SERVER_URL')
		SERVER_PORT = config.get('SERVER','SERVER_PORT')
		CRC_CHECK_LEN = int(config.get('TRANSFER','CRC_CHECK_LEN'))
		IV_LEN = int(config.get('TRANSFER','IV_LEN'))
		BLOCK_SIZE = int(config.get('TRANSFER','BLOCK_SIZE'))
		LOG_PATH = config.get('LOGFILE','PATH')
		SCRIPT_PATH = config.get('PATHS','SCRIPT')
		M2Y_USERPATH = config.get('PATHS','M2YUSERPATH') + os.sep
		PRIVATE_DIRNAME = config.get('PATHS','PRIVATEDIRNAME')
		PUBLIC_DIRNAME = config.get('PATHS','PUBLICDIRNAME')
		CONFIG_FILENAME = config.get('PATHS','CONFIGFILENAME')
		KEYFILE_EXT = config.get('PATHS','KEYFILEEXT')
		METAFILE_EXT = config.get('PATHS','METAFILEEXT')
		
		
		FILE_KEY='random1234'
		LogFileOutstream = open(LOG_PATH, "a")		
		RsaWrapperObj = RSAWrapper()
		logging.basicConfig(level=logging.DEBUG)
	except Exception as ex:	
		print(ex)


###############################
def writeLog(logStr):
	LogFileOutstream.write(logStr)

class Server_status(Enum):

	HEADER_STATUS = 0
	META_STATUS = 1
	FILETRANS_STATUS = 2
	LASTFILE_STATUS = 3

class FileTransferProtocal:
	token_index = 0
	CURRENT_FILE_KEY = None
	BUF_SIZE = 0    
	FILE_SIZE = 0
	FILE_RECIEP_SIZE = 0
	FILE_NAME = ''
	SERVER_STATUS = Server_status.HEADER_STATUS
	write_file_open = None
	rsa_header = RSAFtpHeader()
	config = None
	cur_fromuser = None
	cur_touser = None

	###############################
	def init(self):
		self.SERVER_STATUS = Server_status.HEADER_STATUS
		self.token_index = 0
		self.BUF_SIZE = 0
		self.FILE_RECIEP_SIZE = 0
		self.token_index = 0
		self.FILE_NAME = ""     
		self.CURRENT_FILE_KEY = RsaWrapperObj.make_key(FILE_KEY)
		self.FILE_CRC = 0
		self.rsa_header = RSAFtpHeader()
		self.config = None
		# print(self.CURRENT_FILE_KEY)

	#########################################
	def execute_script(self, script_path, localsParameter = None):
		run_script = SCRIPT_PATH + script_path				
		with open(run_script, "r") as script_file:
			if localsParameter:				
				file_content = script_file.read()
				script_file.close()				
				exec(file_content, globals(), localsParameter)					
			else :
				exec(script_file.read())
			script_file.close()
		return True
		

	# ###################################
	def check_meta_in_conf(self, config, meta_name):
		if meta_name in config:
			return True
		return False

	###################################
	def decrypt_with_aes(self, key, ciphertext):
		iv = ciphertext[:16]            
		aes = AES.new(key, AES.MODE_CFB, iv)
		plaintext = aes.decrypt(ciphertext[16:])
		self.FILE_CRC ^= zlib.crc32(plaintext)
		return plaintext

	##############################
	def write_file(self, real_data):
		try :   
			# print(real_data)      
			with open(self.FILE_NAME, "ab") as write_file_open:           
				write_file_open.write(real_data)
				write_file_open.close()
			return len(real_data)
		except Exception as e:
			print("Can't write file");
		return 0
	
	###################################
	def check_crc_file_part(self, data, crc_token):
		return int(data) == int(crc_token)

	################# Keep track of the chat clients
	def receiveFromClient(self, data):
		data_len = len(data)
		if data_len == BLOCK_SIZE or (self.FILE_SIZE - self.FILE_RECIEP_SIZE + IV_LEN == data_len):         
			last_flag = (self.FILE_SIZE - self.FILE_RECIEP_SIZE + IV_LEN == data_len)
			real_data = self.decrypt_with_aes(self.CURRENT_FILE_KEY, data)                      
			self.FILE_RECIEP_SIZE += len(real_data)
			self.write_file(real_data)			
			RsaWrapperObj.printProgressBar(self.FILE_RECIEP_SIZE, self.FILE_SIZE, prefix = 'Progress:', suffix = (str(data_len) + ' bytes Received'), length = 50)
			if last_flag:				
				self.SERVER_STATUS = Server_status.LASTFILE_STATUS
			return True
		else : 
			return False

	######### step 1
	def header_data_process(self, data):				
		read_data = struct.unpack('l', data[:8])
		self.rsa_header = RSAFtpHeader()
		self.rsa_header.meta_len = read_data[0]
		self.rsa_header.from_user = data[8:40].hex()
		self.rsa_header.to_user = data[40:].hex()
		print(str(self.rsa_header.meta_len) + ":" + str(self.rsa_header.from_user) + ":" + str(self.rsa_header.to_user))
		self.SERVER_STATUS = Server_status.META_STATUS		
		return b'accepted'

	########## step 2
	def meta_data_process(self, data):    		
		dec_txt = RsaWrapperObj.decryptJTS(data, M2Y_USERPATH + 'Roland-frei' + os.sep + PRIVATE_DIRNAME + os.sep +  'roland-frei' + KEYFILE_EXT)
		jsonDec = json.loads(dec_txt)
		RsaWrapperObj.printProgressBar(0, 10000, prefix = 'Progress:', suffix = 'received from client', length = 50)
		# checking length header
		len_json = len(json.dumps(jsonDec))
		if int(self.rsa_header.meta_len) != len_json :
			print("\n Check meta data length is different!" + str(self.rsa_header.meta_len) + ":" + str(len_json))
			return 'failed'
		if not RsaWrapperObj.checkMetaData(jsonDec):
			print("\n Check meta data failed!")
			return 'failed'
		jsonDec['meta_len'] = len_json
		self.FILE_SIZE = jsonDec['filesize']    

		file_save_dir = M2Y_USERPATH + jsonDec['to'] + os.sep + jsonDec['folder']
		m2yutils.makeDirPath(file_save_dir)
		self.FILE_NAME = file_save_dir + os.sep + jsonDec['filename']             
		jsonDec['filekey'] = FILE_KEY
		pub_key_path = M2Y_USERPATH + jsonDec['to'] + os.sep + PUBLIC_DIRNAME + os.sep + jsonDec['from'] + KEYFILE_EXT
		print(pub_key_path)		

		meta_dirpath = file_save_dir + os.sep;		
		m2yutils.makeDirPath(meta_dirpath)
		meta_filepath = meta_dirpath + jsonDec['from'] + "-" + datetime.datetime.now().strftime("%Y%m%d%H%M%S") + METAFILE_EXT

		with open(meta_filepath, 'w') as meta_file_open:
			meta_file_open.write(json.dumps(jsonDec))
			meta_file_open.close()
		write_file_open = open(self.FILE_NAME, "wb")
		write_file_open.close()		
		
		self.config = m2yutils.read_configFile(file_save_dir + os.sep + CONFIG_FILENAME)
		if self.check_meta_in_conf(self.config, 'OnMeta'):
			data_param = {'meta_dirpath': file_save_dir, 'meta_filepath': meta_filepath, 'result' :'False'}			
			script_filename = next(iter(self.config['OnMeta']))
			print(script_filename)
			self.execute_script(script_filename, data_param)						
			global executeScript_result
			print(executeScript_result)
			if not executeScript_result:
				jsonDec["error"] = "no permission"			
		else :
			jsonDec["error"] = 'failed'
		jsonDec['metaCRC'] = str(RsaWrapperObj.getCRCCode(json.dumps(jsonDec, sort_keys=True)))				
		enc = RsaWrapperObj.encryptJTS(json.dumps(jsonDec), pub_key_path)				
		RsaWrapperObj.printProgressBar(0, 10000, prefix = 'Progress:', suffix = 'send meta data to client', length = 50)		
		self.SERVER_STATUS = Server_status.FILETRANS_STATUS
		return enc
	
	def filetransfer_process(self, data):       
		if self.receiveFromClient(data):
			self.token_index += 1
			return b'accepted'
		else :
			return b'resend'
		
	def main_data_process(self, data):
		if self.SERVER_STATUS == Server_status.HEADER_STATUS:			
			return self.header_data_process(data)
		elif self.SERVER_STATUS == Server_status.META_STATUS:			
			return self.meta_data_process(data)					
		elif self.SERVER_STATUS == Server_status.FILETRANS_STATUS:
			return self.filetransfer_process(data)
		elif self.SERVER_STATUS == Server_status.LASTFILE_STATUS:
			if not self.check_crc_file_part(data, self.FILE_CRC):
				return b"failed"
			else :    			
				if self.check_meta_in_conf(self.config, 'OnReceived'):
					script_filename = next(iter(self.config['OnReceived']))
					self.execute_script(script_filename)
				return b"success"
		return None

	async def file_trans_protocal(self, reader, writer):    
		self.init()
		try :
			while True:
				data = await reader.read(BLOCK_SIZE)					
				if data == None or len(data) < CRC_CHECK_LEN:
					break
				result = self.main_data_process(data)				
				writer.write(result)
				writer.drain()
				if(result == b"failed" or result == b"success"):
					self.init()
					break
			print('------------client --------')			
		except Exception as e:
			print('------------Exception occure --------')						
			traceback.print_exc()
		finally:
			writer.close()
			self.init()

loop = asyncio.get_event_loop()
init_app()
coro = asyncio.start_server(RsaFtpVar.file_trans_protocal, SERVER_URL, SERVER_PORT, loop=loop)
server = loop.run_until_complete(coro)

print('Serving on {}'.format(server.sockets[0].getsockname()))
try:
	loop.run_forever()
except KeyboardInterrupt:
	pass

# Close the server
server.close()
loop.run_until_complete(server.wait_closed())
loop.close()
