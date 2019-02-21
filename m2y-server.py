import struct
from asyncio import Task, coroutine, get_event_loop
from components.rsawrapper import RSAWrapper 
from components import rsawrapper 
from Crypto.Cipher import AES
from Crypto.Util import Counter
from enum import Enum
from socket import socket, SO_REUSEADDR, SOL_SOCKET
import asyncio
import json
import logging
import zlib
import traceback
from components.rsawrapper import RSAFtpHeader 
import datetime


SERVER_URL='127.0.0.1'
SERVER_PORT = 5000
CRC_CHECK_LEN = 4
IV_LEN = 16
BLOCK_SIZE = 4096 + IV_LEN

logfile = open("./log/server.log", "a")
rsa_wrapper = RSAWrapper()
logging.basicConfig(level=logging.DEBUG)
FILE_KEY = 'random1234'

def writeLog(logStr):
	logfile.write(logStr)

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

	def init(self):
		self.SERVER_STATUS = Server_status.HEADER_STATUS
		self.token_index = 0
		self.BUF_SIZE = 0
		self.FILE_RECIEP_SIZE = 0
		self.token_index = 0
		self.FILE_NAME = ""     
		self.CURRENT_FILE_KEY = rsa_wrapper.make_key(FILE_KEY)
		self.FILE_CRC = 0
		self.rsa_header = RSAFtpHeader()
		# print(self.CURRENT_FILE_KEY)
		
	def decrypt_with_aes(self, key, ciphertext):
		iv = ciphertext[:16]            
		aes = AES.new(key, AES.MODE_CFB, iv)
		plaintext = aes.decrypt(ciphertext[16:])
		self.FILE_CRC ^= zlib.crc32(plaintext)
		return plaintext

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

	def check_crc_file_part(self, data, crc_token):
		return int(data) == int(crc_token)

	# Keep track of the chat clients
	def receiveFromClient(self, data):
		data_len = len(data)                    
		# print("received " + str(self.SERVER_STATUS) + ": " + str(data_len))
		if data_len == BLOCK_SIZE or (self.FILE_SIZE - self.FILE_RECIEP_SIZE + IV_LEN == data_len):         
			last_flag = (self.FILE_SIZE - self.FILE_RECIEP_SIZE + IV_LEN == data_len)
			real_data = self.decrypt_with_aes(self.CURRENT_FILE_KEY, data)                      
			self.FILE_RECIEP_SIZE += len(real_data)
			self.write_file(real_data)			
			rsa_wrapper.printProgressBar(self.FILE_RECIEP_SIZE, self.FILE_SIZE, prefix = 'Progress:', suffix = (str(data_len) + ' bytes Received'), length = 50)
			if last_flag:				
				self.SERVER_STATUS = Server_status.LASTFILE_STATUS
			return True
		else : 
			return False

	# step 1
	def header_data_process(self, data):				
		read_data = struct.unpack('lll', data)
		self.rsa_header = RSAFtpHeader()
		self.rsa_header.meta_len = read_data[0]
		self.rsa_header.from_user = read_data[1]
		self.rsa_header.to_user = read_data[2]
		print(str(self.rsa_header.meta_len) + ":" + str(self.rsa_header.from_user) + ":" + str(self.rsa_header.to_user))
		self.SERVER_STATUS = Server_status.META_STATUS
		return b'accepted'
	# step 2
	def meta_data_process(self, data):
		dec = rsa_wrapper.decryptJTS(data, './m2you/roland-frei/privateKey/roland-frei.data')		
		rsa_wrapper.printProgressBar(0, 10000, prefix = 'Progress:', suffix = 'received from client', length = 50)
		jsonDec = json.loads(dec)		
		# checking length header
		len_json = len(json.dumps(jsonDec))
		if int(self.rsa_header.meta_len) != len_json :
			print("\n Check meta data length is different!" + str(self.rsa_header.meta_len) + ":" + str(len_json))
			return 'failed'
		if not rsa_wrapper.checkMetaData(jsonDec):
			print("\n Check meta data failed!")
			return 'failed'
		jsonDec['meta_len'] = len_json
		self.FILE_SIZE = jsonDec['filesize']    
		# self.FILE_NAME = './temp.dat'
		file_save_dir = './m2you/'+jsonDec['to']+'/'+jsonDec['folder']
		rsawrapper.makeDirPath(file_save_dir)
		self.FILE_NAME = file_save_dir + '/' + jsonDec['filename']             
		jsonDec['filekey'] = FILE_KEY
		pub_key_path = './m2you/' + jsonDec['to'] + '/pubKey/' + jsonDec['from'] + '.data'
		print(pub_key_path)
		jsonDec['metaCRC'] = str(rsa_wrapper.getCRCCode(json.dumps(jsonDec, sort_keys=True)))
		
		# print(pub_key_path)
		enc = rsa_wrapper.encryptJTS(json.dumps(jsonDec), pub_key_path)		
		rsa_wrapper.printProgressBar(0, 10000, prefix = 'Progress:', suffix = 'send meta data to client', length = 50)
		self.SERVER_STATUS = Server_status.FILETRANS_STATUS
		meta_file_path = file_save_dir + '/' + jsonDec['to'] + '/';		
		rsawrapper.makeDirPath(meta_file_path)
		meta_file_name = meta_file_path + jsonDec['from'] + "-" + datetime.datetime.now().strftime("%Y%m%d%H%M%S") + ".meta"

		with open(meta_file_name, 'w') as meta_file_open:
			meta_file_open.write(json.dumps(jsonDec))
			meta_file_open.close()

		write_file_open = open(self.FILE_NAME, "wb")
		write_file_open.close()
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
				# print('resut = ', result)
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

rsaftp = FileTransferProtocal()
loop = asyncio.get_event_loop()
coro = asyncio.start_server(rsaftp.file_trans_protocal, SERVER_URL, SERVER_PORT, loop=loop)
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