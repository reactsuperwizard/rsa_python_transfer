import struct
import asyncio
import traceback
import os
import sys
import codecs
import io
import json
import binascii
import zlib
from Crypto.Cipher import AES
from Crypto.Util import Counter
from components.m2yutils import RSAWrapper 
from components.m2yutils import RSAFtpHeader 
from components import m2yutils
from collections import OrderedDict
import logging

data_size = 0
JsonMeta = None
glength = 0
dirpath = os.getcwd()
sendfilePath = dirpath + sys.argv[1]

################ Initialize Application ##############
def init_app():
	try:
		global RsaFtpVar, SCRIPT_PATH	
		global SERVER_URL, SERVER_PORT, CRC_CHECK_LEN, IV_LEN, BLOCK_SIZE, FILE_KEY, LOG_PATH, M2Y_USERPATH 
		global PRIVATE_DIRNAME, PUBLIC_DIRNAME, CONFIG_FILENAME, KEYFILE_EXT, METAFILE_EXT
		global LogFileOutstream, RsaWrapperObj, RsaHeaderBlock		
		
		CLIENT_STATUS = 0
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
		INDEX = 0

		FILE_BUF = None		
		LogFileOutstream = open(LOG_PATH, "a")		
		RsaWrapperObj = RSAWrapper()
		RsaHeaderBlock = RSAFtpHeader()
		logging.basicConfig(level=logging.DEBUG)
	except Exception as ex:	
		print(ex)

def sendMetaData() :
	global RsaHeaderBlock
	meta_filepath = m2yutils.checkFileExist(sendfilePath)
	if meta_filepath == None :
		return None
	JsonMeta = None
	with io.open(meta_filepath, 'r', encoding='utf8') as meta_info:
		JsonMeta = json.load(meta_info)         
	if(JsonMeta == None):
		return  None
	img_datapath = M2Y_USERPATH + JsonMeta['from'] + os.sep + JsonMeta['folder'] + os.sep + JsonMeta['filename']
	img_datapath = m2yutils.checkFileExist(img_datapath)
	if img_datapath == None :
		return  None
	imgdata_statinfo = os.stat(img_datapath)
	JsonMeta['filesize'] = imgdata_statinfo.st_size;
	json_meta_str = json.dumps(JsonMeta, sort_keys=True)    
	checkSum = RsaWrapperObj.getCRCCode(json_meta_str)
	JsonMeta['metaCRC'] = str(checkSum)	
	json_meta_str = json.dumps(JsonMeta)
	RsaHeaderBlock.meta_len = len(json_meta_str)	
	RsaHeaderBlock.from_user = m2yutils.getEncrypt(JsonMeta['from'])
	RsaHeaderBlock.to_user = m2yutils.getEncrypt(JsonMeta['to'])
	encrypt_path = M2Y_USERPATH + JsonMeta['from'] + os.sep + PUBLIC_DIRNAME + os.sep + JsonMeta['to'] + KEYFILE_EXT
	print(encrypt_path)
	return RsaWrapperObj.encryptJTS(json_meta_str, encrypt_path)
	
def encrypt_with_aes(key, plaintext):
	iv = os.urandom(16)	
	cipher = AES.new(key, AES.MODE_CFB, iv)
	ciphertext = iv + cipher.encrypt(plaintext)	
	return ciphertext, zlib.crc32(plaintext)

def writeLog(logStr):
	LogFileOutstream.appendFileSync(LOG_PATH, logStr)

def readInChunks(fileObj, chunkSize=2048):
	while True:
		data = fileObj.read(chunkSize)
		if not data:
			break
		yield data

def receive_meta_data(data):
	meta_path = M2Y_USERPATH + 'zhenqiang' + os.sep +  PRIVATE_DIRNAME + os.sep + 'zhenqiang' + KEYFILE_EXT	
	print(data)
	dec_txt = RsaWrapperObj.decryptJTS(data, meta_path)
	
	JsonMeta = json.loads(dec_txt)
	if not RsaWrapperObj.checkMetaData(JsonMeta) or JsonMeta['error'] != '':
		print("\ncrc check failed or From Server Error is " + JsonMeta['error'] + "!")
		return None
	print("---- crc check success! ---- ")
	FILE_KEY = JsonMeta['filekey']
	print("------- start send file ---------")
	print("file key : ", FILE_KEY);               
	return JsonMeta

async def send_data(loop):	
	global RsaHeaderBlock
	reader, writer = await asyncio.open_connection(SERVER_URL, SERVER_PORT, loop=loop)
	FILE_CRC = 0
	send_data = sendMetaData()
	# print(RsaHeaderBlock.meta_len)	
	output = struct.pack('l',RsaHeaderBlock.meta_len) +  RsaHeaderBlock.from_user + RsaHeaderBlock.to_user
	# print(output)
	writer.write(output)	
	writer.drain()
	read_data = await reader.read(1024)  		
	# print('Send: ',  len(data))
	writer.write(send_data)
	writer.drain()
	send_data = await reader.read(4096)  		
	JsonMeta = receive_meta_data(send_data)
	
	path = M2Y_USERPATH + JsonMeta['from'] + os.sep + JsonMeta['folder'] + os.sep + JsonMeta['filename']
	print(path)
	filekey = JsonMeta['filekey']
	file_size = JsonMeta['filesize']
	filekey = RsaWrapperObj.make_key(filekey)
	data_size = 0
	f = open(path, 'rb')
	for chunk in readInChunks(f, BLOCK_SIZE):
		send_data, FILE_CRC_CUR = encrypt_with_aes(filekey, chunk)
		FILE_CRC ^= FILE_CRC_CUR
		writer.write(send_data)
		writer.drain()
		send_data = await reader.read(1024)  	
		data_size += len(chunk)             
		RsaWrapperObj.printProgressBar(data_size, file_size, prefix = 'Progress:', suffix = str(send_data), length = 50)
		if data_size == file_size:
			break
	f.close()	
	str_file_crc = str(FILE_CRC)
	print('Send data complete: ')
	writer.write(bytes(str_file_crc, 'utf8'))
	writer.drain()
	send_data = await reader.read(1024)
	
	if send_data == b'success':
		print('Transfer success!!')
	else :
		print('Transfer failed!!')
	writer.close()

	print('Close the socket')

loop = asyncio.get_event_loop()
try :
	init_app()
	loop.run_until_complete(send_data(loop))
except Exception as ex:
	traceback.print_exc()
	print('Erro occure!!')
loop.close()