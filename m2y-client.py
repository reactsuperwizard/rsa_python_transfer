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
from components.rsawrapper import RSAWrapper 
from components.rsawrapper import RSAFtpHeader 
from components import rsawrapper
from collections import OrderedDict

SERVER_URL='127.0.0.1'
SERVER_PORT = 5000
CLIENT_STATUS = 0
FILE_KEY = ''
BLOCK_SIZE = 4096
INDEX = 0
FILE_BUF = None
FILE_CRC = 0
data_size = 0
JsonMeta = None
glength = 0
logFile = open("./log/client.log", "a")
dirpath = os.getcwd()
sendfilePath = dirpath + sys.argv[1]
rsa_wrapper = RSAWrapper()
rsa_header = RSAFtpHeader()

def sendMetaData() :
	global rsa_header
	meta_filepath = rsawrapper.checkFileExist(sendfilePath)
	if meta_filepath == None :
		return None
	JsonMeta = None
	with io.open(meta_filepath, 'r', encoding='utf8') as meta_info:
		JsonMeta = json.load(meta_info)         
	if(JsonMeta == None):
		return  None
	img_datapath = './m2you/'+JsonMeta['from']+'/'+JsonMeta['folder']+'/'+JsonMeta['filename']  
	img_datapath = rsawrapper.checkFileExist(img_datapath)
	if img_datapath == None :
		return  None
	imgdata_statinfo = os.stat(img_datapath)
	JsonMeta['filesize'] = imgdata_statinfo.st_size;
	json_meta_str = json.dumps(JsonMeta, sort_keys=True)    
	checkSum = rsa_wrapper.getCRCCode(json_meta_str)
	JsonMeta['metaCRC'] = str(checkSum)	
	json_meta_str = json.dumps(JsonMeta)
	rsa_header.meta_len = len(json_meta_str)
	rsa_header.from_user = 1
	rsa_header.to_user = 2
	return rsa_wrapper.encryptJTS(json_meta_str, './m2you/'+JsonMeta['from']+'/pubKey/'+JsonMeta['to']+'.data')
	
def encrypt_with_aes(key, plaintext):
	global FILE_CRC
	iv = os.urandom(16)	
	cipher = AES.new(key, AES.MODE_CFB, iv)
	ciphertext = iv + cipher.encrypt(plaintext)
	FILE_CRC ^= zlib.crc32(plaintext)
	return ciphertext

def writeLog(logStr):
	logFile.appendFileSync("./log/client.log", logStr)

def readInChunks(fileObj, chunkSize=2048):
	while True:
		data = fileObj.read(chunkSize)
		if not data:
			break
		yield data

def receive_meta_data(data):
	dec_txt = rsa_wrapper.decryptJTS(data, './m2you/zhenqiang/privateKey/zhenqiang.data'); 
	JsonMeta = json.loads(dec_txt)
	if not rsa_wrapper.checkMetaData(JsonMeta):
		print("\ncrc check failed!")
		return None
	print("---- crc check success! ---- ")
	FILE_KEY = JsonMeta['filekey']
	print("------- start send file ---------")
	print("file key : ", FILE_KEY);               
	return JsonMeta

async def send_data(loop):
	global FILE_CRC
	global rsa_header
	reader, writer = await asyncio.open_connection(SERVER_URL, SERVER_PORT, loop=loop)

	data = sendMetaData()
	# print(rsa_header.meta_len)	
	output = struct.pack('lll',rsa_header.meta_len, rsa_header.from_user, rsa_header.to_user)
	# print(output)
	writer.write(output)	
	writer.drain()
	read_data = await reader.read(4096)  		
	# print('Send: ',  len(data))
	writer.write(data)
	writer.drain()
	data = await reader.read(4096)  		
	JsonMeta = receive_meta_data(data)
	
	path = './m2you/'+JsonMeta['from']+'/'+JsonMeta['folder']+'/'+JsonMeta['filename']
	print(path)
	filekey = JsonMeta['filekey']
	file_size = JsonMeta['filesize']
	# print(len(filekey))
	filekey = rsa_wrapper.make_key(filekey)
	# print(len(filekey))	
	data_size = 0
	f = open(path, 'rb')
	for chunk in readInChunks(f, BLOCK_SIZE):
		data = encrypt_with_aes(filekey, chunk)
		# print('Send data len: ',  len(data))
		writer.write(data)
		writer.drain()
		data = await reader.read(1024)  	
		# print(data)
		data_size += len(chunk)             
		rsa_wrapper.printProgressBar(data_size, file_size, prefix = 'Progress:', suffix = str(data), length = 50)
		if data_size == file_size:
			break
	f.close()	
	str_file_crc = str(FILE_CRC)
	print('Send data complete: ')
	writer.write(bytes(str_file_crc, 'utf8'))
	writer.drain()
	data = await reader.read(1024)
	
	if data == b'success':
		print('Transfer success!!')
	else :
		print('Transfer failed!!')
	writer.close()

	print('Close the socket')

loop = asyncio.get_event_loop()
try :
	loop.run_until_complete(send_data(loop))
except Exception as ex:
	traceback.print_exc()
	print('Erro occure!!')
loop.close()