import asyncio
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
rsawrapper = RSAWrapper()



def checkFileExist(filePath):
	exists = os.path.isfile(filePath)
	if exists == None:
		print("Can't find", filePath)
		client.destroy()
		return None
	return filePath

def sendMetaData() :
	meta_filepath = checkFileExist(sendfilePath)
	if meta_filepath == None :
		return None
	JsonMeta = None;
	with io.open(meta_filepath, 'r', encoding='utf8') as meta_info:
		JsonMeta = json.load(meta_info)         
	if(JsonMeta == None):
		return  None
	img_datapath = './m2you/'+JsonMeta['from']+'/'+JsonMeta['folder']+'/'+JsonMeta['filename']  
	img_datapath = checkFileExist(img_datapath)
	if img_datapath == None :
		return  None
	imgdata_statinfo = os.stat(img_datapath)
	JsonMeta['filesize'] = imgdata_statinfo.st_size;
	json_meta_str = json.dumps(JsonMeta, sort_keys=True)    
	checkSum = rsawrapper.getCRCCode(json_meta_str)
	JsonMeta['metaCRC'] = str(checkSum)	
	return rsawrapper.encryptJTS(json.dumps(JsonMeta), './m2you/'+JsonMeta['from']+'/pubKey/'+JsonMeta['to']+'.data')   
	


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

def sendFileToServerByStream(JsonMeta, writer):
	path = './m2you/'+JsonMeta['from']+'/'+JsonMeta['folder']+'/'+JsonMeta['filename']
	filekey = JsonMeta['filekey']
	print(len(filekey))
	filekey = rsawrapper.make_key(filekey)
	data_size = 0
	f = open(path, 'rb')
	for chunk in readInChunks(f, BLOCK_SIZE):
		data = encrypt_with_aes(filekey, chunk)
		print('Send data len: ',  len(data))
		writer.write(data)
		writer.drain()
		data_size += len(chunk)             		
	f.close()
	writer.write(bytes(FILE_CRC))
	writer.drain()
	writer.close()
	CLIENT_STATUS = 2

def sendFileToServer():
	if(INDEX == 0) :
		print("file length : ", FILE_BUF.length)
		if FILE_BUF.length > BLOCK_SIZE :
			tmpBuf = Buffer.alloc(BLOCK_SIZE)
			FILE_BUF.copy(tmpBuf, 0, INDEX * BLOCK_SIZE, (INDEX + 1) * BLOCK_SIZE)
			encBuf = encrypt(tmpBuf)
			client.write(encBuf)
			data_size += BLOCK_SIZE
		else:
			encBuf = encrypt(FILE_BUF)
			client.write(encBuf);    
			CLIENT_STATUS = 3
			print("small size : ", FILE_BUF.length)        
		return    
	tmpBuf = Buffer.alloc(BLOCK_SIZE)
	FILE_BUF.copy(tmpBuf, 0, INDEX * BLOCK_SIZE, (INDEX + 1) * BLOCK_SIZE)
	encBuf = encrypt(tmpBuf)
	client.write(encBuf)

def mainFunction(data, writer) :
	global CLIENT_STATUS

	if CLIENT_STATUS == 0:
		print(' \n------ Server Response: ---\n\n', data)
		dec_tst = rsawrapper.decryptJTS(data, './m2you/zhenqiang/privateKey/zhenqiang.data'); 
		print("\n---- decripted txt from server --- \n", dec_tst)
		JsonMeta = json.loads(dec_tst)

		if not rsawrapper.checkMetaData(JsonMeta):
			print("\ncrc check failed!")
			return None

		FILE_KEY = JsonMeta['filekey']
		
		print("\n---- crc check success! ---- \n")
		print("\n------- start send file ---------\n")
		print("file key : ", FILE_KEY);               

		return  sendFileToServerByStream(JsonMeta, writer)
	elif CLIENT_STATUS == 1:
		INDEX +=1;                
		psBar.update(INDEX)

		if(INDEX < Math.floor(FILE_BUF.length/BLOCK_SIZE)):
			sendFileToServer()
			data_size += BLOCK_SIZE
			return

		if(INDEX == Math.floor(FILE_BUF.length/BLOCK_SIZE)):
			tmpBuf = Buffer.alloc(FILE_BUF.length - INDEX * BLOCK_SIZE)
			 # print("rest size", FILE_BUF.length - (INDEX-1) * BLOCK_SIZE)
			FILE_BUF.copy(tmpBuf, 0, INDEX * BLOCK_SIZE, FILE_BUF.length)
			encBuf = encrypt(tmpBuf)
			data_size+= encBuf.length
			print("rest size : ", encBuf.length)
			client.write(encBuf)
			return
		
		if(INDEX == Math.floor(FILE_BUF.length/BLOCK_SIZE) + 1):
			print("\n--------- File CRC Send-------\n")
			print("filecrc : ", FILE_CRC)
			client.write(FILE_CRC.toString())
			CLIENT_STATUS = 2
			return
		
	elif CLIENT_STATUS == 2:
		#--> oldpath = './m2you/' + JsonMeta['from'] + '/'+ JsonMeta['folder'] + '/'
		fname = sendfilePath.split(".")[0]
	
		if data.toString() == "ACK":
			 # psBar.stop()
			print("\n------ ACK Received ---------\n")
			print(oldpath + "==>" + oldpath + fname + ".done")
			 # fs.renameSync(oldpath + sendfilePath , oldpath + fname + ".done")
			client.destroy()
			return
		
		print("Transfer failed !!")
		 # fs.renameSync(oldpath + sendfilePath , oldpath + fname + ".failed")
		client.destroy()
	elif CLIENT_STATUS == 3:
		print("from server")
		client.write(FILE_CRC.toString())
		psBar.update(FILE_BUF.length/BLOCK_SIZE)
		CLIENT_STATUS = 2
	else :
		return None

def receive_meta_data(data):
	print(' \n------ Server Response: ---\n\n', data)
	dec_tst = rsawrapper.decryptJTS(data, './m2you/zhenqiang/privateKey/zhenqiang.data'); 
	print("\n---- decripted txt from server --- \n", dec_tst)
	JsonMeta = json.loads(dec_tst)

	if not rsawrapper.checkMetaData(JsonMeta):
		print("\ncrc check failed!")
		return None

	FILE_KEY = JsonMeta['filekey']
	
	print("\n---- crc check success! ---- \n")
	print("\n------- start send file ---------\n")
	print("file key : ", FILE_KEY);               
	return JsonMeta

async def send_data(message, loop):
	reader, writer = await asyncio.open_connection(SERVER_URL, SERVER_PORT, loop=loop)
	data = sendMetaData()
	global FILE_CRC
	print('Send: ',  len(data))
	writer.write(data)
	writer.drain()
	data = await reader.read(1024)  	
	print('Received: ', data)	
	JsonMeta = receive_meta_data(data)
	
	path = './m2you/'+JsonMeta['from']+'/'+JsonMeta['folder']+'/'+JsonMeta['filename']
	print(path)
	filekey = JsonMeta['filekey']
	file_size = JsonMeta['filesize']
	print(len(filekey))
	filekey = rsawrapper.make_key(filekey)
	print(len(filekey))	
	data_size = 0
	f = open(path, 'rb')
	for chunk in readInChunks(f, BLOCK_SIZE):
		data = encrypt_with_aes(filekey, chunk)
		print('Send data len: ',  len(data))
		writer.write(data)
		writer.drain()
		data = await reader.read(1024)  	
		print(data)
		data_size += len(chunk)             
		if data_size == file_size:
			break
	f.close()	
	str_file_crc = str(FILE_CRC)
	print('Send data len: ',  len(str_file_crc))
	writer.write(bytes(str_file_crc, 'utf8'))
	writer.drain()
	data = await reader.read(1024)
	print(data)
	writer.close()

	print('Close the socket')

message = 'Hello World!'
loop = asyncio.get_event_loop()
loop.run_until_complete(send_data(message, loop))
loop.close()