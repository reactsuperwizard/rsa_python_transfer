import asyncio
import os
import sys
import codecs
import io
import json
import binascii
import zlib

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

def encryptRSA(toEncrypt, relativeOrAbsolutePathToPublicKey) :
	absolutePath = path.resolve(relativeOrAbsolutePathToPublicKey)
	publicKey = logFile.readFileSync(absolutePath, 'utf8')
	# -->key = new NodeRSA()
	key.importKey(publicKey, 'pkcs8-public')
	return key.encrypt(toEncrypt, 'base64', 'utf8')


def decryptRSA(toDecrypt, relativeOrAbsolutePathtoPrivateKey) :
	absolutePath = path.resolve(relativeOrAbsolutePathtoPrivateKey)
	privateKey = logFile.readFileSync(absolutePath, 'utf8')
	# -->key = new NodeRSA()
	key.importKey(privateKey, 'pkcs8-private')
	return key.decrypt(toDecrypt, 'utf8')


def checkFileExist(filePath):
	exists = os.path.isfile(filePath)
	if exists == None:
		print("Can't find", filePath)
		client.destroy()
		return None
	return filePath

def sendMetaData(reader, writer) :
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
	


def encrypt(buffer):
	cipher = crypto.createCipher('aes-128-ctr',FILE_KEY)
	crypted = Buffer.concat([cipher.update(buffer),cipher.final()])
	FILE_CRC = 0
	FILE_CRC ^= crc.crc32(crypted, 'hex')   
	return crypted


def writeLog(logStr):
	logFile.appendFileSync("./log/client.log", logStr)


def sendFileToServerByStream():
	i = 0
	#--> path = './m2you/'+JsonMeta['from']+'/'+JsonMeta['folder']+'/'+JsonMeta['filename']
	#-->readStream = logFile.createReadStream(path, flags: 'r', highWaterMark: BLOCK_SIZE )
	# let chunks = []
	# psBar.start(JsonMeta['filesize']/BLOCK_SIZE, 0)
	# Handle any errors while reading
	#--> readStream.on('error', err => :   return cb(err) )

	## Listen for data
	# readStream.on('data', chunk => :
	#  glength += chunk.length;        
	#  encBuf = encrypt(chunk)
		
	#   # writeLog(INDEX+=1 + ":" + encBuf.toString())

	#  client.write(encBuf)
	#  sleep.usleep(10)
	#   # psBar.update(INDEX+=1)
	#   # print("send Buf : ", encBuf)
	#  data_size += BLOCK_SIZE

	# )

	 # File is done being read
	# readStream.on('close', () => :
	#   # Create a buffer of the image from the stream
	#  print("\n------- Sent File Total Length -----------\n", glength)
	#  CLIENT_STATUS = 2
	#  client.write(FILE_CRC.toString())
	#   # return cb(None, Buffer.concat(chunks))
	# )


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

def mainFunction(data) :
	global CLIENT_STATUS
	if CLIENT_STATUS == 0:
		print(' \n------ Server Response: ---\n\n', data)
		dec_tst = rsaWrapper.decryptJTS(data, './m2you/zhenqiang/privateKey/zhenqiang.data'); 
		print("\n---- decripted txt from server --- \n", dec_tst)
		FILE_KEY = rsaWrapper.checkMetaData(JSON.parse(dec_tst))
		if FILE_KEY == None:
			print("\ncrc check failed!")
			return None
		
		print("\n---- crc check success! ---- \n")
		print("\n------- start send file ---------\n")
		print("file key : ", FILE_KEY);               
		 # sendFileToServer()
		return  sendFileToServerByStream()
		 # CLIENT_STATUS = 1
		 # psBar.start(FILE_BUF.length/BLOCK_SIZE, 0); 

	elif CLIENT_STATUS == 1:
		INDEX +=1;                
		psBar.update(INDEX)
		 # print(INDEX + " : " + data_size)
		 # print("\n", data.toString("utf8"))
		if(INDEX < Math.floor(FILE_BUF.length/BLOCK_SIZE)):
			sendFileToServer()
			data_size += BLOCK_SIZE
			return
		# 16933

		 # print("count ; ", Math.ceil(FILE_BUF.length/BLOCK_SIZE))
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


class FileEncryptProtocol(asyncio.Protocol):
	def connection_made(self, transport):
		self.transport = transport
		result = sendMetaData(self.transport)        
		if result != None
			self.transport.write(result)
	
	def data_received(self, data):
		self.transport.write(data)

async def main(host, port):
	loop = asyncio.get_running_loop()
	server = await loop.create_server(FileEncryptProtocol, host, port)
	await server.serve_forever()

asyncio.run(main(SERVER_URL, SERVER_PORT))


async def main_filetrans_process(message, loop):   
	reader, writer = await asyncio.open_connection(SERVER_URL, SERVER_PORT, loop=loop)
	print("----------start connect to server-----------")
	print("----------main Function -----------")    
	# while True:
	# data = await reader.read()    
	# print(data)
	#   result = mainFunction(data)
	#   if result == None:
	#       break
	#   else :
	#       writer.write(result)
	#       await writer.drain()

	# print('----------Close the socket -------')
	# writer.close()


message = sys.argv[1]
