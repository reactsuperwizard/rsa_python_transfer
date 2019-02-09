from asyncio import Task, coroutine, get_event_loop
from components.rsawrapper import RSAWrapper 
from socket import socket, SO_REUSEADDR, SOL_SOCKET
from enum import Enum
import asyncio
import json
import logging

SERVER_URL='127.0.0.1'
SERVER_PORT = 5000
FILE_INDEX = 0
FILE_KEY = 'random1234'
BUF_SIZE = 0
BLOCK_SIZE = 4096
TMP_BUFFER = bytearray(BLOCK_SIZE)
TMP_SIZE = 0
FILE_SIZE = 0
FILE_NAME = ''
logout = open("./log/server.log", "a")
rsaWrapper = RSAWrapper()
logging.basicConfig(level=logging.DEBUG)

class Server_status(Enum):
	META_STATUS = 0
	FILETRANS_STATUS = 1
	LASTFILE_STATUS = 2

SERVER_STATUS = Server_status.META_STATUS

def initGlobal():
	SERVER_STATUS = Server_status.META_STATUS
	FILE_INDEX = 0
	BUF_SIZE = 0
	TMP_SIZE = 0
	FILE_INDEX = 0
	FILE_NAME = ""
	FILE_CRC = 0

def decrypt(buffer):    
	FILE_CRC += crc.crc32(buffer, 'hex')
	FILE_CRC = FILE_CRC % 0xFFFFFFFFFFFFFFFF

	BUF_SIZE += buffer.length
	decipher = crypto.createDecipher('aes-128-ctr',FILE_KEY)
	dec = Buffer.concat([decipher.update(buffer) , decipher.final()])
	logout.appendFileSync(FILE_NAME, dec)
	return dec

def writeLog(logStr):
	fs.appendFileSync("./log/server.log", logStr)

# Keep track of the chat clients
def receiveFromClient(data):
	# print("received : ", data)
	# writeLog(FILE_INDEX + ":" + data.toString())
	global BLOCK_SIZE
	global TMP_SIZE
	if len(data) == BLOCK_SIZE and TMP_SIZE == 0:
		decrypt(data)
		return    

	if len(data) > BLOCK_SIZE:
		bCnt = Math.floor(len(data) / BLOCK_SIZE)
		rest = len(data) % BLOCK_SIZE
		i = 0
		while i < bCnt:
			buf = Buffer.alloc(BLOCK_SIZE)
			data.copy(buf, 0, BLOCK_SIZE * i, (i + 1) * BLOCK_SIZE)
			decrypt(buf)
			i += 1
		
		if rest != 0:
			if TMP_SIZE + rest >= BLOCK_SIZE:
				data.copy(TMP_BUFFER, TMP_SIZE, BLOCK_SIZE * i, BLOCK_SIZE * i + BLOCK_SIZE - TMP_SIZE)
				decrypt(TMP_BUFFER)
				TMP_SIZE = TMP_SIZE + rest - BLOCK_SIZE
				data.copy(TMP_BUFFER, 0, BLOCK_SIZE * i + BLOCK_SIZE - TMP_SIZE, len(data))
			else :
				data.copy(TMP_BUFFER, TMP_SIZE, BLOCK_SIZE * i, len(data))
				TMP_SIZE += rest
		return 0
	
	if len(data) < BLOCK_SIZE:
		if BUF_SIZE + TMP_SIZE >= FILE_SIZE:
			buf = Buffer.alloc(TMP_SIZE)
			TMP_BUFFER.copy(buf, 0, 0, TMP_SIZE)
			decrypt(buf)
			print("\n-----------------File Receive End----------------\n")
			print("Received data size : " + BUF_SIZE)
			print("CRC : " , data.toString())
			print("mine : ", FILE_CRC)
			if data.toString() == FILE_CRC.toString():
				print("----------- File CRC Match Success !!! -----------\n")
				return 1
			else:
				print("----------- File CRC Match Failed -----------\n")
				return -1           
		
		if TMP_SIZE + len(data) >= BLOCK_SIZE:
			data.copy(TMP_BUFFER, TMP_SIZE, 0, BLOCK_SIZE - TMP_SIZE)
			decrypt(TMP_BUFFER)
			TMP_SIZE = TMP_SIZE + len(data) - BLOCK_SIZE
			data.copy(TMP_BUFFER, 0, len(data) - TMP_SIZE, len(data))
		else :
			data.copy(TMP_BUFFER, TMP_SIZE, 0, len(data))
			TMP_SIZE += len(data)
		return 0
	
def data_process(data): 
	global SERVER_STATUS
	global BLOCK_SIZE
	global FILE_SIZE
	global FILE_KEY
	if SERVER_STATUS == Server_status.META_STATUS:
		dec = rsaWrapper.decryptJTS(data, './m2you/roland-frei/privateKey/roland-frei.data')
		print("---------received from client---------")
		print(dec)
		jsonDec = json.loads(dec)               
		if not rsaWrapper.checkMetaData(jsonDec):
			print("\n Check meta data failed!")
			return
		FILE_SIZE = jsonDec['filesize']
		FILE_NAME = './m2you/'+jsonDec['to']+'/'+jsonDec['folder']+'/'+jsonDec['filename']      
		jsonDec['filekey'] = FILE_KEY
		enc = rsaWrapper.encryptJTS(json.dumps(jsonDec), './m2you/' + jsonDec['from'] + '/pubKey/' + jsonDec['from'] + '.data')
		print("\n ------ send meta data to client : --------\n", enc)
		# print("file_size", FILE_SIZE)
		if FILE_SIZE > BLOCK_SIZE:
			SERVER_STATUS = Server_status.FILETRANS_STATUS
		else :
			SERVER_STATUS = Server_status.LASTFILE_STATUS
		return enc  
	elif SERVER_STATUS == Server_status.FILETRANS_STATUS:
		ret = receiveFromClient(data)
		if ret == 0:
			FILE_INDEX += 1
			# psBar.update(FILE_INDEX)
			# return "1")                   
		elif ret == 1:
			# psBar.stop()
			print("----- Send ACK --------\n")
			return "ACK"
			SERVER_STATUS = Server_status.LASTFILE_STATUS
		else :
			return "ERROR"
		initGlobal()    
	elif SERVER_STATUS == Server_status.LASTFILE_STATUS:
		# print("small data receive")
		#--> tmpData = Buffer.from(data)
		if FILE_INDEX == 0:
			decrypt(tmpData)
			FILE_INDEX += 1
			# return "1")   
			
		
		psBar.update(FILE_SIZE/BLOCK_SIZE)
		psBar.stop()
		if tmpData.toString() == FILE_CRC.toString():
			print("----------- File CRC Match Success !!! -----------\n")
			return "ACK"
		else :
			print("----------- File CRC Match Failed -----------\n")
			return "ERROR"
		initGlobal()
		   
async def socket_server(reader, writer):
	initGlobal()
	while True:
		data = await reader.read()  # Max number of bytes to read
		if not data:
			break
		result = data_process(data)     
		writer.write(result)
		await writer.drain()  # Flow control, see later
	writer.close()

async def main(host, port):
	server = await asyncio.start_server(socket_server, host, port)
	await server.serve_forever()

asyncio.run(main(SERVER_URL, SERVER_PORT))
