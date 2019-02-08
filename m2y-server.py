from socket import socket, SO_REUSEADDR, SOL_SOCKET
from asyncio import Task, coroutine, get_event_loop
import asyncio

SERVER_URL='127.0.0.1'
SERVER_PORT = 5000
SERVER_STATUS = 0
FILE_INDEX = 0
FILE_KEY = 'random1234'
BUF_SIZE = 0
BLOCK_SIZE = 4096
TMP_BUFFER = bytearray(BLOCK_SIZE)
TMP_SIZE = 0
FILE_SIZE = 0
FILE_NAME = ''
logout = open("./log/server.log", "a")

def initGlobal(none):
	SERVER_STATUS = 0
	FILE_INDEX = 0
	BUF_SIZE = 0
	TMP_SIZE = 0
	FILE_INDEX = 0
	FILE_NAME = ""
	FILE_CRC = 0
	print("##### initGlobal ###")

def decrypt(buffer):
	# if(buffer.length != 4096) SERVER_STATUS = 3
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

	if data.length == BLOCK_SIZE and TMP_SIZE == 0:
		decrypt(data)
		return    

	if data.length > BLOCK_SIZE:
		bCnt = Math.floor(data.length / BLOCK_SIZE)
		rest = data.length % BLOCK_SIZE
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
				data.copy(TMP_BUFFER, 0, BLOCK_SIZE * i + BLOCK_SIZE - TMP_SIZE, data.length)
			else :
				data.copy(TMP_BUFFER, TMP_SIZE, BLOCK_SIZE * i, data.length)
				TMP_SIZE += rest
		return 0
	
	if data.length < BLOCK_SIZE:
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
		
		if TMP_SIZE + data.length >= BLOCK_SIZE:
			data.copy(TMP_BUFFER, TMP_SIZE, 0, BLOCK_SIZE - TMP_SIZE)
			decrypt(TMP_BUFFER)
			TMP_SIZE = TMP_SIZE + data.length - BLOCK_SIZE
			data.copy(TMP_BUFFER, 0, data.length - TMP_SIZE, data.length)
		else :
			data.copy(TMP_BUFFER, TMP_SIZE, 0, data.length)
			TMP_SIZE += data.length
		return 0
	
def data_process(data): 

	if SERVER_STATUS == 0:
		dec = rsaWrapper.decryptU(data.toString('utf-8'), './m2you/roland-frei/privateKey/roland-frei.data')
		print("---------received from client---------")
		# checkSecurity.initLoadServerKeys("test")
		jsonDec = JSON.parse(dec)
		
		retMetaData = rsaWrapper.checkMetaData(jsonDec)
		if retMetaData is None:
			print("\n Check meta data failed!")
			return
		

		FILE_SIZE = jsonDec.filesize
		# FILE_NAME = jsonDec.to
		FILE_NAME = './m2you/'+jsonDec.to+'/'+jsonDec.folder+'/'+jsonDec.filename
		#--> writeLog(FILE_NAME + def(err)  )

		#--> enc = rsaWrapper.encryptU(retMetaData, './m2you/' + jsonDec.from + '/pubKey/' + jsonDec.from + '.data')
		print("\n ------ send meta data to client : --------\n\n", enc)
		print("file_size", FILE_SIZE)
		if FILE_SIZE > BLOCK_SIZE:
			SERVER_STATUS = 1
		else :
			SERVER_STATUS = 2
		socket.write(enc)
		# psBar.start(FILE_SIZE/BLOCK_SIZE, 0)		
	elif SERVER_STATUS == 1:
		#--> ret = receiveFromClient(Buffer.from(data))
		if ret == 0:
			FILE_INDEX += 1
			# psBar.update(FILE_INDEX)
			# socket.write("1")					
		elif ret == 1:
			# psBar.stop()
			print("----- Send ACK --------\n")
			socket.write("ACK")
			SERVER_STATUS = 2
		else :
			socket.write("ERROR")		
		initGlobal()	
	elif SERVER_STATUS == 2:		
		# print("small data receive")
		#--> tmpData = Buffer.from(data)
		if FILE_INDEX == 0:
			decrypt(tmpData)
			FILE_INDEX += 1
			# socket.write("1")
			
		
		psBar.update(FILE_SIZE/BLOCK_SIZE)
		psBar.stop()
		if tmpData.toString() == FILE_CRC.toString():
			print("----------- File CRC Match Success !!! -----------\n")
			socket.write("ACK")
		else :
			print("----------- File CRC Match Failed -----------\n")
			socket.write("ERROR")       
		initGlobal()
		   
# class EchoProtocol(asyncio.Protocol):	
# 	def connection_made(self, transport):
# 		self.transport = transport
	
# 	def data_received(self, data):
# 		self.transport.write(data)
# 		# self.data_process(data)

# async def main(host, port):
#    loop = asyncio.get_running_loop()
#    server = await loop.create_server(EchoProtocol, host, port)
#    await server.serve_forever()

# asyncio.run(main('127.0.0.1', SERVER_PORT))

async def handle_echo(reader, writer):
    data = await reader.read(100)
    message = data.decode()
    addr = writer.get_extra_info('peername')
    print("Received %r from %r" % (message, addr))

    print("Send: %r" % message)
    writer.write(data)
    await writer.drain()

    print("Close the client socket")
    writer.close()

loop = asyncio.get_event_loop()
coro = asyncio.start_server(handle_echo, SERVER_URL, SERVER_PORT, loop=loop)
server = loop.run_until_complete(coro)

# Serve requests until Ctrl+C is pressed
print('Serving on {}'.format(server.sockets[0].getsockname()))
try:
    loop.run_forever()
except KeyboardInterrupt:
    pass

# Close the server
server.close()
loop.run_until_complete(server.wait_closed())
loop.close()