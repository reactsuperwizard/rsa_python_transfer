We must use the python3.7 or higher (https://bugs.python.org/issue33770)

#Python3 client-server with encryption
1. the client send some encrypted metadata to the server
2. the server add some infos to the meta dta and send it back to the client
3. the client send the binary file to the server
4. the server send ACK to the client

####the meta data is now built of 2 parts
- some unencrypted binary data with a fixed size (it conatins the size of the following encrypted json data)
- the encrypted json data (encrypted wit rsa)


##the sequence
1. client load the file /m2y/zhenqiang/photo/myfoto.meta .. it contains the meta data as json
2. encrypt the json with /m2y/zhenqiang/pubKey/roland-frei.data
3. send the size of the encrypted json data as int64
4. send the encrypted json data to the server
5. the server receive the size of the json data
6. the server receive the encrypted json data
7. the server decrypt using m2y/roland-frei/privateKey/roland-frei.data
8. the server add ‘filekey=random1234’
9. the server encrypt the json data with /m2y/roland-frei/pubKey/zhenqiang.data
10. the server send the size of the encrypted meta data as int64
11. the server send the meta back
12. the client decrypt with /m2y/zhenqiang/privateKey/zhenqiang.data
13. the client send the binary file block by block … encrypting every block with the filekey=random1234 as key
14. the client send the crc of the binary file as int64
15. the server calculates the crc that it was calculating while reciving

####1. client send the binary header
the client connects to server and
send 24 bytes as binary data
8 bytes length of the metaData
8 Bytes Hash of the “from” username
8 Bytes Hash of the “to” username

####2. client send META data to server
send some encrypted (meta data)
the meta data is in json format.
the encryption is RSA . the client encrypt the meta data with the server public key.
the keys are stored locally as text file.
the meta data contains
- from
- to
- folder
- datetime
- filesize
- filekey // the receiver defines they key for the aes128
- fileCRC
- metaCRC
the server receives the the encrypted meta data (the number of bytes is defined in the 1st header)
then it decrypt the data using his private key
now the server checks if the crc of the meta data is correct
if yes, it stores the the meta data to a file.
the filename is folder/to/from-datetime.meta
(the file contains the meta data as json)

####3. server answer to the client and pass the file encryption key
- the server add ‘filekey=random1234’ to the meta data,
- encrypts the meta data with the client pub key
- send it back to the client.
the client receives the meta data, decrypt it , check the crc

####4. client sending the binary file to the server block by block
then the client start sending the file.
the file can be very large (up to 20 gbytes).
so the client read a block of the file (64k) , encrypt it with AES128 using meta.filekey
and the client send the file block by block.
the server receives the block, decode it and append it to the file.

####5. server check the file and send acknowledge
finally (after sending filesize bytes) the client send the filecrc as int64
if the crc is equal to the server side calculated crc,
- the server renames the file to same filename as the metadata with extension .data
- the server send ‘ACK’ to the client. and the client rename the .meta file to .done
if the client dont get a ‘ACK’ from the server he renames .meta to .failed
lib’s use python 3 libs !
https://pymotw.com/3/asyncio/index.html#module-asyncio
ras ???
aes ???
folder and files
files on zhenqiang (client computer)
/m2y/zhenqiang/photo/myfoto.jpg binary data
/m2y/zhenqiang/photo/myfoto.meta meta data
/m2y/zhenqiang/pubKey/roland-frei.data pubKey
/m2y/zhenqiang/privateKey/zhenqiang.data
files on roland-frei (server computer)
/m2y/roland-frei/photo/zhenqiang_30-12-2018_23-59-59.meta
/m2y/roland-frei/photo/zhenqiang_30-12-2018_23-59-59.data
/m2y/roland-frei/pubKey/zhenqiang.data
/m2y/roland-frei/privateKey/roland-frei.data
running the scripts
python.exe m2y-client.py /m2y/zhenqiang/photo/myfoto.meta
python.exe m2y-server.py


###################################################################
#                       ZhenHaoyun's Task                         #
###################################################################

M2y
m2y i a universal peer to peer communcation protocol, that is flexible, secure and reliable.

currently we can transfer meta data and a file from client to server.
the next step is to add config based scripting

M2Y-FOLDER		
in m2y every kind of communication has his “m2y-folder” … 
in this m2y-folder it stores all data and configuration.

every m2y-folder has 
one m2y.config file 
many pairs of META and DATA files

currently we have the m2y folder “foto”
it means that we make a service to upload fotos to a server 
(it is just one example of possible services)

M2Y-CONFIG
m2y/foto/m2y.config
[OnMeta]
m2yCheckPermission.py 
[OnStartup]
m2yResetAllFiles.py
[OnReceived]
m2yNotifyUser.py
[OnNew]
[OnChanged]
[OnDeleted]
[permission]

roland-frei	= allways
peter-norton	= no

this is the configuration file of the m2y-folder “foto” 
you can see the section [OnMeta], it defines the script that is executed when we the server has received the json meta data.

1. Add to m2y-server.py that when meta data is received, it opens the m2y.config (of json.folder) , check the section [OnMeta] and execute the script m2yCheckPermission.py, passing the filename of the metadata. (you must store the meta data to file before call the script). when the script is executde, read the metadata agin and check if json.error==”” (is empty) if so continue, if there is a error, send the json with the error to the client and dont go to receive the data. (executeScript(section))
2. when the binary file is received completely, execute the scripts [OnReceived]
3. You can write the m2yCheckPermission.py, it read the m2y.config file, check the section [permission] and look if the json.from name is listed there (with = allways) , if not write to the meta data json.error=’no permission’, store the meta to file, and exit
the scripts are stored in /m2y/scripts/

##################################################################
######################### STEP 3 #################################
##################################################################
the binary header
there are 3 fields
meta length 
hash of “from” address
hash of “to” address

if the meta data is received, it must be decrypted using the private key of the receiver.
if we have many users on one server, we dont know what user is receiving the message.

on sending we calculate the hash of the users and place the hash in the binary header.

on receive we need to find the username from the hash.
for this we make a directory /m2y/hash2user/123456789abcdef.txt

the filename is the username hash and the file contains the username
this way we can remove the hardcoded usernames from the scripts

… lets use sha256 for the hash … 

design change
lets move the users from m2y/USERNAME to /m2y/user/USERNAME
m2y/user/roland-frei/foto/m2y.config


m2yCreateUser.py roland-frei.json
create a user from a json file.
the json file contains :
username	
realname
email
mobile phone
street
city
zip



the script create the needed directories, and the rsa keys, the hash2user txt file.
(the keys are only generated if they are not allready there)







