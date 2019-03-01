import hashlib
import sys
import os
import json
import io

from components import m2yutils

RESULT = 'FAILED - GEN USER'
def check_fucntion(meta_path):
    global RESULT
    try:
        config = m2yutils.read_configFile('./m2y.ini')        
        M2Y_HASHPATH = config.get('PATHS','M2YHASHPATH') + os.sep
        HASHFILE_EXT = config.get('PATHS','HASHFILEEXT')
        with io.open(meta_path, 'r', encoding='utf8') as meta_info:
            JsonMeta = json.load(meta_info)            
            if JsonMeta != None:
                username = bytes(JsonMeta['username'], 'utf-8')
                filename = m2yutils.getEncrypt(username).hex()
                print(filename)
                m2yutils.makeDirPath(M2Y_HASHPATH)
                print(M2Y_HASHPATH)
                hashfile_path = M2Y_HASHPATH + filename + HASHFILE_EXT
                print(m2yutils.checkFileExist(hashfile_path))
                if m2yutils.checkFileExist(hashfile_path):
                    with open(hashfile_path, 'w') as outfile:
                        outfile.write(username.decode("utf-8") )
                        outfile.close()                                        
                RESULT = 'SUCCESS - GEN USER'
                ############### check the file path ###########

                #################### write file #####################
    except Exception as ex:
        pass

meta_path = sys.argv[1]        
if meta_path :
    check_fucntion(meta_path)
print(RESULT)
