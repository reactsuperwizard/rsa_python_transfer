import hashlib
import sys
import os
import json
import io
import hashlib
from components import rsawrapper 

RESULT = 'FAILED - GEN USER'
def check_fucntion(meta_path):
    global RESULT
    with io.open(meta_path, 'r', encoding='utf8') as meta_info:
        JsonMeta = json.load(meta_info)
        if JsonMeta != None:
            sha256 = hashlib.sha256()
            username = bytes(JsonMeta['username'], 'utf-8')
            sha256.update(username)
            filename = sha256.hexdigest()            
            path = './m2y/'
            rsawrapper.checkFileExist('')
            RESULT = 'SUCCESS - GEN USER'
            
            ############### check the fil1e path ###########

            #################### write file #####################

meta_path = sys.argv[1]        
if meta_path :
    check_fucntion(meta_path)
print(RESULT)
