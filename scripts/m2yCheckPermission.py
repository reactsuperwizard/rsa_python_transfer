import os
import json
import configparser

global executeScript_result;
executeScript_result = False

def executeScript(meta_dirpath, meta_filepath):    
    try:        
        print(meta_filepath)    
        with open(meta_filepath, 'r') as meta_file_open:
            ############## JSON READ COMPLETE
            jsonStrData = meta_file_open.read()            
            jsonDec = json.loads(jsonStrData)
            meta_file_open.close()
            from_user = jsonDec['from']
            ############### CONFIG
            conf_path = meta_dirpath + '/m2y.config'            
            config = configparser.ConfigParser(allow_no_value=True)
            config.optionxform=str
            config.read(conf_path)            
            print(from_user)
            if 'permission' in config and from_user in config['permission']:                
                if config['permission'][from_user] == 'always':
                    return True

    except Exception as identifier:
        print(identifier)

    return False

print('BEGIN:')        
if meta_filepath and  meta_dirpath :    
    executeScript_result = executeScript(meta_dirpath, meta_filepath)
print('COMPLETED:')
