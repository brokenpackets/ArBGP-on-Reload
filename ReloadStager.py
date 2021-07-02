from jsonrpclib import Server
import ssl
import base64
from cvplibrary import CVPGlobalVariables, GlobalVariableNames
import hashlib

ssl._create_default_https_context = ssl._create_unverified_context

###Variables
fileName = 'rc.eos'
fileLocation = '/mnt/flash/'
fileBody = '''#!/bin/bash
sed -i s/'^end'/'service routing protocols model multi-agent\\nend'/ /mnt/flash/startup-config
rm /mnt/flash/rc.eos
'''
###
fileMd5 = hashlib.md5(fileBody)
fileHash = fileMd5.hexdigest()
fileEncoded = fileBody.encode('base64','strict')
fileStripped = fileEncoded.replace('\n','')

ip = CVPGlobalVariables.getValue(GlobalVariableNames.CVP_IP)
user = CVPGlobalVariables.getValue(GlobalVariableNames.CVP_USERNAME)
passwd = CVPGlobalVariables.getValue(GlobalVariableNames.CVP_PASSWORD)

class hashException(Exception):
  """ Exception raised due to hash mismatch."""

### Rest of script
def main():
  #SESSION SETUP FOR eAPI TO DEVICE
  url = "https://%s:%s@%s/command-api" % (user, passwd, ip)
  ss = Server(url)

  #Copy file to EOS
  uploadFile = ss.runCmds ( 1, [ 'enable', 'bash timeout 2 echo "'+fileStripped+'" | base64 -d > '+fileLocation+fileName])
  #Md5 checksum
  checkHash = ss.runCmds ( 1, ['enable', 'bash timeout 2 cat '+fileLocation+fileName+' | md5sum'])[1]['messages'][0]
  if checkHash.startswith(fileHash):
    # Hash matches
    pass
  else:
    removeFile = ss.runCmds ( 1, [ 'enable', 'bash timeout 2 rm -rf '+fileLocation+fileName])
    raise hashException('Hash Mismatch')
if __name__ == "__main__":
  main()
