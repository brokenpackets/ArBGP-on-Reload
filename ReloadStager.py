from jsonrpclib import Server
import ssl
import base64
from cvplibrary import CVPGlobalVariables, GlobalVariableNames
import hashlib

ssl._create_default_https_context = ssl._create_unverified_context

"""
This file creates an aliases file called /etc/profile.d/00-aliases.sh, which will automatically apply
to all user profiles. The goal is to automatically map curl to curl --interface for all users, so
that CVP image downloads can utilize the `ip http client local-interface` equivalent for CVP 2021+.

Workflow:
  - Pushes 00-aliases.sh with the new curl alias.
  - Creates a file called rc.eos under /mnt/flash, which will automatically
    create this file on reboot to make it persistent.
  - Builds the EOS config of `ip http client local-interface` for consistency.
Update the `updateSource` variable to match the linux namespace desired update-source:
  eg: et12, vlan100, lo0, etc...
"""

###Variables
updateSource = 'lo0' #make sure to use linux intf naming here.
aliasFileBody = "alias curl='curl --interface {interface}'\n".format(interface=updateSource)
rcFileBody = '#!/bin/sh\n/usr/bin/cp /mnt/flash/00-aliases.sh /etc/profile.d/00-aliases.sh\n/usr/bin/chown root:eosadmin /etc/profile.d/00-aliases.sh\n'
###

device_ip = CVPGlobalVariables.getValue(GlobalVariableNames.CVP_IP)
user = CVPGlobalVariables.getValue(GlobalVariableNames.CVP_USERNAME)
passwd = CVPGlobalVariables.getValue(GlobalVariableNames.CVP_PASSWORD)

class hashException(Exception):
    """ Exception raised due to hash mismatch."""

def uploadFile(fileBody,fileLocation,fileName,sudo=False):
    url = "https://%s:%s@%s/command-api" % (user, passwd, device_ip)
    ss = Server(url)
    fileMd5 = hashlib.md5(fileBody)
    fileHash = fileMd5.hexdigest()
    fileEncoded = fileBody.encode('base64','strict')
    fileStripped = fileEncoded.replace('\n','')
    if sudo == True:
        uploadFile = ss.runCmds( 1, [ 'enable', 'bash timeout 2 echo "'+fileStripped+'" | base64 -d > /mnt/flash/'+fileName])
        copyFile = ss.runCmds( 1, ['enable', 'bash timeout 2 sudo su -c \"cp /mnt/flash/'+fileName+' '+fileLocation+fileName+'\" -s /bin/bash root', 'bash timeout 2 sudo chown root:eosadmin '+ fileLocation+fileName])
    else:
        uploadFile = ss.runCmds( 1, [ 'enable', 'bash timeout 2 echo "'+fileStripped+'" | base64 -d > '+fileLocation+fileName])
    #Md5 checksum
    checkHash = ss.runCmds( 1, ['enable', 'bash timeout 2 sudo cat '+fileLocation+fileName+' | md5sum'])[1]['messages'][0]
    if checkHash.startswith(fileHash):
      # Hash matches
      return True
    else:
      return True
      removeFile = ss.runCmds( 1, [ 'enable', 'bash timeout 2 sudo rm -rf '+fileLocation+fileName])
      raise hashException('Hash Mismatch')

### Rest of script
def main():
    ### Step 1 - build aliases file:
    aliases = uploadFile(aliasFileBody,'/etc/profile.d/','00-aliases.sh',sudo=True)
    if aliases == True:
        print '! aliases file uploaded successfully'
    ### Step 2 - create rc.eos file to auto-load aliases on-boot.
    rcEOS = uploadFile(rcFileBody,'/mnt/flash/','rc.eos')
    if rcEOS == True:
       print '! rc.eos file uploaded successfully'
    print 'ip http client local-interface '+updateSource


if __name__ == "__main__":
  main()
