#!/usr/bin/python -u

import cgi
#import cgitb
import os
import sh
import random
import re
import hashlib

#cgitb.enable()

#<<SENSITIVE INFO REDACTED>>
BOOT_ENCRYPTION_KEY = "0"
#<<SENSITIVE INFO REDACTED>>

PCFILE_PATH = "/var/mindstage/pcfiles/"

def verifyToken( verifydata, verifykey ):
	tokenresult = "0000000000"
	rematch = re.search(r'Digest username="([0123456789abcdef]{40})", realm="ipxe", nonce="([0123456789abcdef]{32})", uri="\/cgi-bin\/boot\.cgi\?auth", response="([0123456789abcdef]{32})"', verifydata)
	if rematch:
		vname = rematch.group(1)
		vnonce = rematch.group(2)
		vsubmit = rematch.group(3)
		if len(vname) == 40:
			if len(vnonce) == 32:
				if len(vsubmit) == 32:
					#Check so we get sane data from iPXE, in that case, decrypt the encrypted username, extract the card number, create hashed result, compare hashed result, and if both match
					#Return the card number to the calling function. If no sane data is received, or hash does not match, then return "0000000000".
					imac = vname[:12]
					iauth = vname[12:32]
					iip = vname[32:]
					decryptionArray = {}
					decryptionArray[int(verifykey[20:22],16)] = "0"
					decryptionArray[int(verifykey[22:24],16)] = "1"
					decryptionArray[int(verifykey[24:26],16)] = "2"
					decryptionArray[int(verifykey[26:28],16)] = "3"
					decryptionArray[int(verifykey[28:30],16)] = "4"
					decryptionArray[int(verifykey[30:32],16)] = "5"
					decryptionArray[int(verifykey[32:34],16)] = "6"
					decryptionArray[int(verifykey[34:36],16)] = "7"
					decryptionArray[int(verifykey[36:38],16)] = "8"
					decryptionArray[int(verifykey[38:40],16)] = "9"
					tempToken = ""
					for x in range(0, 10):
						ica = x*2
						keyInt = int( iauth[ica:ica+2] , 16) - int( verifykey[ica:ica+2] , 16)
						if keyInt in decryptionArray:
							tempToken = tempToken + str( decryptionArray[keyInt] )
					if len(tempToken) == 10:
						tokenHash = ""
						for x in range(0, 10):
							tcalc = 60 + int(tempToken[x:x+1])*2
							bcalc = 40 + (x*2)
							tokenHash = tokenHash + hex( int(verifykey[tcalc:tcalc+2],16) + int( verifykey[bcalc:bcalc+2],16) )[2:]
						m = hashlib.md5()
						n = hashlib.md5()
						o = hashlib.md5()
						m.update(vname + ":ipxe:" + iip + BOOT_ENCRYPTION_KEY + tokenHash + imac)
						o.update(verifykey)
						n.update(m.hexdigest() + ":" + o.hexdigest() + ":3acc8b65999c924f05d694ca26f6a2f7")
						if n.hexdigest() == vsubmit:
							tokenresult = tempToken
						else:
							tokenresult = "0000000000"
	return tokenresult

def form_print(s=""):
	print s.format(ip_port=ISCSI_SERVER, iqn=iqn, srvmsg=SERVER_MESSAGE, mpc=master_ip)

ISCSI_SERVER = "192.168.1.2:3260"

#<<SENSITIVE INFO REDACTED>>
MASTER_IQN = "0"
#<<SENSITIVE INFO REDACTED>>

MODE = "client"
SERVER_MESSAGE = "Var god skanna din bricka!"

#All valid personell.
#<<SENSITIVE INFO REDACTED>>
tagAuth = {}
#<<SENSITIVE INFO REDACTED>>

if "QUERY_STRING" in os.environ:
	menuToken = os.environ["QUERY_STRING"]
else:
	menuToken = ""
if "HTTP_AUTHORIZATION" in os.environ:
	authData = os.environ["HTTP_AUTHORIZATION"]
else:
	authData = ""

cardstack = list(range(17,127))
ecKey = ""
inkey = ""

MASTER_IP_PATH = "/var/mindstage/master-ip"
master_ip = "None"
if os.path.exists(MASTER_IP_PATH):
	with open(MASTER_IP_PATH, "r") as f:
		master_ip = f.read().strip()

if master_ip == "192.168.1.2":
	master_ip = "None"

client_ip = os.environ["REMOTE_ADDR"]
iqn = MASTER_IQN

#If any other PC is in master, disallow booting
if not master_ip == "None":
        if not master_ip == client_ip:
                menuToken = "failboot"

#iPXE either want to auth using authdata, or if authdata is empty, want to get authentication information
if menuToken == "auth":
	#Generate fake key incase file does not load. Load keyfile.
	random.shuffle(cardstack)
	for x in range(0, 40):
		inkey = inkey + hex(cardstack[x])[2:]
	if os.path.exists(PCFILE_PATH + client_ip + "_key.txt"):
		with open(PCFILE_PATH + client_ip + "_key.txt", "r") as kfile:
       			inkey = kfile.read().strip()
	if len(authData) > 1:
		cardData = verifyToken( authData, inkey )
		if cardData in tagAuth:
			#Client is in master mode. Thus scanning the tag means toggle it off.
			if client_ip == master_ip:
				master_ip = "None"
				sh.sudo.updatemaster("0")
				SERVER_MESSAGE = "Successfully set to CLIENT MODE from " + tagAuth[cardData]
			#No one is in master mode. Thus scanning the tag means toggle it on.
			elif master_ip == "None":
				master_ip = client_ip
				sh.sudo.updatemaster( str(int(re.split(r'\.', client_ip)[3]) - 50) )
				SERVER_MESSAGE = "Successfully set to MASTER MODE from " + tagAuth[cardData]
			#Someone else is in master. "Stealing" or turning off the master from him could have catastropic consequences.
			else:
				SERVER_MESSAGE = tagAuth[cardData] + ", you cant set MASTER MODE when " + master_ip + " is already master."
		else:
			SERVER_MESSAGE = "Felaktig bricka, Skanna igen!"
	else:
		z = hashlib.md5()
		z.update(inkey)
		menuToken = "printauth"


if client_ip == master_ip:
	MODE = "master"


if MODE not in ("master-usb", "master"):
	iqn = sh.sudo.mindcontrol("iscsi_create", client_ip)

#If any PC is in master, disallow any other PC from booting.
if menuToken == "failboot":
        form_print("Content-Type: text/plain")
        form_print()
        form_print("""#!ipxe
echo The computers are currently updating from master with IP {mpc}.
echo Note that the computer number is last octet minus 50.
echo They are currently closed for customers.
prompt Press any key to reboot.
reboot""")
#Booting into iscsi image
elif menuToken == "boot":
	form_print("Content-Type: text/plain")
	form_print()
	form_print("""#!ipxe
	set initiator-iqn {iqn}
	set keep-san 1
	set net0/gateway 0.0.0.0""")
	if MODE == "usb-boot":
    		# Used when installing.
    		form_print("""sanhook --drive 0x81 iscsi:{ip_port}:::{iqn}
		sanboot --no-describe --drive 0x80""")
	else:
		form_print("""sanboot iscsi:{ip_port}:::{iqn}""")
#Print authentication information so iPXE can auth
elif menuToken == "printauth":
	form_print("Status: 401 Unauthorized")
	form_print("WWW-Authenticate: Digest realm=\"ipxe\", nonce=\"" + z.hexdigest() + "\"")
	form_print("Content-Type: text/plain")
	form_print()
	form_print("401 Unauthorized")
#Normal boot, eg unspecified boot. Give opportunity to press key for card scan, or boot normally.
else:
	form_print("Content-Type: text/plain")
	form_print()
	form_print("#!ipxe")
	form_print("set servermessage {srvmsg}")
	random.shuffle(cardstack)
	for x in range(0, 40):
		ecKey = ecKey + hex(cardstack[x])[2:]
		form_print("set z" + str(x + 10) + ":int8 " + str(cardstack[x]))
	with open(PCFILE_PATH + client_ip + "_key.txt", "w") as eckeyfile:
		eckeyfile.write(ecKey)
	form_print("""imgfree
cpair --foreground 7 --background 0 0
cpair --foreground 7 --background 0 1
cpair --foreground 7 --background 0 2
cpair --foreground 7 --background 0 3
cpair --foreground 7 --background 0 4
cpair --foreground 7 --background 0 5
cpair --foreground 7 --background 0 6
cpair --foreground 7 --background 0 7
set lf:hex 0a
set lfs ${{lf:string}}${{lf:string}}${{lf:string}}
set lflong ${{lfs}}${{lfs}}${{lfs}}${{lfs}}${{lfs}}${{lfs}}${{lfs}}${{lf:string}}${{lf:string}}
set sp:hex 20
set ss ${{sp:string}}${{sp:string}}${{sp:string}}${{sp:string}}${{sp:string}}
set spaces ${{ss}}${{ss}}${{ss}}${{ss}}${{ss}}${{sp:string}}${{sp:string}}
:start
prompt --key=0x02 --timeout 5000 Waiting for client response {mpc}... && goto seboot || goto skipboot
:skipboot
chain http://192.168.1.2/cgi-bin/boot.cgi?boot
:seboot
set scancount:int8 0
clear completeinput
clear passwordinput
set deftimeout 0
:continue
menu ${{servermessage}}
item --key 0 0
item --key 1 1
item --key 2 2
item --key 3 3
item --key 4 4
item --key 5 5
item --key 6 6
item --key 7 7
item --key 8 8
item --key 9 9
item
item
item
item
item
item
item
item
item
item cancel
choose --default cancel --timeout ${{deftimeout}} input && goto process || goto start
:process
iseq ${{input}} cancel && goto start || goto cproc
:cproc
set deftimeout 56
set servermessage Var god skanna din bricka!
set temp:int8 ${{z1${{scancount}}}}
inc temp ${{z2${{input}}}}
set completeinput ${{completeinput}}${{temp:string}}
set pass:int8 ${{z3${{scancount}}}}
inc pass ${{z4${{input}}}}
set passwordinput ${{passwordinput}}${{pass:string}}
inc scancount
iseq ${{scancount}} 10 && goto doprompt || goto continue
:doprompt
prompt --key 0x0a --timeout 56 ${{spaces}}Var god skanna din bricka!${{lflong}}${{sp:string}} && goto doecho || goto start
:doecho
chain http://${{mac:hexraw}}${{completeinput:hexraw}}${{ip:hexraw}}:${{ip:hexraw}}${{bootpassword}}${{passwordinput:hexraw}}${{mac:hexraw}}@192.168.1.2/cgi-bin/boot.cgi?auth""")
	
exit()
