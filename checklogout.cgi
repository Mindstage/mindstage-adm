#!/usr/bin/python -u

import cgi
#import cgitb
import os
import sh

#cgitb.enable()

MASTER_IP_PATH = "/var/mindstage/master-ip"
master_ip = "None"

if os.path.exists(MASTER_IP_PATH):
        with open(MASTER_IP_PATH, "r") as f:
                master_ip = f.read().strip()

if master_ip == "192.168.1.2":
        master_ip = "None"

client_ip = os.environ["REMOTE_ADDR"]

print "Content-Type: text/plain"
print ""

#Logout requested, logging out.
#NOTE: WORKS ONLY IF YOU ARE MASTER FOR OBVIOUS SECURITY REASONS
if "QUERY_STRING" in os.environ:
        if os.environ["QUERY_STRING"] == "1":
                if master_ip == client_ip:
                        master_ip = "None"
                        sh.sudo.updatemaster("0")
                        print "LogoutSuccessful"

#Return status of requesting PC. This to delete the
#"Logout Personell" icon from desktop in customer mode at boot.
if master_ip == client_ip:
        print "Yes"
else:
        print "No"
