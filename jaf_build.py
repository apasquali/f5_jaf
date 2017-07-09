import netmiko
import sys
import socket
import time
import os
import logging
import logging.handlers
import datetime
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings()

###################################################################################

def build_f5 (VIPfqdn, VIPEnv, VIPip, VIPShort, VIPDesc, VIPEmail, CertType, VIPServicePort, inputFile):
	
	#Create Partition
	#create auth partition CCI_CERT
	command = "create auth partition " + VIPShort.upper() + "_" + VIPEnv.upper() + " description \"" + VIPDesc + "\""
	output = net_connect.send_command(command)
	if output != "":
		print ("When creating Partition Error:  " + output)
		d = {'time' : datetime.datetime.now().strftime("%m-%d.%H:%M:%S.%f"), 'executed_on' : socket.gethostname(), 'ScriptName' : os.path.basename(__file__), 'user' : user, 'enviroment_build' : VIPfqdn, 'command' : command, 'response' : output, 'message' : 'ERROR - Issues creating partition'}
		my_logger.debug(d)
		result = 1
		return result
	else:
		print ("Success creating Partition")
		d = {'time' : datetime.datetime.now().strftime("%m-%d.%H:%M:%S.%f"), 'executed_on' : socket.gethostname(), 'ScriptName' : os.path.basename(__file__), 'user' : user, 'enviroment_build' : VIPfqdn, 'command' : command, 'response' : output, 'message' : 'Success - Created Partition'}
		my_logger.debug(d)

	#Create Pools
	#create ltm pool /CCI_CERT/CCI_Cert_Static_20143 description "CCI Cert Static Content Web Servers Pool " monitor https_httpd
	command = "create ltm pool /" + VIPShort.upper() + "_" + VIPEnv.upper() + "/" + VIPShort.upper() + "_" + VIPEnv.capitalize() + "_Static_" + VIPServicePort + " monitor tcp"
	output = net_connect.send_command(command)
	if output != "":
		print ("When creating Pool Static Error:  " + output)
		d = {'time' : datetime.datetime.now().strftime("%m-%d.%H:%M:%S.%f"), 'executed_on' : socket.gethostname(), 'ScriptName' : os.path.basename(__file__), 'user' : user, 'enviroment_build' : VIPfqdn, 'command' : command, 'response' : output, 'message' : 'ERROR - Issues creating Static Pool'}
		my_logger.debug(d)
		result = 2
		return result
	else:
		print ("Success creating Static Pool")
		d = {'time' : datetime.datetime.now().strftime("%m-%d.%H:%M:%S.%f"), 'executed_on' : socket.gethostname(), 'ScriptName' : os.path.basename(__file__), 'user' : user, 'enviroment_build' : VIPfqdn, 'command' : command, 'response' : output, 'message' : 'Success - Created Static Pool'}
		my_logger.debug(d)

	#create ltm pool /CCI_CERT/CCI_Cert_20143 description "CCI Cert Application Servers Pool " monitor https_tomcat
	command = "create ltm pool /" + VIPShort.upper() + "_" + VIPEnv.upper() + "/" + VIPShort.upper() + "_" + VIPEnv.capitalize() + "_" + VIPServicePort + " monitor tcp"
	output = net_connect.send_command(command)
	if output != "":
		print ("When creating App Pool Error:  " + output)
		d = {'time' : datetime.datetime.now().strftime("%m-%d.%H:%M:%S.%f"), 'executed_on' : socket.gethostname(), 'ScriptName' : os.path.basename(__file__), 'user' : user, 'enviroment_build' : VIPfqdn, 'command' : command, 'response' : output, 'message' : 'ERROR - Issues creating App Pool'}
		my_logger.debug(d)
		result = 3
		return result
	else:
		d = {'time' : datetime.datetime.now().strftime("%m-%d.%H:%M:%S.%f"), 'executed_on' : socket.gethostname(), 'ScriptName' : os.path.basename(__file__), 'user' : user, 'enviroment_build' : VIPfqdn, 'command' : command, 'response' : output, 'message' : 'Success - Created App Pool'}
		my_logger.debug(d)
		print ("Success creating App Pool")

	#closing input file to reopen to find servers
	inputFile.close()
	inputFile = open(filein, 'r')
	lines = inputFile.readline().strip()

	#Adding Nodes and Pool Members
	while (lines != ""):
		serverDNS = lines.split(',')[1]
		serverDNS = serverDNS.lower()
		serverTestPart = serverDNS [:2]
		if (serverTestPart == "ar" or serverTestPart == "w2"):
			if DevDevEnvTest == True:
				serverDNS = serverDNS + ".devcorp.com"
				serverIP =  socket.gethostbyname(serverDNS)
			else:
				serverDNS = serverDNS + ".com"
				serverIP = socket.gethostbyname(serverDNS)

			#Adding Node
			#create ltm node server1.com address 172.x.x.x description "CCI Static Server"
			command = "create ltm node " + serverDNS.lower() + " address " + serverIP
			output = net_connect.send_command(command)
			if output != "":
				print ("When creating node:  " + output)
				d = {'time' : datetime.datetime.now().strftime("%m-%d.%H:%M:%S.%f"), 'executed_on' : socket.gethostname(), 'ScriptName' : os.path.basename(__file__), 'user' : user, 'enviroment_build' : VIPfqdn, 'command' : command, 'response' : output, 'message' : 'ERROR - When creating Node - ' + serverDNS}
				my_logger.debug(d)
				result = 4
				return result
			else:
				d = {'time' : datetime.datetime.now().strftime("%m-%d.%H:%M:%S.%f"), 'executed_on' : socket.gethostname(), 'ScriptName' : os.path.basename(__file__), 'user' : user, 'enviroment_build' : VIPfqdn, 'command' : command, 'response' : output, 'message' : 'Success - Created Node - ' + serverDNS}
				my_logger.debug(d)
			
			if 'wb' in serverDNS[3:5]:
				#Add static (DMZ) members to pools
				#modify ltm pool /CCI_CERT/CCI_Cert_Static_20143 members add { serverweb.com:20143 }
				command = "modify ltm pool /" + VIPShort.upper() + "_" + VIPEnv.upper() + "/" + VIPShort.upper() + "_" + VIPEnv.capitalize() + "_Static_" + VIPServicePort + " members add { " + serverDNS.lower() + ":" + VIPServicePort + " }"
				output = net_connect.send_command(command)
				if output != "":
					print ("When adding node Pool Static Error:  " + output)
					d = {'time' : datetime.datetime.now().strftime("%m-%d.%H:%M:%S.%f"), 'executed_on' : socket.gethostname(), 'ScriptName' : os.path.basename(__file__), 'user' : user, 'enviroment_build' : VIPfqdn, 'command' : command, 'response' : output, 'message' : 'ERROR - When adding members to static pool.'}
					my_logger.debug(d)
					result = 5
					return result
				else:
					d = {'time' : datetime.datetime.now().strftime("%m-%d.%H:%M:%S.%f"), 'executed_on' : socket.gethostname(), 'ScriptName' : os.path.basename(__file__), 'user' : user, 'enviroment_build' : VIPfqdn, 'command' : command, 'response' : output, 'message' : 'Success - Added members to static pool'}
					my_logger.debug(d)
			
			if 'ap' in serverDNS[3:5]:
				#Add app members to pools
				#Modify ltm pool /CCI_CERT/CCI_Cert_20143 members add { serverapp.com:20143 }
				command = "modify ltm pool /" + VIPShort.upper() + "_" + VIPEnv.upper() + "/" + VIPShort.upper() + "_" + VIPEnv.capitalize() + "_" + VIPServicePort + " members add { " + serverDNS.lower() + ":" + VIPServicePort + " }"
				output = net_connect.send_command(command)
				if output != "":
					print ("When adding node Pool App Error:  " + output)
					d = {'time' : datetime.datetime.now().strftime("%m-%d.%H:%M:%S.%f"), 'executed_on' : socket.gethostname(), 'ScriptName' : os.path.basename(__file__), 'user' : user, 'enviroment_build' : VIPfqdn, 'command' : command, 'response' : output, 'message' : 'ERROR - When adding members to app pool.'}
					my_logger.debug(d)
					result = 5
					return result
				else:
					d = {'time' : datetime.datetime.now().strftime("%m-%d.%H:%M:%S.%f"), 'executed_on' : socket.gethostname(), 'ScriptName' : os.path.basename(__file__), 'user' : user, 'enviroment_build' : VIPfqdn, 'command' : command, 'response' : output, 'message' : 'Success - Added members to app pool'}
					my_logger.debug(d)

		lines = inputFile.readline().strip()

	#Creating CSR
	#External
	if CertType.lower() == 'external':
		# create sys crypto key /CCI_CERT/cci-cert.com keysize 2048 gen-csr country US city 'San Antonio' state TX organization 'Company' ou 'IS' common-name vipfqdn.com email-address email@email.com
		if VIPEnv.lower == 'prod':
			command = "create sys crypto key /" + VIPShort.upper() + "_" + VIPEnv.upper() + "/" + VIPfqdn.lower() + " keysize 2048 gen-csr country US city 'San Antonio' state TX organization 'Company' ou 'IS' common-name " + VIPDNS.lower() + ".com email-address " + VIPEmail.lower()
			output = net_connect.send_command(command)
		else:
			command = "create sys crypto key /" + VIPShort.upper() + "_" + VIPEnv.upper() + "/" + VIPfqdn.lower() + " keysize 2048 gen-csr country US city 'San Antonio' state TX organization 'Company' ou 'IS' common-name " + VIPDNS.lower() + "-" + VIPEnv.lower() + ".com email-address " + VIPEmail.lower()
			output = net_connect.send_command(command)
		time.sleep(3)
		if output[:10] != "To sign a ":
			print ("When creating External Certificate:  " + output)
			d = {'time' : datetime.datetime.now().strftime("%m-%d.%H:%M:%S.%f"), 'executed_on' : socket.gethostname(), 'ScriptName' : os.path.basename(__file__), 'user' : user, 'enviroment_build' : VIPfqdn, 'command' : command, 'response' : output, 'message' : 'ERROR - Issues creating external CSR.'}
			my_logger.debug(d)
			result = 6
			return result
		else:
			#modifying string to remove extra lines at top
			output = output.split("\n",2)[2]
			certFile = open(VIPShort + "-" + VIPEnv.lower() + "-external.com.csr",'w')
			certFile.write(output)
			certFile.close()
			print ("*******************************************")
			print (output)
			print ("*******************************************")
			print ("Success creating external Certificate")
			d = {'time' : datetime.datetime.now().strftime("%m-%d.%H:%M:%S.%f"), 'executed_on' : socket.gethostname(), 'ScriptName' : os.path.basename(__file__), 'user' : user, 'enviroment_build' : VIPfqdn, 'command' : command, 'response' : output, 'message' : 'Success - Created External CSR'}
			my_logger.debug(d)
	else:
		#create sys crypto key /CCI_CERT/cci-cert..com keysize 2048 gen-csr country US city 'San Antonio' state TX organization 'Company' ou '"  +  f5Device  +  "' common-name vipfqdn.com email-address email@email.com
		if VIPEnv == 'prod':
			command = "create sys crypto key /" + VIPShort.upper() + "_" + VIPEnv.upper() + "/" + VIPfqdn.lower() + " keysize 2048 gen-csr country US city 'San Antonio' state TX organization 'Company' ou '" + f5Device + "' common-name " + VIPShort.lower() + ".com email-address " + VIPEmail.lower()
			output = net_connect.send_command(command)
		else:
			command = "create sys crypto key /" + VIPShort.upper() + "_" + VIPEnv.upper() + "/" + VIPfqdn.lower() + " keysize 2048 gen-csr country US city 'San Antonio' state TX organization 'Company' ou '" + f5Device + "' common-name " + VIPShort.lower() + "-" + VIPEnv.upper() + ".com email-address " + VIPEmail.lower()
			output = net_connect.send_command(command)
		time.sleep(3)
		if output[:10] != "To sign a ":
			print ("When creating Internal Certificate:  " + output)
			d = {'time' : datetime.datetime.now().strftime("%m-%d.%H:%M:%S.%f"), 'executed_on' : socket.gethostname(), 'ScriptName' : os.path.basename(__file__), 'user' : user, 'enviroment_build' : VIPfqdn, 'command' : command, 'response' : output, 'message' : 'ERROR - Issues creating internal CSR'}
			my_logger.debug(d)
			result = 6
			return result
		else:
			#modifying string to remove extra lines at top
			output = output.split("\n",2)[2]
			certFile = open(VIPShort + "-" + VIPEnv.lower() + "-internal.com.csr",'w')
			certFile.write(output)
			certFile.close()
			print ("*******************************************")
			print (output)
			print ("*******************************************")
			print ("Success creating internal Certificate")
			d = {'time' : datetime.datetime.now().strftime("%m-%d.%H:%M:%S.%f"), 'executed_on' : socket.gethostname(), 'ScriptName' : os.path.basename(__file__), 'user' : user, 'enviroment_build' : VIPfqdn, 'command' : command, 'response' : output, 'message' : 'Success - Created internal CSR'}
			my_logger.debug(d)

	#Client SSL
	# create ltm profile client-ssl /CCI_CERT/clientssl-cci-cert  ciphers '-ALL:!SSLv3:!SSLv2:!TLSv1:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-CBC-SHA:ECDHE-RSA-AES256-CBC-SHA' defaults-from clientssl
	command = " create ltm profile client-ssl /" + VIPShort.upper() + "_" + VIPEnv.upper() + "/clientssl-" + VIPShort.lower() + "-" + VIPEnv.lower() + "  ciphers '-ALL:!SSLv3:!SSLv2:!TLSv1:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-CBC-SHA:ECDHE-RSA-AES256-CBC-SHA' defaults-from clientssl"
	output = net_connect.send_command(command)
	if output != "":
		print ("When adding Client SSL Error:  " + output)
		d = {'time' : datetime.datetime.now().strftime("%m-%d.%H:%M:%S.%f"), 'executed_on' : socket.gethostname(), 'ScriptName' : os.path.basename(__file__), 'user' : user, 'enviroment_build' : VIPfqdn, 'command' : command, 'response' : output, 'message' : 'ERROR - Issues creating Client SSL'}
		my_logger.debug(d)
		result = 7
		return result
	else:
		print ("Success creating SSL Profile")
		d = {'time' : datetime.datetime.now().strftime("%m-%d.%H:%M:%S.%f"), 'executed_on' : socket.gethostname(), 'ScriptName' : os.path.basename(__file__), 'user' : user, 'enviroment_build' : VIPfqdn, 'command' : command, 'response' : output, 'message' : 'Success - Created SSL profile'}
		my_logger.debug(d)
			
	#SNAT
	# create ltm snatpool /CCI_CERT/CCI_Cert_SNAT_Pool members add { 172.x.x.x }
	command = "create ltm snatpool /" + VIPShort.upper() + "_" + VIPEnv.upper() + "/" + VIPShort.upper() + "_" + VIPEnv.capitalize() + "_SNAT_Pool members add { " + VIPip + " }"
	output = net_connect.send_command(command)
	if output != "":
		print ("When adding SNAT Error:  " + output)
		d = {'time' : datetime.datetime.now().strftime("%m-%d.%H:%M:%S.%f"), 'executed_on' : socket.gethostname(), 'ScriptName' : os.path.basename(__file__), 'user' : user, 'enviroment_build' : VIPfqdn, 'command' : command, 'response' : output, 'message' : 'ERROR - Issues creating SNAT'}
		my_logger.debug(d)
		result = 8
		return result
	else:
		print ("Success creating SNAT")
		d = {'time' : datetime.datetime.now().strftime("%m-%d.%H:%M:%S.%f"), 'executed_on' : socket.gethostname(), 'ScriptName' : os.path.basename(__file__), 'user' : user, 'enviroment_build' : VIPfqdn, 'command' : command, 'response' : output, 'message' : 'Success - Created SNAT'}
		my_logger.debug(d)

	#Policy
	# create ltm policy /CCI_CERT/cci_cert_tomcat_redirect controls add { forwarding } requires add { http } rules add { cci_cert_tomcat_redirect_rule { ordinal 1 conditions add { 0 { http-uri path starts-with values { /cci_api/ } } } actions add { 0 { forward select pool /CCI_CERT/CCI_Cert_20143 } } } cci_cert_index_redirect_rule { ordinal 2 conditions add { 0 { http-uri path equals values { / } } } actions add { 0 { http-uri replace path /index.html } } } cci_cert_catchall_rule { ordinal 3 conditions add { 0 { http-uri path starts-with values { / } } } actions add { 0 { forward select pool /CCI_CERT/CCI_Cert_Static_20143 } } } } strategy first-match
	command = "create ltm policy /" + VIPShort.upper() + "_" + VIPEnv.upper() + "/" + VIPShort.lower() + "_" + VIPEnv.lower() + "_tomcat_redirect controls add { forwarding } requires add { http } rules add { " + VIPShort.lower() + "_" + VIPEnv.lower() + "_tomcat_redirect_rule { ordinal 1 conditions add { 0 { http-uri path starts-with values { /" + VIPShort.lower() + "_api/ } } } actions add { 0 { forward select pool /" + VIPShort.upper() + "_" + VIPEnv.upper() + "/" + VIPShort.upper() + "_" + VIPEnv.capitalize() + "_" + VIPServicePort + " } } } " + VIPShort.lower() + "_" + VIPEnv.lower() + "_index_redirect_rule { ordinal 2 conditions add { 0 { http-uri path equals values { / } } } actions add { 0 { http-header remove name Cookie } 1 { http-uri replace path /index.html } } } " + VIPShort.lower() + "_" + VIPEnv.lower() + "_catchall_rule { ordinal 3 conditions add { 0 { http-uri path starts-with values { / } } } actions add { 0 { http-header remove name Cookie } 1 { forward select pool /" + VIPShort.upper() + "_" + VIPEnv.upper() + "/" + VIPShort.upper() + "_" + VIPEnv.capitalize() + "_Static_" + VIPServicePort + " } } } } strategy first-match"
	output = net_connect.send_command(command)
	if output != "":
		print ("When adding Policy Error:  " + output)
		d = {'time' : datetime.datetime.now().strftime("%m-%d.%H:%M:%S.%f"), 'executed_on' : socket.gethostname(), 'ScriptName' : os.path.basename(__file__), 'user' : user, 'enviroment_build' : VIPfqdn, 'command' : command, 'response' : output, 'message' : 'ERROR - Issues creating policy.'}
		my_logger.debug(d)
		result = 9
		return result
	else:
		print ("Success creating Policy")
		d = {'time' : datetime.datetime.now().strftime("%m-%d.%H:%M:%S.%f"), 'executed_on' : socket.gethostname(), 'ScriptName' : os.path.basename(__file__), 'user' : user, 'enviroment_build' : VIPfqdn, 'command' : command, 'response' : output, 'message' : 'Success - Created Policy'}
		my_logger.debug(d)

	#VIP
	#443 VIP
	# create ltm virtual /CCI_CERT/CCI_Cert_443 destination /CCI_CERT/172.x.x.x:443 ip-protocol tcp profiles add { /CCI_CERT/clientssl-cci-cert { context clientside } http-tomcat { } oneconnect { } serverssl { context serverside } tcp-lan-optimized { } } pool /CCI_CERT/CCI_Cert_Static_20143 persist replace-all-with { cookie-tomcat { default yes } } fallback-persistence source-tomcat source-address-translation { pool /CCI_CERT/CCI_Cert_SNAT_Pool type snat } policies add { /CCI_CERT/cci_cert_tomcat_redirect } description "CCI Cert Virtual Server"
	command = "create ltm virtual /" + VIPShort.upper() + "_" + VIPEnv.upper() + "/" + VIPShort.upper() + "_" + VIPEnv.capitalize() + "_443 destination /" + VIPShort.upper() + "_" + VIPEnv.upper() + "/" + VIPip + ":443 ip-protocol tcp profiles add { /" + VIPShort.upper() + "_" + VIPEnv.upper() + "/clientssl-" + VIPShort.lower() + "-" + VIPEnv.lower() + " { context clientside } http-tomcat { } oneconnect { } serverssl { context serverside } tcp-lan-optimized { } } pool /" + VIPShort.upper() + "_" + VIPEnv.upper() + "/" + VIPShort.upper() + "_" + VIPEnv.capitalize() + "_Static_" + VIPServicePort + " persist replace-all-with { cookie-tomcat { default yes } } fallback-persistence source-tomcat source-address-translation { pool /" + VIPShort.upper() + "_" + VIPEnv.upper() + "/" + VIPShort.upper() + "_" + VIPEnv.capitalize() + "_SNAT_Pool type snat } policies add { /" + VIPShort.upper() + "_" + VIPEnv.upper() + "/" + VIPShort.lower() + "_" + VIPEnv.lower() + "_tomcat_redirect } description \"" + VIPShort.upper() + " " + VIPEnv.capitalize() + " Virtual Server\""
	output = net_connect.send_command(command)
	if output != "":
		print ("When adding 443-https VIP Error:  " + output)
		d = {'time' : datetime.datetime.now().strftime("%m-%d.%H:%M:%S.%f"), 'executed_on' : socket.gethostname(), 'ScriptName' : os.path.basename(__file__), 'user' : user, 'enviroment_build' : VIPfqdn, 'command' : command, 'response' : output, 'message' : 'ERROR - Issues creating 443 VIP.'}
		my_logger.debug(d)
		result = 10
		return result
	else:
		print ("Success creating 443 VIP")
		d = {'time' : datetime.datetime.now().strftime("%m-%d.%H:%M:%S.%f"), 'executed_on' : socket.gethostname(), 'ScriptName' : os.path.basename(__file__), 'user' : user, 'enviroment_build' : VIPfqdn, 'command' : command, 'response' : output, 'message' : 'Success - Created 443 VIP'}
		my_logger.debug(d)

	#80 VIP
	# create ltm virtual /CCI_CERT/CCI_Cert_80 destination /CCI_CERT/172.x.x.x:80 ip-protocol tcp profiles add { http { } tcp-lan-optimized { } } pool /CCI_CERT/CCI_Cert_Static_20143  policies add { /Common/HTTPtoHTTPS-Policy } description "CCI Cert HTTP Redirection Virtual Server"
	command = "create ltm virtual1 /" + VIPShort.upper() + "_" + VIPEnv.upper() + "/" + VIPShort.upper() + "_" + VIPEnv.capitalize() + "_80 destination /" + VIPShort.upper() + "_" + VIPEnv.upper() + "/" + VIPip + ":80 ip-protocol tcp profiles add { http { } tcp-lan-optimized { } } pool /" + VIPShort.upper() + "_" + VIPEnv.upper() + "/" + VIPShort.upper() + "_" + VIPEnv.capitalize() + "_Static_" + VIPServicePort + "  policies add { /Common/HTTPtoHTTPS-Policy } description \"" + VIPShort.upper() + " " + VIPEnv.capitalize() + " HTTP Redirection Virtual Server\""
	output = net_connect.send_command(command)
	if output != "":
		print ("When adding 80-http VIP Error:  " + output)
		d = {'time' : datetime.datetime.now().strftime("%m-%d.%H:%M:%S.%f"), 'executed_on' : socket.gethostname(), 'ScriptName' : os.path.basename(__file__), 'user' : user, 'enviroment_build' : VIPfqdn, 'command' : command, 'response' : output, 'message' : 'ERROR - Issues creating 80 VIP.'}
		my_logger.debug(d)
		result = 11
		return result
	else:
		print ("Success creating 80 VIP")
		d = {'time' : datetime.datetime.now().strftime("%m-%d.%H:%M:%S.%f"), 'executed_on' : socket.gethostname(), 'ScriptName' : os.path.basename(__file__), 'user' : user, 'enviroment_build' : VIPfqdn, 'command' : command, 'response' : output, 'message' : 'Success - Created 80 VIP'}
		my_logger.debug(d)
	
	result = 0
	return result

###########################################################################################################

def remove_f5 (VIPfqdn, VIPEnv, VIPip, VIPShort, VIPDesc, VIPEmail, CertType, VIPServicePort, inputFile, results):
	
	print ("**********************************")
	print (" _____                           *")
	print ("|_   _|                          *")
	print ("  | |  ___ ___ _   _  ___  ___   *")
	print ("  | | / __/ __| | | |/ _ \/ __|  *")
	print (" _| |_\__ \__ \ |_| |  __/\__ \  *")
	print ("|_____|___/___/\__,_|\___||___/  *")
	print ("**********************************")
	print ("*      Backing out changes       *")
	print ("**********************************")
		
	if results > 10:
		#443 VIP
		#delete ltm virtual /CCI_CERT/CCI_Cert_443 destination /CCI_CERT/172.x.x.x:443"
		command = "delete ltm virtual /" + VIPShort.upper() + "_" + VIPEnv.upper() + "/" + VIPShort.upper() + "_" + VIPEnv.capitalize() + "_443"
		output = net_connect.send_command(command)
		if output != "":
			print ("When deleting 443-https VIP Error:  " + output)
			d = {'time' : datetime.datetime.now().strftime("%m-%d.%H:%M:%S.%f"), 'executed_on' : socket.gethostname(), 'ScriptName' : os.path.basename(__file__), 'user' : user, 'enviroment_build' : VIPfqdn, 'command' : command, 'response' : output, 'message' : 'ERROR - Issues deleting 443 VIP.'}
			my_logger.debug(d)
		else:
			print ("Success removing 443 VIP")
			d = {'time' : datetime.datetime.now().strftime("%m-%d.%H:%M:%S.%f"), 'executed_on' : socket.gethostname(), 'ScriptName' : os.path.basename(__file__), 'user' : user, 'enviroment_build' : VIPfqdn, 'command' : command, 'response' : output, 'message' : 'Success - Removing 443 VIP'}
			my_logger.debug(d)

	if results > 9:
		#Policy
		# delete ltm policy /CCI_CERT/cci_cert_tomcat_redirect
		command = "delete ltm policy /" + VIPShort.upper() + "_" + VIPEnv.upper() + "/" + VIPShort.lower() + "_" + VIPEnv.lower() + "_tomcat_redirect"
		output = net_connect.send_command(command)
		if output != "":
			print ("When deleting Policy Error:  " + output)
			d = {'time' : datetime.datetime.now().strftime("%m-%d.%H:%M:%S.%f"), 'executed_on' : socket.gethostname(), 'ScriptName' : os.path.basename(__file__), 'user' : user, 'enviroment_build' : VIPfqdn, 'command' : command, 'response' : output, 'message' : 'ERROR - Issues deleting policy.'}
			my_logger.debug(d)
		else:
			print ("Success removing policy")
			d = {'time' : datetime.datetime.now().strftime("%m-%d.%H:%M:%S.%f"), 'executed_on' : socket.gethostname(), 'ScriptName' : os.path.basename(__file__), 'user' : user, 'enviroment_build' : VIPfqdn, 'command' : command, 'response' : output, 'message' : 'Success - Removing Policy'}
			my_logger.debug(d)

	if results > 8:
		#SNAT
		# delete ltm snatpool /CCI_CERT/CCI_Cert_SNAT_Pool members add { 172.x.x.x }
		command = "delete ltm snatpool /" + VIPShort.upper() + "_" + VIPEnv.upper() + "/" + VIPShort.upper() + "_" + VIPEnv.capitalize() + "_SNAT_Pool"
		output = net_connect.send_command(command)
		if output != "":
			print ("When deleting SNAT Error:  " + output)
			d = {'time' : datetime.datetime.now().strftime("%m-%d.%H:%M:%S.%f"), 'executed_on' : socket.gethostname(), 'ScriptName' : os.path.basename(__file__), 'user' : user, 'enviroment_build' : VIPfqdn, 'command' : command, 'response' : output, 'message' : 'ERROR - Issues deleting SNAT.'}
			my_logger.debug(d)
		else:
			print ("Success removing SNAT")
			d = {'time' : datetime.datetime.now().strftime("%m-%d.%H:%M:%S.%f"), 'executed_on' : socket.gethostname(), 'ScriptName' : os.path.basename(__file__), 'user' : user, 'enviroment_build' : VIPfqdn, 'command' : command, 'response' : output, 'message' : 'Success - Removing SNAT'}
			my_logger.debug(d)
		
	if results > 7:
		#Client SSL
		# delete ltm profile client-ssl /CCI_CERT/clientssl-cci-cert
		command = "delete ltm profile client-ssl /" + VIPShort.upper() + "_" + VIPEnv.upper() + "/clientssl-" + VIPShort.lower() + "-" + VIPEnv.lower()
		output = net_connect.send_command(command)
		if output != "":
			print ("When deleting Client SSL Error:  " + output)
			d = {'time' : datetime.datetime.now().strftime("%m-%d.%H:%M:%S.%f"), 'executed_on' : socket.gethostname(), 'ScriptName' : os.path.basename(__file__), 'user' : user, 'enviroment_build' : VIPfqdn, 'command' : command, 'response' : output, 'message' : 'ERROR - Issues deleting client SSL.'}
			my_logger.debug(d)
		else:
			print ("Success removing Client SSL")
			d = {'time' : datetime.datetime.now().strftime("%m-%d.%H:%M:%S.%f"), 'executed_on' : socket.gethostname(), 'ScriptName' : os.path.basename(__file__), 'user' : user, 'enviroment_build' : VIPfqdn, 'command' : command, 'response' : output, 'message' : 'Success - Removing Client SSL'}
			my_logger.debug(d)

	if results > 6:
		#Certificate
		#delete sys crypto key /CCI_CERT/cci-cert..com.key
		command = "delete sys crypto key /" + VIPShort.upper() + "_" + VIPEnv.upper() + "/" + VIPfqdn.lower() + ".key"
		output = net_connect.send_command(command)
		if output != "":
			print ("When deleting SSL Certificate:  " + output)
			d = {'time' : datetime.datetime.now().strftime("%m-%d.%H:%M:%S.%f"), 'executed_on' : socket.gethostname(), 'ScriptName' : os.path.basename(__file__), 'user' : user, 'enviroment_build' : VIPfqdn, 'command' : command, 'response' : output, 'message' : 'ERROR - Issues deleting certificate.'}
			my_logger.debug(d)
		else:
			print ("Success removing Certificate")
			d = {'time' : datetime.datetime.now().strftime("%m-%d.%H:%M:%S.%f"), 'executed_on' : socket.gethostname(), 'ScriptName' : os.path.basename(__file__), 'user' : user, 'enviroment_build' : VIPfqdn, 'command' : command, 'response' : output, 'message' : 'Success - Removing CSR'}
			my_logger.debug(d)

	if results > 3:
		#delete ltm pool /CCI_CERT/CCI_Cert_20143 description "CCI Cert Application Servers Pool " monitor https_tomcat
		command = "delete ltm pool /" + VIPShort.upper() + "_" + VIPEnv.upper() + "/" + VIPShort.upper() + "_" + VIPEnv.capitalize() + "_" + VIPServicePort
		output = net_connect.send_command(command)
		if output != "":
			print ("When deleting Pool Static Error:  " + output)
			d = {'time' : datetime.datetime.now().strftime("%m-%d.%H:%M:%S.%f"), 'executed_on' : socket.gethostname(), 'ScriptName' : os.path.basename(__file__), 'user' : user, 'enviroment_build' : VIPfqdn, 'command' : command, 'response' : output, 'message' : 'ERROR - Issues deleting app pool.'}
			my_logger.debug(d)
		else:
			print ("Success removing application pool")
			d = {'time' : datetime.datetime.now().strftime("%m-%d.%H:%M:%S.%f"), 'executed_on' : socket.gethostname(), 'ScriptName' : os.path.basename(__file__), 'user' : user, 'enviroment_build' : VIPfqdn, 'command' : command, 'response' : output, 'message' : 'Success - Removing App Pool'}
			my_logger.debug(d)
	
	if results > 2:
		#Delete Pools
		#delete ltm pool /CCI_CERT/CCI_Cert_Static_20143 description "CCI Cert Static Content Web Servers Pool " monitor https_httpd
		command = "delete ltm pool /" + VIPShort.upper() + "_" + VIPEnv.upper() + "/" + VIPShort.upper() + "_" + VIPEnv.capitalize() + "_Static_" + VIPServicePort
		output = net_connect.send_command(command)
		if output != "":
			print ("When deleting Pool Static Error:  " + output)
			d = {'time' : datetime.datetime.now().strftime("%m-%d.%H:%M:%S.%f"), 'executed_on' : socket.gethostname(), 'ScriptName' : os.path.basename(__file__), 'user' : user, 'enviroment_build' : VIPfqdn, 'command' : command, 'response' : output, 'message' : 'ERROR - Issues deleting Static Pool.'}
			my_logger.debug(d)
		else:
			print ("Success removing static/web pool")
			d = {'time' : datetime.datetime.now().strftime("%m-%d.%H:%M:%S.%f"), 'executed_on' : socket.gethostname(), 'ScriptName' : os.path.basename(__file__), 'user' : user, 'enviroment_build' : VIPfqdn, 'command' : command, 'response' : output, 'message' : 'Success - Removing Static Pool'}
			my_logger.debug(d)
	
	if results > 4:
		#closing input file to reopen to find servers
		inputFile.close()
		inputFile = open(filein, 'r')
		lines = inputFile.readline().strip()

		#Delete Nodes
		while (lines != ""):
			serverDNS = lines.split(',')[1]
			serverDNS = serverDNS.lower()
			serverTestPart = serverDNS [:2]
			if (serverTestPart == "ar" or serverTestPart == "w2"):
				if DevDevEnvTest == True:
					serverDNS = serverDNS + ".devcorp.com"
				else:
					serverDNS = serverDNS + ".com"

				#Delete Node
				#delete ltm node server1..com address 172.x.x.x description "CCI Static Server"
				command = "delete ltm node " + serverDNS.lower()
				output = net_connect.send_command(command)
				if output != "":
					print ("When deleting node:  " + output)
					d = {'time' : datetime.datetime.now().strftime("%m-%d.%H:%M:%S.%f"), 'executed_on' : socket.gethostname(), 'ScriptName' : os.path.basename(__file__), 'user' : user, 'enviroment_build' : VIPfqdn, 'command' : command, 'response' : output, 'message' : 'ERROR - Issues deleting node: ' + serverDNS}
					my_logger.debug(d)
				else:
					print ("Success removing node:  " + serverDNS.lower())
					d = {'time' : datetime.datetime.now().strftime("%m-%d.%H:%M:%S.%f"), 'executed_on' : socket.gethostname(), 'ScriptName' : os.path.basename(__file__), 'user' : user, 'enviroment_build' : VIPfqdn, 'command' : command, 'response' : output, 'message' : 'Success - Removing Node - ' + serverDNS}
					my_logger.debug(d)
				
			lines = inputFile.readline().strip()
			
	if results > 1:
		#Delete Partition
		command = "delete auth partition " + VIPShort.upper() + "_" + VIPEnv.upper()
		output = net_connect.send_command(command)
		if output != "":
			print ("When deleting Partition Error:  " + output)
			d = {'time' : datetime.datetime.now().strftime("%m-%d.%H:%M:%S.%f"), 'executed_on' : socket.gethostname(), 'ScriptName' : os.path.basename(__file__), 'user' : user, 'enviroment_build' : VIPfqdn, 'command' : command, 'response' : output, 'message' : 'ERROR - Issues deleting Partition.'}
			my_logger.debug(d)
		else:
			print ("Success removing partition")
			d = {'time' : datetime.datetime.now().strftime("%m-%d.%H:%M:%S.%f"), 'executed_on' : socket.gethostname(), 'ScriptName' : os.path.basename(__file__), 'user' : user, 'enviroment_build' : VIPfqdn, 'command' : command, 'response' : output, 'message' : 'Success - Removing Partition'}
			my_logger.debug(d)
	
###########################################################################################################

my_logger = logging.getLogger('MyLogger')
my_logger.setLevel(logging.DEBUG)

handler = logging.handlers.SysLogHandler(address = ('172.x.x.x',514))
my_logger.addHandler(handler)

try:
	filein = sys.argv[1]
	inputFile = open(filein, 'r')
	lines = inputFile.readline().strip()
except:
	print "Input file not found"
	d = {'time' : datetime.datetime.now().strftime("%m-%d.%H:%M:%S.%f"), 'executed_on' : socket.gethostname(), 'ScriptName' : os.path.basename(__file__), 'user' : user, 'enviroment_build' : VIPfqdn, 'command' : command, 'response' : output, 'message' : 'Error - Input file not found'}
	my_logger.debug(d)

while (lines != ""):
	stringTest = lines.split(',')[0]
	if stringTest.lower() == "f5":
		VIPfqdn = lines.split(',')[1]
		VIPEnv = lines.split(',')[2]
		VIPShort = lines.split(',')[5]
		VIPDesc = lines.split(',')[6]
		VIPEmail = lines.split(',')[7]
		CertType = lines.split(',')[8]
	lines = inputFile.readline().strip()
	
#testing a VIP FQDN name for devcorp
#if devcorp is found, building int devcorp
#otherwise building in dev, cert, prod
try:
	VIPip =  socket.gethostbyname(VIPfqdn)
	DevDevEnvTest = False
except:
	print "VIP fqdn was not found in DNS"
	d = {'time' : datetime.datetime.now().strftime("%m-%d.%H:%M:%S.%f"), 'executed_on' : socket.gethostname(), 'ScriptName' : os.path.basename(__file__), 'message' : 'ERROR - VIP fqdn was not found in DNS'}
	my_logger.debug(d)
	sys.exit(126)
	
if 'devcorp..com' in VIPfqdn:
	DevDevEnvTest = True

if VIPfqdn == "" or VIPEnv == "" or VIPip == "" or VIPShort == "" or VIPDesc == "" or VIPEmail == "" or VIPDesc == "" or CertType == "":
	print "issues with input file, missing arguments"
	d = {'time' : datetime.datetime.now().strftime("%m-%d.%H:%M:%S.%f"), 'executed_on' : socket.gethostname(), 'ScriptName' : os.path.basename(__file__), 'message' : 'ERROR - Issues with input file, missing arguments.'}
	my_logger.debug(d)
	sys.exit(126)

if VIPEnv.lower() == 'cert':
	#VIPEnv = "cert"
	VIPServicePort = "20143"
	f5Device = "f5-cert.com"
elif VIPEnv.lower() == 'dev' and DevDevEnvTest == True:
	#VIPEnv = "dev"
	VIPServicePort = "20143"
	f5Device = "f5-devops.com"
elif VIPEnv.lower() == 'dev':
	VIPServicePort = "20143"
	f5Device = "f5-dev.com"
elif VIPEnv.lower() == 'prod':
	VIPEnv = "prod"
	VIPServicePort = "30143"
	f5Device = "f5-prod.com"
elif VIPEnv.lower() == 'uat':
	#VIPEnv = "uat"
	VIPServicePort = "20143"
	f5Device = "f5-uat.com"
else:
	print "Issues with environment in file name"
	d = {'time' : datetime.datetime.now().strftime("%m-%d.%H:%M:%S.%f"), 'executed_on' : socket.gethostname(), 'ScriptName' : os.path.basename(__file__), 'message' : 'ERROR - Issues with enviroment in file name.'}
	my_logger.debug(d)
	sys.exit(126)

try:
	user = os.environ['SrvUser']
except:
	print ("User enviroment variable not set. Exiting")
	d = {'time' : datetime.datetime.now().strftime("%m-%d.%H:%M:%S.%f"), 'executed_on' : socket.gethostname(), 'ScriptName' : os.path.basename(__file__), 'message' : 'ERROR - User enviroment variable not set.'}
	my_logger.debug(d)
	sys.exit(126)
try:
	passwd = os.environ['SrvPassword']
except:
	print ("Password enviroment variable not set. Exiting")
	d = {'time' : datetime.datetime.now().strftime("%m-%d.%H:%M:%S.%f"), 'executed_on' : socket.gethostname(), 'ScriptName' : os.path.basename(__file__), 'user' : user, 'enviroment_build' : VIPfqdn, 'message' : 'ERROR - Password enviroment veriable not set.'}
	my_logger.debug(d)
	sys.exit(126)

f5_ssh = {
'device_type': 'f5_ltm',
'ip':   f5Device,
'username': user,
'password': passwd,
}

SSHClass = netmiko.ssh_dispatcher(f5_ssh['device_type'])
try:
	net_connect = SSHClass(**f5_ssh)
except:
	print "Issues connecting to F5. " + f5Device
	d = {'time' : datetime.datetime.now().strftime("%m-%d.%H:%M:%S.%f"), 'executed_on' : socket.gethostname(), 'ScriptName' : os.path.basename(__file__), 'user' : user, 'enviroment_build' : VIPfqdn, 'message' : 'ERROR - Issues connecting to F5.'}
	my_logger.debug(d)
	sys.exit(126)
	
d = {'time' : datetime.datetime.now().strftime("%m-%d.%H:%M:%S.%f"), 'executed_on' : socket.gethostname(), 'ScriptName' : os.path.basename(__file__), 'user' : user, 'enviroment_build' : VIPfqdn, 'message' : 'Starting ' + VIPfqdn + ' F5 build'}
my_logger.debug(d)

results = build_f5 (VIPfqdn, VIPEnv, VIPip, VIPShort, VIPDesc, VIPEmail, CertType, VIPServicePort, inputFile)

if results == 0:

	if CertType.lower() != 'external':
		certFile = open(VIPShort + "-" + VIPEnv.lower() + "-internal..com.csr",'r')
		csr_data = certFile.read()
		if VIPEnv.lower() == 'prod':
			url = "https://prod-pki.com/add-pkcs10-request.xuda"
			form_data = {'ca': 'e34315047a15d365a52eec1ba7e9147', 'domainID': '6d549147fe146679dc973b322b37a1db568d7e', 'pkcs10_input': csr_data}
		else:
			url = "https://cert-pki.com/add-pkcs10-request.xuda"
			form_data = {'ca': '78eec670f7dcbbcf9468cfa4b0da655', 'domainID': 'd7d6ffec3a9ab8be95f6d4685f6b75a16d7232', 'pkcs10_input': csr_data}
			
		response = requests.post(url, verify = False, data=form_data)
		if not 'Your information has been submitted.' in response.content:
			rint ("Issues with submitting CSR to pki.")
			d = {'time' : datetime.datetime.now().strftime("%m-%d.%H:%M:%S.%f"), 'executed_on' : socket.gethostname(), 'ScriptName' : os.path.basename(__file__), 'user' : user, 'enviroment_build' : VIPfqdn, 'url' : response.url, 'message' : 'Issues with submitting CSR to pki.'}
			my_logger.debug(d)
		else:
			print ("Success submitting CSR to pki.")
			d = {'time' : datetime.datetime.now().strftime("%m-%d.%H:%M:%S.%f"), 'executed_on' : socket.gethostname(), 'ScriptName' : os.path.basename(__file__), 'user' : user, 'enviroment_build' : VIPfqdn, 'url' : response.url, 'message' : 'Success - Submitting CSR to pki'}
			my_logger.debug(d)
		certFile.close()
		
	print ("*****************************************")
	print ("* ____                              _ _ *")
	print ("*/ ___| _   _  ___ ___ ___  ___ ___| | |*")
	print ("*\___ \| | | |/ __/ __/ _ \/ __/ __| | |*")
	print ("* ___) | |_| | (_| (_|  __/\__ \__ \_|_|*")
	print ("*|____/ \__,_|\___\___\___||___/___(_|_)*")
	print ("*****************************************")
	d = {'time' : datetime.datetime.now().strftime("%m-%d.%H:%M:%S.%f"), 'executed_on' : socket.gethostname(), 'ScriptName' : os.path.basename(__file__), 'user' : user, 'enviroment_build' : VIPfqdn, 'message' : 'Successfuly built - ' + VIPfqdn}
	my_logger.debug(d)
	
elif results > 0:
	remove_f5 (VIPfqdn, VIPEnv, VIPip, VIPShort, VIPDesc, VIPEmail, CertType, VIPServicePort, inputFile, results)
else:
	print ("Something went wrong but wasnt caught correctly.")
	d = {'time' : datetime.datetime.now().strftime("%m-%d.%H:%M:%S.%f"), 'executed_on' : socket.gethostname(), 'ScriptName' : os.path.basename(__file__), 'user' : user, 'enviroment_build' : VIPfqdn, 'message' : 'Error - Something went wrong but wasnt caught correctly.'}
	my_logger.debug(d)
	
net_connect.disconnect()
inputFile.close()
sys.exit(0)
