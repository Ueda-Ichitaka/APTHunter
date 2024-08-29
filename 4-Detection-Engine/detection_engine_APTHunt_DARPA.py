#!/usr/bin/env python3


###################################
######   APTHunter     ############
###  Detection Engine - DARPA #####
###################################
###################################

from neo4j import GraphDatabase

import pandas as pd
#from tabulate import tabulate

import os

#from array import *
import time
import datetime
#from datetime import datetime
from datetime import timedelta

from progress.bar import IncrementalBar

import pytz
start_time = time.time()

#panada framework - display complete contents of a dataframe
pd.set_option('display.max_rows', None)
pd.set_option('display.max_columns', None)
pd.set_option('display.width', None)
pd.set_option('display.max_colwidth', None)

driver = GraphDatabase.driver(
	"bolt://127.0.0.1:7687",
	auth=("neo4j", "neo4jchanged"),
	#notifications_min_severity='OFF',  # or 'OFF' to disable
   # notifications_disabled_categories=['HINT', 'GENERIC', 'DEPRECATION']
	)


threat_score = 0
Trusted_IP_Addresses_subnet = "128.55.12"
#Trusted_IP_Addresses_subnet = "192.168.8.135"
path_csv = "/home/riru/APTHunter/APTHunter/4-Detection-Engine/results/theia-1-1_full_darpa_" + str(time.time()) + "/"

initial_comp_timestamp_list = []
compromised_process_list = []
detections = pd.DataFrame({'host':[], 'detection_type': [], 'detection_timestamp': [], 'detection_details': [], 'threat_Score': [], 'certainity_Score': []})

Incoming_Connections = pd.DataFrame({'host':[], 'detection_timestamp': [], 'source': [], 'SYSCALL': [], 'detection_details': [], 'threat_Score': [], 'certainity_Score': []})
Outgoing_Connections = pd.DataFrame({'host':[], 'detection_timestamp': [], 'source': [], 'SYSCALL': [], 'detection_details': [], 'threat_Score': [], 'certainity_Score': []})
T1571_Non_Standard_Port = pd.DataFrame({'host':[], 'detection_timestamp': [], 'source': [], 'SYSCALL': [], 'detection_details': [], 'threat_Score': [], 'certainity_Score': []})

Domain_Hijaking = pd.DataFrame({'host':[], 'detection_timestamp': [], 'source': [], 'SYSCALL': [], 'Intermediate_process': [], 'SYSCALL_2': [], 'IP Address': [], 'Count': [], 'threat_Score': [], 'certainity_Score': []})
FootHold = pd.DataFrame({'host':[], 'detection_timestamp': [], 'source': [], 'SYSCALL': [], 'detection_details': [], 'threat_Score': [], 'certainity_Score': []})
Send_Internal = pd.DataFrame({'host':[], 'detection_timestamp': [], 'source': [], 'SYSCALL': [], 'detection_details': [], 'threat_Score': [], 'certainity_Score': []})

IntRecon = pd.DataFrame({'host':[], 'detection_timestamp': [], 'Compromised Process': [], 'Inter_process': [], 'SYSCALL_2': [], 'detection_details': [], 'threat_Score': [], 'certainity_Score': []})
IntRecon_prov = pd.DataFrame({'host':[], 'detection_timestamp': [], 'source': [], 'Intermediate_process': [], 'SYSCALL_2': [], 'Recon': [], 'Count': [], 'threat_Score': [], 'certainity_Score': []})

# Portscan =
# Lateral_Movement =

Priv_Escal = pd.DataFrame({'host':[], 'detection_timestamp': [], 'source': [], 'Intermediate_process': [], 'SYSCALL_2': [], 'Target': [], 'Count': [], 'threat_Score': [], 'certainity_Score': []})
Proc_Inj = pd.DataFrame({'host':[], 'detection_timestamp': [], 'source': [], 'SYSCALL': [], 'Target': [], 'Count': [], 'threat_Score': [], 'certainity_Score': []})
Priv_Escal_2 = pd.DataFrame({'host':[], 'detection_timestamp': [], 'source': [], 'SYSCALL': [], 'Target': [], 'Count': [], 'threat_Score': [], 'certainity_Score': []})
# Priv_Escal_SUP =
# Priv_Escal_Util =
# Priv_Escal_Task =
# Priv_Escal_Acc =

Exfil = pd.DataFrame({'host':[], 'detection_timestamp': [], 'source': [], 'SYSCALL': [], 'detection_details': [], 'threat_Score': [], 'certainity_Score': []})
Exfil_prov = pd.DataFrame({'host':[], 'detection_timestamp': [], 'Compromised Process': [], 'Intermediate_process': [], 'SYSCALL_3': [], 'exfil': [], 'Count': [], 'threat_Score': [], 'certainity_Score': []})
Exfil_internal = pd.DataFrame({'host':[], 'detection_timestamp': [], 'Compromised Process': [], 'Intermediate_process': [], 'SYSCALL_3': [], 'exfil': [], 'Count': [], 'threat_Score': [], 'certainity_Score': []})
#Exfil_scp = pd.DataFrame({'name_1':[], 'caption_1':[], 'syscall':[], 'name_2':[], 'caption_2':[], 'timestamp':[], 'threat_Score': [], 'certainity_Score': []})

#Impact_Shutdown =

Clear_logs = pd.DataFrame({'host':[], 'detection_timestamp': [], 'source': [], 'SYSCALL': [], 'detection_details': [], 'threat_Score': [], 'certainity_Score': []})
Untrusted_File_RM = pd.DataFrame({'host':[], 'detection_timestamp': [], 'source': [], 'SYSCALL': [], 'detection_details': [], 'threat_Score': [], 'certainity_Score': []})

timestamp_from = datetime.datetime.fromtimestamp(1557784800-18000,  pytz.timezone("AMERICA/NEW_YORK"))
timestamp_to = datetime.datetime.fromtimestamp(1557936000, pytz.timezone("AMERICA/NEW_YORK"))  #1557871200
print (timestamp_from)
print(timestamp_to)


print("I am APTHunt script")
if not os.path.exists(path_csv):
	os.makedirs(path_csv)	

with driver.session() as session:

#################################################################################
########################## Initial Compromise ###################################
#################################################################################




	# Drakon APT - Initial Compromise rule - paths that are common on the source subject, destination subject, r2.syscall, and timestamp are grouped and counted
	# Initial Compromise
	## Incoming Connections
	result = session.run("""MATCH p=(n1)-[r:SYSCALL]->(n2)
		WHERE r.type =~"ACCEPT" and n2.caption =~ '^(?:[0-9]{1,3}.){3}[0-9]{1,3}.*' and not n2.caption STARTS WITH $Trusted_Addresses
		RETURN n1.host as host, n1.caption as caption, r.type as syscall, n2.caption as caption_n2, r.timestamp as timestamp, count(n2) as count""",
		Trusted_Addresses = Trusted_IP_Addresses_subnet)

	for record in result:
		threat_score = 0
		certainty_score = 0

		Incoming_Connections = pd.concat([Incoming_Connections, pd.DataFrame({'host':[record["host"]], 'detection_timestamp': [record["timestamp"]], 'source': [record["caption"]], 'SYSCALL': [record["syscall"]], 'detection_details': [record["caption_n2"]], 'threat_Score': [threat_score], 'certainity_Score': [certainty_score]})],ignore_index=True)




	# Initial Compromise
	## Outgoing Connections
	result = session.run("""MATCH p=(n1)-[r:SYSCALL]->(n2)
		WHERE r.type =~"CONNECT" and n2.caption =~ '^(?:[0-9]{1,3}.){3}[0-9]{1,3}.*' and not n2.caption STARTS WITH $Trusted_Addresses and not n2.caption =~ '127.0.0.1.*' and not n2.caption =~ '0.0.0.0.*|0000.*' and not n1.caption =~ '/usr/lib/firefox/firefox|firefox|/bin/ping|sendmail|wget|pkg|fetch|netstat|ping|null'
		RETURN n1.host as host, n1.caption as caption, n1.name as name_1, r.type as syscall, n2.caption as caption_n2, r.timestamp as timestamp, count(n2) as count""",
		Trusted_Addresses = Trusted_IP_Addresses_subnet)

	for record in result:
		threat_score = 5
		certainty_score = 10		

		Outgoing_Connections = pd.concat([Outgoing_Connections, pd.DataFrame({'host':[record["host"]], 'detection_timestamp': [record["timestamp"]], 'source': [record["caption"] + ':' + record["name_1"]], 'SYSCALL': [record["syscall"]], 'detection_details': [record["caption_n2"]], 'threat_Score': [threat_score], 'certainity_Score': [certainty_score]})],ignore_index=True)




	# Initial Compromise
	## T1571: Non-Standard Port
	result = session.run("""MATCH p=(n1)-[r:SYSCALL]->(n2)
		WHERE r.type =~"CONNECT" and n2.caption =~ '^(?:[0-9]{1,3}.){3}[0-9]{1,3}.*' and not n2.caption STARTS WITH $Trusted_Addresses and not n1.caption =~ 'sendmail|wget|pkg|fetch|netstat|ping|null' and not n2.caption =~ '127.0.0.1.*' and not (n1.caption =~'.*ssh|.*sshd|ssh|sshd' and n2.caption =~'.*:22') and not (n1.caption =~'/usr/lib/firefox/firefox|firefox|/bin/ping|ping' and n2.caption =~'.*:80|.*:443|')
		RETURN n1.host as host, n1.caption as caption, n1.name as name_1, r.type as syscall, n2.caption as caption_n2, r.timestamp as timestamp, count(n2) as count""",
		Trusted_Addresses = Trusted_IP_Addresses_subnet)

	for record in result:
		threat_score = 5
		certainty_score = 10
		 			
		T1571_Non_Standard_Port = pd.concat([T1571_Non_Standard_Port, pd.DataFrame({'host':[record["host"]], 'detection_timestamp': [record["timestamp"]], 'source': [record["caption"] + ':' + record["name_1"]], 'SYSCALL': [record["syscall"]], 'detection_details': [record["caption_n2"]], 'threat_Score': [threat_score], 'certainity_Score': [certainty_score]})],ignore_index=True)



	# Initial Compromise
	## T1584: Compromise Infrastructure
    ## Domain Hijacking
	### SSH Connection to IP after SSH daemon being modifed by Internet explorer service (e.g.,Firefox)
	### Check if internet explorer service did other events
	result = session.run("""MATCH p=(n1)-[r1:SYSCALL]->(n2)-[r2:SYSCALL]->(n3)
		WHERE n1.caption =~ '/usr/lib/firefox|firefox' AND n2.caption = '/bin/ssh|ssh' AND r2.type =~"CONNECT" AND n3.caption =~ '^(?:[0-9]{1,3}.){3}[0-9]{1,3}.*'  and r2.timestamp >= r1.timestamp
		RETURN n1.host as host, n1.caption as caption, n1.name as name_1, r1.type as syscall, n2.caption as caption_n2, r2.type as syscall2, n3.caption as caption_n3, n2.name as name_n2, r2.timestamp as timestamp, count(n3) as count""")

	for record in result:
		threat_score = 5
		certainty_score = 10
		source_proc =  record["caption"] + ':' + record["name_1"]

		Domain_Hijaking = pd.concat([Domain_Hijaking, pd.DataFrame({'host':[record["host"]], 'detection_timestamp': [record["timestamp"]], 'source': [record["caption"] + ':' + record["name_1"]], 'SYSCALL': [record["syscall"]], 'Intermediate_process': [record["caption_n2"]], 'SYSCALL_2': [record["syscall2"]], 'IP Address': [record["caption_n3"]], 'Count': [record["count"]], 'threat_Score': [threat_score], 'certainity_Score': [certainty_score]})],ignore_index=True)

driver.close()  # close the driver object



# Checking init comp rule (with high certinity) match (no previous incoming connections on the same socket)
for index1, row1 in Outgoing_Connections.iterrows():
	for index2, row2 in Incoming_Connections.iterrows():		
		if (row1['detection_details'] == row2['detection_details']):			
			Outgoing_Connections.at[index1, 'certainity_Score'] = 0

#drop false detections
Outgoing_Connections = Outgoing_Connections[Outgoing_Connections.certainity_Score != 0]

for index1, row1 in Outgoing_Connections.iterrows():
	initial_comp_timestamp_list.append(row1['detection_timestamp'])
	compromised_process_list.append(row1['source'].split(':')[1])		
		

print("Incoming_Connections")
print(Incoming_Connections.sort_values(by=['detection_timestamp'], ascending=False))
print("")
print("T1190 Exploit Public-Facing Applications (Initial Compromise)")
print(Outgoing_Connections.sort_values(by=['detection_timestamp'], ascending=False))
print("")
print("T1571 Non_Standard_Port (Initial Compromise)")
print(T1571_Non_Standard_Port.sort_values(by=['detection_timestamp'], ascending=False))
print("")
print("T1584-001 Domain_Hijaking")
print(Domain_Hijaking.sort_values(by=['detection_timestamp'], ascending=False))
print("")


#send to CSV files
Incoming_Connections.to_csv(path_csv+'Init_Comp_Incoming_Connections.csv',index=True)
Outgoing_Connections.to_csv(path_csv+'Init_Comp_Exploit_Public_Facing.csv',index=True)
T1571_Non_Standard_Port.to_csv(path_csv+'Init_Comp_T1571__Non_Standard_Port.csv',index=True)
Domain_Hijaking.to_csv(path_csv+'Init_Comp_T1584_001_Domain_Hijaking.csv',index=True)

      
#################################################################################
########################## FootHold #############################################
#################################################################################

with driver.session() as session:
	
	bar = IncrementalBar('Countdown', max = len(compromised_process_list))
	for index, compromised_process in enumerate(compromised_process_list):

		bar.next()
		initial_comp_timestamp = initial_comp_timestamp_list[index]


		# Establish FootHold
		result = session.run("""MATCH p=(n1)-[r:SYSCALL*1..3]->(n2)-[r2:SYSCALL]->(n3)
			WHERE n1.name = $process_condition AND r2.type =~'EXECUTE|FORK|CLONE' AND n3.caption =~ '/bin/.*|/bin/bash|apt|apt-get|bash|browse|cat|chsh|cmp|dbus-daemon|dbus-launch|dpkg|dpkg-deb|env|find|firefox|fusermount|hostname|ionice|kill|ls|lsb_release|man|mandb|mv|nc|net|nice|nm|open|passwd|perl|pkexec|ps|run-parts|scp|script|sh|ssh|su|sudo|tar|test|thunderbird|top|tr|uxterm|vim|wall|wget|who|whoami|write|xauth|xterm|x-www-browser' AND r2.timestamp >= $timestamp_condition
			RETURN n1.host as host, n1.caption as caption, n1.name as name_1, r2.type as syscall2, n3.caption as caption_n3, r2.timestamp as timestamp, count(n3) as count""",
			timestamp_condition = initial_comp_timestamp, process_condition = compromised_process)

		for record in result:
			threat_score = 5
			certainty_score = 0
			 			
			FootHold = pd.concat([FootHold, pd.DataFrame({'host':[record["host"]], 'detection_timestamp': [record["timestamp"]], 'source': [record["caption"] + ':' + record["name_1"]], 'SYSCALL': [record["syscall2"]], 'detection_details': [record["caption_n3"]], 'threat_Score': [threat_score], 'certainity_Score': [certainty_score]})],ignore_index=True)


		# Drakon APT - Recon rule
		## Sensitive commands
		result = session.run("""MATCH p=(n1)-[r:SYSCALL*1..3]->(n2)-[r2:SYSCALL]->(n3)
			WHERE n1.name = $process_condition AND r2.type =~'EXECUTE|FORK|CLONE' AND n3.caption =~ '/sbin/.*|/bin/.*|/usr/bin/.*|/usr/local/.*|/usr/sbin/.*|bash|sudo|anacron|apt|apt-get|bin|browse|cat|chsh|cmp|cron|dbus-daemon|dbus-launch|dhclient|dhclient-script|dpkg|dpkg-deb|dumpe2fs|env|etc|find|firefox|fsck|fusermount|hostname|init|insmod|ionice|kill|lib|logotate|ls|lsb_release|man|mandb|mv|nc|net|net|nice|nm|open|passwd|perl|pkexec|ps|resolvconf|run-parts|scp|script|service|su|sysctl|tar|test|thunderbird|top|tr|uxterm|vim|wall|wget|who|whoami|write|xauth|xterm|x-www-browser|wall|ls' OR n3.caption contains 'ls|wall|sudo|su|cat' AND r2.timestamp >= $timestamp_condition
			RETURN n1.host as host, n1.caption as caption, n1.name as name_1, r2.type as syscall2, n2.caption as caption_2, n2.name as name_2, n3.caption as caption_3, localdatetime(r2.timestamp) as timestamp, count(n3) as count""", timestamp_condition = initial_comp_timestamp, process_condition = compromised_process)

		for record in result:
			threat_score = 2
			certainty_score = 0

			IntRecon = pd.concat([IntRecon, pd.DataFrame({'host':[record["host"]], 'detection_timestamp': [record["timestamp"]], 'Compromised Process': [record["caption"] + ':' + record["name_1"]], 'Inter_process':[record["caption_2"] + ':' + record["name_2"]], 'SYSCALL_2': [record["syscall2"]], 'detection_details': [record["caption_3"]], 'threat_Score': [threat_score], 'certainity_Score': [certainty_score]})],ignore_index=True)


		# modified
		# Reconaissance
		## sensitive read for /etc/passwd, ...
		result = session.run("""MATCH p=(n1)-[r:SYSCALL*1..3]->(n2)-[r2:SYSCALL]->(n3)
			WHERE (n1.name = $process_condition AND r2.type =~'READ|OPEN|MMAP' AND n3.caption =~ '/etc/.*|passwd|hosts|shadow') OR ( r2.type =~ 'EXECUTE' AND n3.caption contains 'cat /etc/*') AND r2.timestamp >= $timestamp_condition
			RETURN n1.host as host, n1.caption as caption, n1.name as name_1, r2.type as syscall2, n2.caption as caption_2, n3.caption as caption_3, localdatetime(r2.timestamp) as timestamp, count(n3) as count""",
			timestamp_condition = initial_comp_timestamp, process_condition = compromised_process)

		for record in result:
			threat_score = 2
			certainty_score = 0

			IntRecon = pd.concat([IntRecon, pd.DataFrame({'host':[record["host"]], 'detection_timestamp': [record["timestamp"]], 'Compromised Process': [record["caption"] + ':' + record["name_1"]], 'Inter_process':[record["caption_2"]], 'SYSCALL_2': [record["syscall2"]], 'detection_details': [record["caption_3"]], 'threat_Score': [threat_score], 'certainity_Score': [certainty_score]})],ignore_index=True)



		# Reconaissance
		## TODO recon stage
# 		result = session.run("""MATCH
# 			WHERE
# 			RETURN """,
# 			timestamp_condition = initial_comp_timestamp, process_condition = compromised_process)
#
# 		for record in result:
# 			threat_score = 5
# 			certainty_score = 10
#
# 			IntRecon = pd.concat([IntRecon, pd.DataFrame({'host':[record["host"]], 'detection_timestamp': [record["timestamp"]], 'Compromised Process': [record["caption"] + ':' + record["name_1"]], 'Inter_process':[record["caption_2"]], 'SYSCALL_2': [record["syscall2"]], 'detection_details': [record["caption_3"]], 'threat_Score': [threat_score], 'certainity_Score': [certainty_score]})],ignore_index=True)



		# modified
		# Privilege Escalation
		## Privilege Escalation using sudo
		result = session.run("""MATCH p=(n1)-[r:SYSCALL*1..3]->(n2)-[r2:SYSCALL]->(n3)
			WHERE n2.caption =~ '/usr/bin/sudo|sudo|su' AND r2.type =~ 'EXECUTE' AND n1.name = $process_condition AND r2.timestamp >= $timestamp_condition
			RETURN n3.host as host, n1.caption as caption,  n2.caption as caption_n2, r2.type as syscall_2, n3.caption as caption_n3, r2.timestamp as timestamp, count(n3) as count""",
			timestamp_condition = initial_comp_timestamp, process_condition = compromised_process)

		for record in result:
			threat_score = 5
			certainty_score = 10

			Priv_Escal = pd.concat([Priv_Escal, pd.DataFrame({'host':[record["host"]], 'detection_timestamp': [record["timestamp"]], 'source': [record["caption"]], 'SYSCALL_2': [record["syscall_2"]], 'Target': [record["caption_n3"]], 'Count': [record["count"]], 'threat_Score': [threat_score], 'certainity_Score': [certainty_score]})],ignore_index=True)



		# Privilege Escalation
		## Privilege Escalation using super user privileges
		result = session.run("""MATCH p=(n1)-[r:SYSCALL*1..3]->(n2)-[r2:SYSCALL]->(n3)
			WHERE r2.type =~ 'CHANGE_PRINCIPAL' AND n1.name = $process_condition AND r2.timestamp >= $timestamp_condition
			RETURN n3.host as host, n1.caption as caption,  n2.caption as caption_n2, r2.type as syscall_2, n3.caption as caption_n3, r2.timestamp as timestamp, count(n3) as count""",
			timestamp_condition = initial_comp_timestamp, process_condition = compromised_process)

		for record in result:
			threat_score = 5
			certainty_score = 10

			Priv_Escal = pd.concat([Priv_Escal, pd.DataFrame({'host':[record["host"]], 'detection_timestamp': [record["timestamp"]], 'source': [record["caption"]], 'SYSCALL_2': [record["syscall_2"]], 'Target': [record["caption_n3"]], 'Count': [record["count"]], 'threat_Score': [threat_score], 'certainity_Score': [certainty_score]})],ignore_index=True)




		# Privilege Escalation
		## T1055: Process injection
		result = session.run("""MATCH p=(n1)-[r:SYSCALL*1..2]->(n2)-[r2:SYSCALL]->(n3)
			WHERE r2.type =~ 'MODIFY_PROCESS' AND (n1.name = $process_condition OR n2.name = $process_condition) AND r2.timestamp >= $timestamp_condition
			RETURN n3.host as host, n1.caption as caption, n2.caption as caption_n2 , r2.type as syscall_2, r2.timestamp as timestamp, count(n3) as count""",
			timestamp_condition = initial_comp_timestamp, process_condition = compromised_process)

		for record in result:
			threat_score = 5
			certainty_score = 10		

			Proc_Inj = pd.concat([Proc_Inj, pd.DataFrame({'host':[record["host"]], 'detection_timestamp': [record["timestamp"]], 'source': [record["caption"]], 'SYSCALL': [record["syscall_2"]], 'Target': [record["caption_n2"]], 'Count': [record["count"]], 'threat_Score': [threat_score], 'certainity_Score': [certainty_score]})],ignore_index=True)




		# Privilege Escalation
		## T1055: Process injection
		### modified version of the query above to work with tc-e5-trace-2
		result = session.run("""MATCH p=(n1)-[r:SYSCALL]->(n2)
			WHERE r.type =~ 'MODIFY_PROCESS' AND n2.name = $process_condition AND r.timestamp >= $timestamp_condition
			RETURN n2.host as host, n1.caption as caption, n2.caption as caption_n2, n2.name as name_n2 , r.type as syscall, r.timestamp as timestamp, count(n2) as count""",
			timestamp_condition = initial_comp_timestamp, process_condition = compromised_process)

		for record in result:
			threat_score = 5
			certainty_score = 10

			Proc_Inj = pd.concat([Proc_Inj, pd.DataFrame({'host':[record["host"]], 'detection_timestamp': [record["timestamp"]], 'source': [record["caption"]], 'SYSCALL': [record["syscall"]], 'Target': [record["caption_n2"] + ":" + record["name_n2"]], 'Count': [record["count"]], 'threat_Score': [threat_score], 'certainity_Score': [certainty_score]})],ignore_index=True)






		# Privilege Escalation
		## Privilage escalation using exploits of vulnerable services (e.g., load_helper.ko)
		result = session.run("""MATCH p=(n1)-[r1:SYSCALL]->(n2)
			WHERE r1.type =~ 'CLONE' and n2.caption =~ '.*:0' and not n1.caption =~ '.*:0' and not n1.caption =~ 'null:null|:'
			SET n2:Compromised
			SET n1:Culprit
			RETURN n1.host as host, n1.caption as caption, n2.caption as caption_n2, r1.type as syscall, r1.timestamp as timestamp, count(n2) as count""")

		for record in result:
			threat_score = 5
			certainty_score = 10		

			Priv_Escal_2 = pd.concat([Priv_Escal_2, pd.DataFrame({'host':[record["host"]], 'detection_timestamp': [record["timestamp"]], 'source': [record["caption"]], 'SYSCALL': [record["syscall"]], 'Target': [record["caption_n2"]], 'Count': [record["count"]], 'threat_Score': [threat_score], 'certainity_Score': [certainty_score]})],ignore_index=True)




		# Privilege Escalation
		## super user utilities
		### TODO
		# result = session.run("""MATCH
		# 	WHERE
		# 	RETURN """,
		# 	timestamp_condition = initial_comp_timestamp, process_condition = compromised_process)
  #
		# for record in result:
		# 	threat_score = 5
		# 	certainty_score = 10
  #
		# 	Priv_Escal_Util = pd.concat([Priv_Escal_Util, pd.DataFrame()],ignore_index=True)




		# Privilege Escalation
		## super user privileges
		### TODO
		# result = session.run("""MATCH
		# 	WHERE
		# 	RETURN """,
		# 	timestamp_condition = initial_comp_timestamp, process_condition = compromised_process)
  #
		# for record in result:
		# 	threat_score = 5
		# 	certainty_score = 10
  #
		# 	Priv_Escal_SUP = pd.concat([Priv_Escal_SUP, pd.DataFrame()],ignore_index=True)




		# Privilege Escalation
		## scheduled task
		### TODO
		# result = session.run("""MATCH
		# 	WHERE
		# 	RETURN """,
		# 	timestamp_condition = initial_comp_timestamp, process_condition = compromised_process)
  #
		# for record in result:
		# 	threat_score = 5
		# 	certainty_score = 10
  #
		# 	Priv_Escal_Task = pd.concat([Priv_Escal_Task, pd.DataFrame()],ignore_index=True)
  #




		# Privilege Escalation
		## valid domain accoutn
		### TODO
		# result = session.run("""MATCH
		# 	WHERE
		# 	RETURN """,
		# 	timestamp_condition = initial_comp_timestamp, process_condition = compromised_process)
  #
		# for record in result:
		# 	threat_score = 5
		# 	certainty_score = 10
  #
		# 	Priv_Escal_Acc = pd.concat([Priv_Escal_Acc, pd.DataFrame()],ignore_index=True)






		# Lateral Movement
		result = session.run("""MATCH p=(n1)-[r:SYSCALL*1..3]->(n2)-[r2:SYSCALL]->(n3)
			WHERE n1.name = $process_condition AND r2.type =~'SENDMSG' AND n3.caption =~ '^(?:[0-9]{1,3}.){3}[0-9]{1,3}.*' AND n3.caption STARTS WITH $Trusted_Addresses AND r2.timestamp >= $timestamp_condition
			RETURN n1.host as host, n1.caption as caption, n1.name as name_1, r2.type as syscall2, n3.caption as caption_n3, r2.timestamp as timestamp, count(n3) as count""",
			timestamp_condition = initial_comp_timestamp, process_condition = compromised_process, Trusted_Addresses = Trusted_IP_Addresses_subnet)

		for record in result:
			threat_score = 5
			certainty_score = 10
			 			
			Send_Internal = pd.concat([Send_Internal, pd.DataFrame({'host':[record["host"]], 'detection_timestamp': [record["timestamp"]], 'source': [record["caption"] + ':' + record["name_1"]], 'SYSCALL': [record["syscall2"]], 'detection_details': [record["caption_n3"]], 'threat_Score': [threat_score], 'certainity_Score': [certainty_score]})],ignore_index=True)






		# Cleanup Tracks
		## Clear Logs:
		result = session.run("""MATCH p=(n1)-[r:SYSCALL*1..3]->(n2)-[r2:SYSCALL]->(n3)
			WHERE (n1.name = $process_condition OR n2.name = $process_condition) AND r2.type =~'UNLINK' AND n3.caption =~ '.*log.*' AND r2.timestamp >= $timestamp_condition
			RETURN n1.host as host, n1.caption as caption, n1.name as name_1, r2.type as syscall2, n3.caption as caption_n3, r2.timestamp as timestamp, count(n3) as count""",
			timestamp_condition = initial_comp_timestamp, process_condition = compromised_process, Trusted_Addresses = Trusted_IP_Addresses_subnet)

		for record in result:
			threat_score = 5
			certainty_score = 10
			 			
			Clear_logs = pd.concat([Clear_logs, pd.DataFrame({'host':[record["host"]], 'detection_timestamp': [record["timestamp"]], 'source': [record["caption"] + ':' + record["name_1"]], 'SYSCALL': [record["syscall2"]], 'detection_details': [record["caption_n3"]], 'threat_Score': [threat_score], 'certainity_Score': [certainty_score]})],ignore_index=True)




		# Cleanup Tracks
		## Clear artifacts:
		result = session.run("""MATCH p=(n1)-[r:SYSCALL*1..3]->(n2)-[r2:SYSCALL]->(n3)
			WHERE (n1.name = $process_condition OR n2.name = $process_condition) AND r2.type =~'UNLINK' AND NOT n3.caption =~ '.*log.*' AND r2.timestamp >= $timestamp_condition
			RETURN n1.host as host, n1.caption as caption, n1.name as name_1, r2.type as syscall2, n3.caption as caption_n3, r2.timestamp as timestamp, count(n3) as count""",
			timestamp_condition = initial_comp_timestamp, process_condition = compromised_process, Trusted_Addresses = Trusted_IP_Addresses_subnet)

		for record in result:
			threat_score = 5
			certainty_score = 10
			 			
			Untrusted_File_RM = pd.concat([Untrusted_File_RM, pd.DataFrame({'host':[record["host"]], 'detection_timestamp': [record["timestamp"]], 'source': [record["caption"] + ':' + record["name_1"]], 'SYSCALL': [record["syscall2"]], 'detection_details': [record["caption_n3"]], 'threat_Score': [threat_score], 'certainity_Score': [certainty_score]})],ignore_index=True)
			
	bar.finish()

	bar = IncrementalBar('Countdown', max = len(IntRecon))
	for index1, row1 in IntRecon.iterrows():


		bar.next()               		


		# Exfiltration
		##
		result = session.run("""MATCH p=(n1)-[r1:SYSCALL*0..2]->(n2)-[r3:SYSCALL]->(n4)
			WHERE (n1.name = $process_condition OR n2.name = $process_condition) AND r3.type =~'SENDMSG' AND n4.caption =~ '^(?:[0-9]{1,3}.){3}[0-9]{1,3}.*' AND NOT n4.caption STARTS WITH $Trusted_Addresses
			RETURN n1.host as host, n1.caption as caption, n1.name as name_1, n2.caption as caption_2, n4.caption as caption_4, r3.type as syscall_3, r3.timestamp as timestamp, count(n4) as count""",
			process_condition = row1['Compromised Process'].split(':')[1], Trusted_Addresses = Trusted_IP_Addresses_subnet)

		for record in result:
			threat_score = 5
			certainty_score = 10		

			Exfil_prov = pd.concat([Exfil_prov, pd.DataFrame({'host':[record["host"]], 'detection_timestamp': [record["timestamp"]], 'Compromised Process': [record["caption"] + ':' + record["name_1"]], 'Intermediate_process':[record["caption_2"]], 'SYSCALL_3': [record["syscall_3"]], 'exfil': [record["caption_4"]], 'Count': [record["count"]], 'threat_Score': [threat_score], 'certainity_Score': [certainty_score]})],ignore_index=True)



		# Exfiltration
		## Exfil using scp
		### TODO: search with caption ssh or with process name or both?
		# result = session.run("""MATCH p=(n1)-[r:SYSCALL]->(n2)
		# 	WHERE n1.caption contains 'scp' or n2.caption contains 'scp' AND r.timestamp >= $timestamp_condition
		# 	RETURN n1.name as name_n1, n1.caption as caption_n1, r.type as syscall, n2.name as name_n2, n2.capion as caption_n2, r.timestamp as timestamp""",
		# 	timestamp_condition = initial_comp_timestamp, Trusted_Addresses = Trusted_IP_Addresses_subnet)
  #
		# for record in result:
		# 	threat_score = 5
		# 	certainty_score = 10
  #
		# 	Exfil_scp = pd.concat([Exfil_scp, pd.DataFrame({'name_1':[record["name_n1"]], 'caption_1':[record["caption_n1"]], 'syscall':[record["syscall"]], 'name_2':[record["name_n2"]], 'caption_2':[record["caption_n2"]], 'timestamp':[record["timestamp"]], 'threat_Score': [threat_score], 'certainity_Score': [certainty_score]})], ignore_index=True)



		# Exfiltration
		## Internal Exfiltration
		result = session.run("""MATCH p=(n1)-[r1:SYSCALL*0..2]->(n2)-[r3:SYSCALL]->(n4)
			WHERE (n1.name = $process_condition OR n2.name = $process_condition) AND r3.type =~'SENDMSG' AND n4.caption =~ '^(?:[0-9]{1,3}.){3}[0-9]{1,3}.*' AND n4.caption STARTS WITH $Trusted_Addresses
			RETURN n1.host as host, n1.caption as caption, n1.name as name_1, n2.caption as caption_2, n4.caption as caption_4, r3.type as syscall_3, r3.timestamp as timestamp, count(n4) as count""",
			process_condition = row1['Compromised Process'].split(':')[1], Trusted_Addresses = Trusted_IP_Addresses_subnet)

		for record in result:
			threat_score = 5
			certainty_score = 10		

			Exfil_internal = pd.concat([Exfil_internal, pd.DataFrame({'host':[record["host"]], 'detection_timestamp': [record["timestamp"]], 'Compromised Process': [record["caption"] + ':' + record["name_1"]], 'Intermediate_process':[record["caption_2"]], 'SYSCALL_3': [record["syscall_3"]], 'exfil': [record["caption_4"]], 'Count': [record["count"]], 'threat_Score': [threat_score], 'certainity_Score': [certainty_score]})],ignore_index=True)


		
	bar.finish()				
driver.close()  # close the driver object






timezone = pytz.timezone("AMERICA/NEW_YORK")
for index1, row1 in IntRecon.iterrows():
	for index2, row2 in Outgoing_Connections.iterrows():
		if (row1['host'] == row2['host'] and ( (row2['detection_timestamp'] + timedelta(minutes=10)) > timezone.localize(row1['detection_timestamp']) >= row2['detection_timestamp'])):
			IntRecon.at[index1, 'certainity_Score'] = 10


## This is already printed above before entering the loops through the compromised process list
# print("Incoming_Connections")
# print(Incoming_Connections.sort_values(by=['detection_timestamp'], ascending=False))
# print("")
# print("T1190 Exploit Public-Facing Applications (Initial Compromise)")
# print(Outgoing_Connections.sort_values(by=['detection_timestamp'], ascending=False))
# print("")
# print("T1571 Non_Standard_Port (Initial Compromise)")
# print(T1571_Non_Standard_Port.sort_values(by=['detection_timestamp'], ascending=False))
# print("")
# print("T1584-001 Domain_Hijaking")
# print(Domain_Hijaking.sort_values(by=['detection_timestamp'], ascending=False))
# print("")


print("Establish Foothold")
print(FootHold.groupby(['host','source','SYSCALL','detection_details']).agg({'detection_timestamp':'min'}).sort_values(by=['detection_timestamp'], ascending=True))
print("")
print("Internal Recon")
print(IntRecon.groupby(['host','Compromised Process','Inter_process','SYSCALL_2','detection_details']).agg(First_Occurence = ('detection_timestamp', 'min'), Last_Occurence=('detection_timestamp', 'max'), Count = ('detection_timestamp', 'nunique')).sort_values(by=['First_Occurence'], ascending=True))
print("")

print("Privilage Escalation")
print("T1055: Process Injection")
print(Proc_Inj.sort_values(by=['detection_timestamp'], ascending=False))
print("")
print("T1068: Exploitation for Privilege Escalation")
print(Priv_Escal.sort_values(by=['detection_timestamp'], ascending=False))
print("")
print("T1068: Exploitation for Privilege Escalation-2")
print(Priv_Escal_2.sort_values(by=['detection_timestamp'], ascending=False))
print("")
# print("Super User Utilites")
# print(Priv_Escal_Util.sort_values(by=['detection_timestamp'], ascending=False))
# print("")
# print("Super User Privileges")
# print(Priv_Escal_SUP.sort_values(by=['detection_timestamp'], ascending=False))
# print("")
# print("Scheduled Task")
# print(Priv_Escal_Task.sort_values(by=['detection_timestamp'], ascending=False))
# print("")
# print("Valid Domain Account")
# print(Priv_Escal_Acc.sort_values(by=['detection_timestamp'], ascending=False))
# print("")


print("Lateral Movement")
print(Send_Internal.sort_values(by=['detection_timestamp'], ascending=False))
print("")

print("EXFIL PROV")
print(Exfil_prov.groupby(['host','Compromised Process','Intermediate_process','SYSCALL_3','exfil']).agg(First_Occurence = ('detection_timestamp', 'min'), Last_Occurence=('detection_timestamp', 'max'), Count = ('detection_timestamp', 'nunique')).sort_values(by=['First_Occurence'], ascending=True))
print("")
print("EXFIL Internal")
print(Exfil_internal.groupby(['host','Compromised Process','Intermediate_process','SYSCALL_3','exfil']).agg(First_Occurence = ('detection_timestamp', 'min'), Last_Occurence=('detection_timestamp', 'max'), Count = ('detection_timestamp', 'nunique')).sort_values(by=['First_Occurence'], ascending=True))
print("")
# print("Exfiltration using scp")
# print(Exfil_scp.sort_values(by=['timestamp'], ascending=True))
# print("")


print("Cleanup Tracks")
print("Clear logs")
print(Clear_logs.sort_values(by=['detection_timestamp'], ascending=False))
print("")
print("Untrusted File RM")
print(Untrusted_File_RM.sort_values(by=['detection_timestamp'], ascending=False))





## send to CSV files

FootHold.to_csv(path_csv+'FootHold.csv',index=True)
IntRecon.to_csv(path_csv+'IntRecon.csv',index=True)
Proc_Inj.to_csv(path_csv+'Priv_escal_Proc_Inj.csv',index=True)
Priv_Escal.to_csv(path_csv+'Priv_Escal.csv',index=True)
Priv_Escal_2.to_csv(path_csv+'Priv_Escal_2.csv',index=True)
Send_Internal.to_csv(path_csv+'Send_Internal.csv',index=True)
Exfil_prov.to_csv(path_csv+'Exfil_prov.csv',index=True)
Exfil_internal.to_csv(path_csv+'Exfil_internal.csv',index=True)
#Exfil_scp.to_csv(path_csv+'Exfil_scp.csv',index=True)
Clear_logs.to_csv(path_csv+'Cleanup_Clear_logs.csv',index=True)
Untrusted_File_RM.to_csv(path_csv+'Cleanup_Untrusted_File_RM.csv',index=True)

file_time_taken = open(path_csv+"Time_taken.txt","w")
elapsed_time = time.time() - start_time
file_time_taken.write("Time taken (Seconds): ")
file_time_taken.write(str(elapsed_time))

print("")
print ("Time taken(seconds):", elapsed_time)

