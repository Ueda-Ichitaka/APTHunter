#!/usr/bin/env python3


###################################
######   Log Normalizer   #########
###### 	      AND    	  #########
######  Causality Tracker #########
######  Version Details   #########
######        V0.8        #########
######	Theia Version     #########
###################################
# Import json module
import json
import csv
import os
import time


start_time = time.time()
start_time_slice = time.time()
i = 1
# Open the existing JSON file for loading into a variable
#Val = input("Enter value: \n")
#DateFrom = 1523028060000000000
DateFrom  = 1557734400000000000   # 1557842610159000000
#DateTo   = 1523031000000000000
DateTo    = 1557993600000000000   # 1557843310159000000
# here we start with object and do backward tracking:
#whoami object:
#In: ta1-cadets-1-e5-official-2.bin.100.json.1
#key_object = "8FA40B6F-BAF5-AF51-B5BA-4F9291AFCEAC"
#Output files: whoami_backwards.csv' and whoami_forward.csv'
#key_object_cmd = "whoami"
Recon = ["whoami", "hostname", "ps", "cat", "who"]
Exfil = ["/etc/passwd", "/etc/shadow", "/etc/hosts", "/etc/pwd.db", "scp"]
InitComp = [""]
InitComp_native_process = ["sshd", "ssh", "sendmail", "wget", "scp", "firefox", "nginx", "apache"]
RemoteAccess = ['sshd','ssh','apache', 'firefox']
PrivEscal_process = ["sudo", "su"]
key_object = "null"
path_len = 0
#working_on_target = False
flag = False
#scp -r /etc/passwd admin@128.55.12.51:./docs/
#In ta1-cadets-1-e5-official-2.bin.116.json
#Output files: scp_etc_passwd_forward.csv and scp_etc_passwd_backwards.csv
#key_object = "B8FFD54B-E634-C156-B4E6-8D03E6C1084F"

object_recon_list = []
object_exfil_list = []
InitComp_native_process_list = []
PrivEscal_process_list = []
RemoteAccess_list = []
RemoteAccess_name_list = []

backward_object = "null"
backward_object_list = []
backward_object_path_length = []

process_UUID_list = []
process_name_list = []
process_cmd_list = []
process_uid_list = []
objects_UUID_list = []
objects_name_list = []
objects_uid_list = []

process_UUID = []
process_name = []
process_cmd = ""
object_UUID = []
object_name = []

fileList = []
fileList = [
	# 'ta1-theia-1-e5-official-1.bin.json',
	# 'ta1-theia-1-e5-official-1.bin.json.1',
	# 'ta1-theia-1-e5-official-1.bin.1.json',
	# 'ta1-theia-1-e5-official-1.bin.1.json.1',
	# 'ta1-theia-1-e5-official-1.bin.2.json',
	# 'ta1-theia-1-e5-official-1.bin.json.1',
	'ta1-theia-1-e5-official-2.bin.json',
	'ta1-theia-1-e5-official-2.bin.json.1',
	]

for i in range(1,40):
	fileList.append('ta1-theia-1-e5-official-2.bin.' + str(i) + '.json')
	fileList.append('ta1-theia-1-e5-official-2.bin.' + str(i) + '.json' + '.1')


if not os.path.exists('./extraction_proof/'):
	os.makedirs('./extraction_proof/')





### clearing Output files
with open('backwards.csv', 'w') as outfile2:
	with open('forward.csv', 'w') as outfile:
		print("Starting processing ...")

### 1- Read Subjects and Objects per log file#######
###################################################
#with open('attack-initial-comp', 'w') as outfile:
for log_file in fileList:
	if(log_file.endswith('.json')):
		while not os.path.exists('/home/riru/Engagement5/Data/theia/' + log_file + '.1'):
			print(log_file + " is not ready yet ..., check back in 1 minute ...")
			time.sleep(60)
	elif(log_file.endswith('.json.1')):
		while not os.path.exists('/home/riru/Engagement5/Data/theia/' + log_file.replace('.json.1','.json.2')):
			print(log_file + " is not ready yet ..., check back in 1 minute ...")
			time.sleep(60)

	print ("Working on:", log_file)

	start_time_slice = time.time()
	if not os.path.exists('./subjects_and_objects/' + log_file):
    		os.makedirs('./subjects_and_objects/' + log_file)

	if os.path.isfile('./subjects_and_objects/' + log_file + '/' + 'subjects.csv'):
		print ("Subjects and Objects files exists...")
	else:
		print ("Subjects and Objects files not exist - creating the files...")
		with open('./subjects_and_objects/' + log_file + '/' + 'subjects.csv', 'w') as outfile:
			with open('./subjects_and_objects/' + log_file + '/' + 'objects.csv', 'w') as outfile2:
				thewriter = csv.writer(outfile)
				thewriter2 = csv.writer(outfile2)
				with open('/home/riru/Engagement5/Data/theia/' + log_file) as jsondata:
					for line in (list(jsondata)):
						cdm_record = json.loads(line.strip())
						cdm_record_type = list(cdm_record['datum'].keys())[0]
						cdm_record_values = cdm_record['datum'][cdm_record_type]
						flag = False
						if (cdm_record_type == "com.bbn.tc.schema.avro.cdm20.Subject"):

							try:
								process_cmd = (cdm_record_values['cmdLine']['string']).encode('utf-8')
							except:
								process_cmd = ""

							try:
								process_path = cdm_record_values['properties']['map']['path']
							except:
								process_path = ""

							try:
								process_uid = cdm_record_values['properties']['map']['uid']
							except:
								process_uid = ""
							thewriter.writerow([cdm_record_values['uuid'],process_path,process_cmd,process_uid])


							# if 	cdm_record_values['properties'] is None:
							# 	thewriter.writerow([cdm_record_values['uuid'],'None',process_cmd])
							# else:
							# 	try:
							# 		thewriter.writerow([cdm_record_values['uuid'],cdm_record_values['properties']['map']['name'],process_cmd])
							# 	except KeyError as ke:
							# 		print(ke.args)
							# 		if str(ke) == 'name':
							# 			thewriter.writerow([cdm_record_values['uuid'],cdm_record_values['properties']['map']['path'],process_cmd])
							# 		else:
							# 			thewriter.writerow([cdm_record_values['uuid'],'None',process_cmd])


						elif (cdm_record_type == "com.bbn.tc.schema.avro.cdm20.FileObject"):

							try:
								object_file_name = cdm_record_values['baseObject']['properties']['map']['filename']
							except:
								object_file_name = ""

							try:
								object_file_uid = cdm_record_values['baseObject']['properties']['map']['uid']

							except:
								object_file_uid = ""

							thewriter2.writerow([cdm_record_values['uuid'],object_file_name,object_file_uid])

							# if 	cdm_record_values['baseObject']['properties'] is None:
							# 	thewriter2.writerow([cdm_record_values['uuid'],'None'])
							# else:
							# 	try:
							# 		thewriter2.writerow([cdm_record_values['uuid'],cdm_record_values['baseObject']['properties']['map']['path']])
							# 	except KeyError as ke:
							# 			print(ke.args)
							# 			if str(ke) == 'path':
							# 				thewriter2.writerow([cdm_record_values['uuid'],cdm_record_values['baseObject']['properties']['map']['filename']])
							# 			else:
							# 				thewriter2.writerow([cdm_record_values['uuid'],cdm_record_values['baseObject']['properties']['map']['inode']])


						elif (cdm_record_type == "com.bbn.tc.schema.avro.cdm20.NetFlowObject"):

							try:
								object_flow_uid = cdm_record_values['baseObject']['properties']['map']['uid']
							except:
								object_flow_uid = ""

							thewriter2.writerow([cdm_record_values['uuid'],cdm_record_values['remoteAddress']['string'] + ':' + str(cdm_record_values['remotePort']['int']),object_flow_uid])


						else:
							continue
	print("Subject and Objects are ready ...")

	#### Read Subjects and Objects Files #####################
	### Clear lists
	process_UUID_list = []
	process_name_list = []
	process_cmd_list = []
	process_uid_list = []
	objects_UUID_list = []
	objects_name_list = []
	objects_uid_list = []

	#### 1- Read subjects and objects extracted from the base file: ta1-theia-1-e5-official-1.bin.json
	print("Read Subject and Objects ...")
	with open('./subjects_and_objects/' + 'ta1-theia-1-e5-official-2.bin.json' + '/' + 'subjects.csv') as csv_file1:
		csv_reader1 = csv.reader(csv_file1, delimiter=',')
		for row in csv_reader1:
			process_UUID_list.append(row[0])
			process_name_list.append(row[1])
			# corection to Darpa Dataset
			if (row[2] =="-bash"):
				process_cmd_list.append("bash")
				#process_cmd_list.append(row[1])
			else:
				process_cmd_list.append(row[2])

			process_uid_list.append(row[3])

	with open('./subjects_and_objects/' + 'ta1-theia-1-e5-official-2.bin.json' + '/' + 'objects.csv') as csv_file2:
		csv_reader2 = csv.reader(csv_file2, delimiter=',')
		for row in csv_reader2:
			objects_UUID_list.append(row[0])
			objects_name_list.append(row[1])
			#print(row)
			objects_uid_list.append(row[2])

	### 2- Read subjects and objects extracted from the target file ###
	with open('./subjects_and_objects/' + log_file + '/' + 'subjects.csv') as csv_file1:
		csv_reader1 = csv.reader(csv_file1, delimiter=',')
		for row in csv_reader1:
			process_UUID_list.append(row[0])
			process_name_list.append(row[1])
			# corection to Darpa Dataset
			if (row[2] =="-bash"):
				process_cmd_list.append(row[1])
			else:
				process_cmd_list.append(row[2])

			process_uid_list.append(row[3])

	with open('./subjects_and_objects/' + log_file + '/' + 'objects.csv') as csv_file2:
		csv_reader2 = csv.reader(csv_file2, delimiter=',')
		for row in csv_reader2:
			objects_UUID_list.append(row[0])
			objects_name_list.append(row[1])
			objects_uid_list.append(row[2])


	###### Search in subjects and objects for interesting objects

	print("Extract list of interesting subjects and objects ...")

	### Clear lists
	object_recon_list = []
	object_exfil_list = []
	InitComp_native_process_list = []
	PrivEscal_process_list = []
	RemoteAccess_list = []

	#Find key recon objects
	for key_object_recon in Recon:
		for index, process_name in enumerate(process_name_list):
			if (process_name.startswith(key_object_recon)):
				object_recon_list.append(process_UUID_list[index])

	for key_object_recon in Recon:
		for index, process_name in enumerate(process_cmd_list):
			if (process_name.startswith(key_object_recon)):
				object_recon_list.append(process_UUID_list[index])

	#Complement Recon list from objects list
	for key_object_recon in Recon:
		for index, object_name in enumerate(objects_name_list):
			if (key_object_recon == object_name.split('/')[-1]):
				#if(key_object_recon == 'whoami'):
					#print (key_object_recon)
					#print (object_name.split('/')[-1])
					#print (objects_UUID_list[index])
				object_recon_list.append(objects_UUID_list[index])

	#Remote access processes
	for index, process_name in enumerate(process_name_list):
		if (process_name.split('/')[-1] in RemoteAccess):
			RemoteAccess_list.append(process_UUID_list[index])
			RemoteAccess_name_list.append(process_name)

	#find key exfiltrate
	for key_object_exf in Exfil:
		for index, object_name in enumerate(objects_name_list):
			if (key_object_exf == object_name):
				object_exfil_list.append(objects_UUID_list[index])

	#native processes
	for process_name in process_name_list:
		if (process_name in InitComp_native_process):
			InitComp_native_process_list.append(process_UUID_list[process_name_list.index(process_name)])


	for key_object_priv in PrivEscal_process:
		for index, process_name in enumerate(process_cmd_list):
			if (process_name.startswith(key_object_priv)):
				PrivEscal_process_list.append(process_UUID_list[index])


	#Privilage escalation processes
	for index, process_name in enumerate(process_name_list):
		if (process_name in PrivEscal_process):
			PrivEscal_process_list.append(process_UUID_list[index])




	######### Extract Interesting Events ##########

	if not os.path.exists('./extracted_events/' + log_file):
		os.makedirs('./extracted_events/' + log_file)

	if os.path.isfile('./extracted_events/' + log_file + '/' + 'forward.csv'):
		print ("Events extracted before, overwrite them...")
	else:
		print ("Extracting events ...")
	with open('./extracted_events/' + log_file + '/' + 'backwards.csv', 'w') as outfile2:
		with open('./extracted_events/' + log_file + '/' + 'forward.csv', 'w') as outfile:
			thewriter = csv.writer(outfile)
			thewriter2 = csv.writer(outfile2)
			# clear lists
			backward_object = "null"
			backward_object_list = []
			backward_object_path_length = []

			print ("Extracting Events from:", log_file)
			start_time_slice = time.time()
			with open('/home/riru/Engagement5/Data/theia/' + log_file) as jsondata:
				for line in reversed(list(jsondata)):
					cdm_record = json.loads(line.strip())
					cdm_record_type = list(cdm_record['datum'].keys())[0]
					cdm_record_values = cdm_record['datum'][cdm_record_type]
					#print ("should print object list")
					#print (backward_object_list)
					flag = False
					if (cdm_record_type == "com.bbn.tc.schema.avro.cdm20.Event"):

						event_type = cdm_record_values['type']
						if not (event_type == "EVENT_CLONE" or event_type == "EVENT_EXECUTE" or event_type == "EVENT_READ" or event_type == "EVENT_FORK" or event_type == "EVENT_ACCEPT" or event_type == "EVENT_CONNECT" or event_type == "EVENT_MODIFY_PROCESS" or event_type == "EVENT_LOADLIBRARY" or event_type == "EVENT_CHANGE_PRINCIPAL" or event_type == "EVENT_MMAP"):
							continue

						for key_object_recon in object_recon_list:
							if (key_object_recon == cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID']):
								if (key_object_recon == '0100D00F-DE26-0C00-0000-0000B790005A'):
									print("Whoami found 1")
								key_object = cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID']
								flag = True
								break
	#
	#					if (not flag):
	#						if (event_type == 'EVENT_CONNECT' or event_type == 'EVENT_ACCEPT'):
	#							flag = True
	#							#if (cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'] in InitComp_native_process_list):
	#							#	continue
	#
						if (not flag):
							#if (event_type == 'EVENT_EXECUTE' or event_type == 'EVENT_OPEN' or event_type == 'EVENT_READ'):
							for key_object_exf in object_exfil_list:
								if (key_object_exf == cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID']):
									key_object = cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID']
									flag = True
									break

						if (not flag):
							for key_process_priv in PrivEscal_process_list:
								if (key_process_priv == cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID']):
									key_object = cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID']
									flag = True
									break

						if (not flag):
							for index, ii in enumerate(backward_object_list):
								if (ii == cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID']):
									backward_object = ii
									if (backward_object_path_length[index] > 100):
										backward_object_path_length.pop(index)
										backward_object_list.pop(index)
									else:
										backward_object_path_length[index] += 1
									flag = True
									break

						flag = False
						predicate_object = cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID']

						try:
							predicate_object_value = objects_name_list[objects_UUID_list.index(cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
						except:
							predicate_object_value = "null"

						subject_UUID = cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID']

						if  (event_type == "EVENT_EXECUTE" and (predicate_object == key_object or predicate_object == backward_object)):

							timestampmilliseconds = str(cdm_record_values['timestampNanos'])[:10] + '.' + str(cdm_record_values['timestampNanos'])[10:13]
							col1 = timestampmilliseconds + ':' + str(cdm_record_values['sequence']['long'])

							#omit the path from predicateObjectPath, to make the subject executable same as in other EVENTS (no path there).
							subject_proces_name = "null"
							subject_process = "null"
							subject_uid = "null"
							#print ("Event_Execute")

							try:
								subject_proces_name = process_name_list[process_UUID_list.index(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
							except:
								subject_proces_name = "null"

							try:
								subject_process = process_cmd_list[process_UUID_list.index(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
							except:
								subject_process = "null"

							if (subject_process == "null"):
								try:
									subject_process = process_name_list[process_UUID_list.index(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
								except:
									subject_process = "null"

							try:
								subject_uid = process_uid_list[process_UUID_list.index(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
							except:
								subject_uid = "null"

							col2 = cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'] + ':' + subject_proces_name
							#col2 = cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID']
							#col2 = cdm_record_values['properties']['map']['exec']
							### JUST SPECAIL FOR EVENT_EXECUTE ### THE SUBJECT BECOMES THE OBJECT AFTER EXECUTING IT
							#col2 = cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'] + ':' + cdm_record_values['properties']['map']['cmdLine']
							col3 = event_type[6:]
							col4 = cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID']

							try:
								col5 = process_cmd_list[process_UUID_list.index(cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
							except:
								col5 = "null"

							if (subject_proces_name == "bash"):

								try:
									col5 = process_cmd_list[process_UUID_list.index(cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
								except:
									col5 = "null"

								if (col5 == "null") :
									try:
										col5 = process_name_list[process_UUID_list.index(cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
									except:
										col5 = "null"

							else:
								try:
									col5 = process_name_list[process_UUID_list.index(cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
								except:
									col5 = "null"


							if (col5 == "null") :
								try:
									col5 = process_name_list[process_UUID_list.index(cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
								except:
									col5 = "null"

								try:
									col5 = objects_name_list[objects_UUID_list.index(cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
								except:
									col5 = "null"

							try:
								object_uid = process_uid_list[process_UUID_list.index(cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
							except:
								object_uid = "null"

							if (object_uid == "null"):
								try:
									object_uid = objects_uid_list[objects_UUID_list.index(cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
								except:
									object_uid = "null"

							col5 = col5 + ":" + object_uid



							if (cdm_record['hostId'] == '37345038-89F2-5899-8FD2-B6D0844A7DBF'):
								col6 = 'ta1-theia-1'
							elif (cdm_record['hostId'] == 'DF4AF963-C31C-DAFC-B5C6-D86F33322775'):
								col6 = 'ta1-trace-2'
							else:
								col6 = 'null'


							thewriter.writerow([col1,col2,col3,col4,col5,col6])
							try:
								backward_object_list.index(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])
							except ValueError :
								backward_object_list.append(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])
								backward_object_path_length.append(0)

						#elif  (event_type == "EVENT_OPEN" and (predicate_object == key_object or predicate_object == backward_object or subject_UUID == backward_object)):
						#	timestampmilliseconds = str(cdm_record_values['timestampNanos'])[:10] + '.' + str(cdm_record_values['timestampNanos'])[10:13]
						#	col1 = timestampmilliseconds + ':' + str(cdm_record_values['sequence']['long'])
						#	col2 = cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'] + ':' + cdm_record_values['properties']['map']['exec']
						#	col3 = event_type[6:]
						#	col4 = cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID']
						#	col5 = cdm_record_values['predicateObjectPath']['string']
						#	if (cdm_record['hostId'] == 'A8370E61-8ECA-ACD4-5394-57E645AE3379'):
						#		col6 = 'ta1-theia-1'
						#	else:
						#		col6 = 'null'
						#	thewriter.writerow([col1,col2,col3,col4,col5,col6])
						#	#backward_object_list.append(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])
						#	#backward_object_path_length.append(0)
						#	predicateObjectUUIDLlist.append(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])
						#	predicateObjectPathLlist.append(cdm_record_values['properties']['map']['exec'])

						elif  (event_type == "EVENT_READ" and (predicate_object == key_object or predicate_object == backward_object)):
							timestampmilliseconds = str(cdm_record_values['timestampNanos'])[:10] + '.' + str(cdm_record_values['timestampNanos'])[10:13]
							col1 = timestampmilliseconds + ':' + str(cdm_record_values['sequence']['long'])
							subject_process = "null"
							subject_uid = "null"

							try:
								subject_process = process_cmd_list[process_UUID_list.index(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
							except:
								subject_process = "null"

							if (subject_process == "null"):
								try:
									subject_proces = process_name_list[process_UUID_list.index(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
								except:
									subject_process = "null"

							try:
								subject_uid = process_uid_list[process_UUID_list.index(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
							except:
								subject_uid = "null"

							# try:
							# 	col2 = cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'] + ':' + process_name_list[process_UUID_list.index(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
							# except:
							# 	col2 = cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'] + ':' + "null"

							col2 = cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'] + ':' + subject_process + ':' + subject_uid


							col3 = event_type[6:]
							col4 = cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID']

							try:
								col5 = objects_name_list[objects_UUID_list.index(cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
							except:
								col5 = "null"

							try:
								object_uid = objects_uid_list[objects_UUID_list.index(cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
							except:
								object_uid = "null"

							col5 = col5 + ":" + object_uid

							if (cdm_record['hostId'] == 'DF4AF963-C31C-DAFC-B5C6-D86F33322775'):
								col6 = 'ta1-trace-2'
							elif (cdm_record['hostId'] == '37345038-89F2-5899-8FD2-B6D0844A7DBF'):
								col6 = 'ta1-theia-1'
							else:
								col6 = 'null'

							thewriter.writerow([col1,col2,col3,col4,col5,col6])

							try:
								backward_object_list.index(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])
							except ValueError :
								backward_object_list.append(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])
								backward_object_path_length.append(0)



						elif  (event_type == "EVENT_MMAP" and (predicate_object == key_object or predicate_object == backward_object)):
							timestampmilliseconds = str(cdm_record_values['timestampNanos'])[:10] + '.' + str(cdm_record_values['timestampNanos'])[10:13]
							col1 = timestampmilliseconds + ':' + str(cdm_record_values['sequence']['long'])
							subject_process = "null"
							subject_uid = "null"

							try:
								subject_process = process_cmd_list[process_UUID_list.index(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
							except:
								subject_process = "null"

							if (subject_process == "null"):
								try:
									subject_process = process_name_list[process_UUID_list.index(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
								except:
									subject_process = "null"

							try:
								subject_uid = process_uid_list[process_UUID_list.index(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
							except:
								subject_uid = "null"

							# try:
							# 	col2 = cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'] + ':' + process_name_list[process_UUID_list.index(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
							# except:
							# 	col2 = cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'] + ':' + "null"

							col2 = cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'] + ':' + subject_process + ':' + subject_uid
							col3 = event_type[6:]
							col4 = cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID']

							try:
								col5 = objects_name_list[objects_UUID_list.index(cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
							except:
								col5 = "null"

							if (cdm_record['hostId'] == 'DF4AF963-C31C-DAFC-B5C6-D86F33322775'):
								col6 = 'ta1-trace-2'
							elif (cdm_record['hostId'] == '37345038-89F2-5899-8FD2-B6D0844A7DBF'):
								col6 = 'ta1-theia-1'
							else:
								col6 = 'null'

							thewriter.writerow([col1,col2,col3,col4,col5,col6])

							try:
								backward_object_list.index(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])
							except ValueError :
								backward_object_list.append(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])
								backward_object_path_length.append(0)

						elif  (event_type == "EVENT_FORK" and (predicate_object == key_object or predicate_object == backward_object)):
							# EVENT_FORK format: timestampNanos:sequence,subject_UUID:exec,type,predicateObject_UUID,predicateObjectPath
							timestampmilliseconds = str(cdm_record_values['timestampNanos'])[:10] + '.' + str(cdm_record_values['timestampNanos'])[10:13]
							col1 = timestampmilliseconds + ':' + str(cdm_record_values['sequence']['long'])
							subject_process = "null"
							subject_uid = "null"

							try:
								subject_process = process_cmd_list[process_UUID_list.index(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
							except:
								subject_process = "null"

							if (subject_process == "null"):
								try:
									subject_process = process_name_list[process_UUID_list.index(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
								except:
									subject_process = "null"

							try:
								subject_uid = process_uid_list[process_UUID_list.index(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
							except:
								subject_uid = "null"

							col2 = cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'] + ':' + subject_process + ':' + subject_uid

# 							try:
# 								col2 = cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'] + ':' + process_name_list[process_UUID_list.index(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
# 							except:
# 								col2 = cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'] + ':' + "null"

							col3 = event_type[6:]
							col4 = cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID']

							try:
								col5 = process_name_list[process_UUID_list.index(cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
							except:
								col5 = "null"

							if (col5 == "null") :

								try:
									col5 = process_name_list[process_UUID_list.index(cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
								except:
									col5 = "null"

								try:
									col5 = objects_name_list[objects_UUID_list.index(cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
								except:
									col5 = "null"

							try:
								object_uid = process_uid_list[process_UUID_list.index(cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
							except:
								object_uid = "null"

							if (object_uid == "null"):
								try:
									object_uid = objects_uid_list[objects_UUID_list.index(cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
								except:
									object_uid = "null"

							col5 = col5 + ":" + object_uid


							if (cdm_record['hostId'] == 'DF4AF963-C31C-DAFC-B5C6-D86F33322775'):
								col6 = 'ta1-trace-2'
							elif (cdm_record['hostId'] == '37345038-89F2-5899-8FD2-B6D0844A7DBF'):
								col6 = 'ta1-theia-1'
							else:
								col6 = 'null'

							thewriter.writerow([col1,col2,col3,col4,col5,col6])

							try:
								backward_object_list.index(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])
							except ValueError :
								backward_object_list.append(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])
								backward_object_path_length.append(0)


						elif  (event_type == "EVENT_WRITE" and (predicate_object == key_object or predicate_object == backward_object)):
							timestampmilliseconds = str(cdm_record_values['timestampNanos'])[:10] + '.' + str(cdm_record_values['timestampNanos'])[10:13]
							col1 = timestampmilliseconds + ':' + str(cdm_record_values['sequence']['long'])
							subject_process = "null"
							subject_uid = "null"

							try:
								subject_process = process_cmd_list[process_UUID_list.index(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
							except:
								subject_process = "null"

							if (subject_process == "null"):
								try:
									subject_process = process_name_list[process_UUID_list.index(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
								except:
									subject_process = "null"

							try:
								subject_uid = process_uid_list[process_UUID_list.index(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
							except:
								subject_uid = "null"

							col2 = cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'] + ':' + subject_process + ':' + subject_uid


							# try:
							# 	col2 = cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'] + ':' + process_name_list[process_UUID_list.index(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
							# except:
							# 	col2 = cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'] + ':' + "null"


							col3 = event_type[6:]
							col4 = cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID']

							try:
								col5 = objects_name_list[objects_UUID_list.index(cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
							except:
								col5 = "null"

							try:
								object_uid = objects_uid_list[objects_UUID_list.index(cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
							except:
								object_uid = "null"

							col5 = col5 + ":" + object_uid

							if (cdm_record['hostId'] == 'DF4AF963-C31C-DAFC-B5C6-D86F33322775'):
								col6 = 'ta1-trace-2'
							elif (cdm_record['hostId'] == '37345038-89F2-5899-8FD2-B6D0844A7DBF'):
								col6 = 'ta1-theia-1'
							else:
								col6 = 'null'

							thewriter2.writerow([col1,col2,col3,col4,col5,col6])

							try:
								backward_object_list.index(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])
							except ValueError :
								backward_object_list.append(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])
								backward_object_path_length.append(0)

						#elif  ((event_type == "EVENT_CLOSE" or event_type == "EVENT_EXIT") and (predicate_object == key_object or predicate_object == backward_object)):
						#	# EVENT_CLOSE format: timestampNanos:sequence,subject_UUID:exec,type,predicateObject_UUID,predicateObjectPath
						#	timestampmilliseconds = str(cdm_record_values['timestampNanos'])[:10] + '.' + str(cdm_record_values['timestampNanos'])[10:13]
						#	col1 = timestampmilliseconds + ':' + str(cdm_record_values['sequence']['long'])
						#	col2 = cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'] + ':' + cdm_record_values['properties']['map']['exec']
						#	#col2 = cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID']
						#	col3 = event_type[6:]
						#	col4 = cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID']
						#	#print(predicateObjectPathList)
						#	# predicateObjectPath is missing in the READ and WRITE events, so fill in them from OPEN events
						#	col5 = 'null'
						#	for predicateObject_UUID in predicateObjectUUIDLlist:
						#		if (predicateObject_UUID == col4):
						#			col5 = cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID']  + ':' + predicateObjectPathLlist[predicateObjectUUIDLlist.index(predicateObject_UUID)]
						#			break
						#	thewriter2.writerow([col1,col2,col3,col4,col5])
						#	backward_object = cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID']


						elif  (event_type == "EVENT_ACCEPT" and subject_UUID == backward_object):
							timestampmilliseconds = str(cdm_record_values['timestampNanos'])[:10] + '.' + str(cdm_record_values['timestampNanos'])[10:13]
							col1 = timestampmilliseconds + ':' + str(cdm_record_values['sequence']['long'])
							subject_process = "null"
							subject_uid = "null"

							try:
								subject_process = process_cmd_list[process_UUID_list.index(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
							except:
								subject_process = "null"

							if (subject_process == "null"):
								try:
									subject_process = process_name_list[process_UUID_list.index(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
								except:
									subject_process = "null"

							try:
								subject_uid = process_uid_list[process_UUID_list.index(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
							except:
								subject_uid = "null"

							col2 = cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'] + ':' + subject_process + ':' + subject_uid

							# try:
							# 	col2 = cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'] + ':' + process_name_list[process_UUID_list.index(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
							# except:
							# 	col2 = cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'] + ':' + "null"

							col3 = event_type[6:]
							col4 = cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID']

							try:
								col5 = objects_name_list[objects_UUID_list.index(cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
							except:
								col5 = "null"

							try:
								object_uid = objects_uid_list[objects_UUID_list.index(cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
							except:
								object_uid = "null"

							col5 = col5 + ":" + object_uid

							if (cdm_record['hostId'] == 'DF4AF963-C31C-DAFC-B5C6-D86F33322775'):
								col6 = 'ta1-trace-2'
							elif (cdm_record['hostId'] == '37345038-89F2-5899-8FD2-B6D0844A7DBF'):
								col6 = 'ta1-theia-1'
							else:
								col6 = 'null'

							thewriter.writerow([col1,col2,col3,col4,col5,col6])

							try:
								backward_object_list.index(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])
							except ValueError :
								backward_object_list.append(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])
								backward_object_path_length.append(0)


						elif  (event_type == "EVENT_CONNECT" and subject_UUID == backward_object):
							timestampmilliseconds = str(cdm_record_values['timestampNanos'])[:10] + '.' + str(cdm_record_values['timestampNanos'])[10:13]
							col1 = timestampmilliseconds + ':' + str(cdm_record_values['sequence']['long'])
							subject_process = "null"
							subject_uid = "null"

							try:
								subject_process = process_cmd_list[process_UUID_list.index(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
							except:
								subject_process = "null"

							if (subject_process == "null"):
								try:
									subject_process = process_name_list[process_UUID_list.index(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
								except:
									subject_process = "null"

							try:
								subject_uid = process_uid_list[process_UUID_list.index(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
							except:
								subject_uid = "null"

							col2 = cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'] + ':' + subject_process + ':' + subject_uid

							# try:
							# 	col2 = cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'] + ':' + process_name_list[process_UUID_list.index(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
							# except:
							# 	col2 = cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'] + ':' + "null"

							col3 = event_type[6:]
							col4 = cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID']

							try:
								col5 = objects_name_list[objects_UUID_list.index(cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
							except:
								col5 = "null"

							try:
								object_uid = objects_uid_list[objects_UUID_list.index(cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
							except:
								object_uid = "null"

							col5 = col5 + ":" + object_uid

							if (cdm_record['hostId'] == 'DF4AF963-C31C-DAFC-B5C6-D86F33322775'):
								col6 = 'ta1-trace-2'
							elif (cdm_record['hostId'] == '37345038-89F2-5899-8FD2-B6D0844A7DBF'):
								col6 = 'ta1-theia-1'
							else:
								col6 = 'null'

							thewriter.writerow([col1,col2,col3,col4,col5,col6])
							try:
								backward_object_list.index(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])
							except ValueError :
								backward_object_list.append(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])
								backward_object_path_length.append(0)


						elif  (event_type == "EVENT_MODIFY_PROCESS" and (predicate_object == key_object or predicate_object == backward_object)):
							timestampmilliseconds = str(cdm_record_values['timestampNanos'])[:10] + '.' + str(cdm_record_values['timestampNanos'])[10:13]
							col1 = timestampmilliseconds + ':' + str(cdm_record_values['sequence']['long'])
							subject_process = "null"
							subject_uid = "null"

							try:
								subject_process = process_cmd_list[process_UUID_list.index(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
							except:
								subject_process = "null"

							if (subject_process == "null"):
								try:
									subject_process = process_name_list[process_UUID_list.index(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
								except:
									subject_process = "null"

							try:
								subject_uid = process_uid_list[process_UUID_list.index(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
							except:
								subject_uid = "null"

							col2 = cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'] + ':' + subject_process + ':' + subject_uid

							# try:
							# 	col2 = cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'] + ':' + process_name_list[process_UUID_list.index(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
							# except:
							# 	col2 = cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'] + ':' + "null"

							col3 = event_type[6:]
							col4 = cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID']

							try:
								col5 = process_cmd_list[process_UUID_list.index(cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
							except:
								col5 = "null"

							if (col5 == "null"):
								try:
									col5 = process_name_list[process_UUID_list.index(cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
								except:
									col5 = "null"

								try:
									col5 = objects_name_list[objects_UUID_list.index(cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
								except:
									col5 = "null"

							try:
								object_uid = process_uid_list[process_UUID_list.index(cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
							except:
								object_uid = "null"

							if (object_uid == "null"):
								try:
									object_uid = objects_uid_list[objects_UUID_list.index(cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
								except:
									object_uid = "null"

							col5 = col5 + ":" + object_uid


							if (cdm_record['hostId'] == 'DF4AF963-C31C-DAFC-B5C6-D86F33322775'):
								col6 = 'ta1-trace-2'
							elif (cdm_record['hostId'] == '37345038-89F2-5899-8FD2-B6D0844A7DBF'):
								col6 = 'ta1-theia-1'
							else:
								col6 = 'null'

							thewriter.writerow([col1,col2,col3,col4,col5,col6])

							try:
								backward_object_list.index(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])
							except ValueError :
								backward_object_list.append(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])
								backward_object_path_length.append(0)

						elif  (event_type == "EVENT_CLONE"):
							timestampmilliseconds = str(cdm_record_values['timestampNanos'])[:10] + '.' + str(cdm_record_values['timestampNanos'])[10:13]
							col1 = timestampmilliseconds + ':' + str(cdm_record_values['sequence']['long'])
							subject_process = "null"
							subject_uid = "null"

							try:
								subject_process = process_cmd_list[process_UUID_list.index(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
							except:
								subject_process = "null"

							if (subject_process == "null"):
								try:
									subject_process = process_name_list[process_UUID_list.index(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
								except:
									subject_process = "null"

							try:
								subject_uid = process_uid_list[process_UUID_list.index(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
							except:
								subject_uid = "null"

							try:
								col2 = cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'] + ':' + subject_process + ':' + subject_uid
							except:
								col2 = cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'] + ':' + subject_process + ':' + "null"
								print("Case of UnicodeDecodeError:")
								print (subject_uid)

							col3 = event_type[6:]
							col4 = cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID']

							try:
								col5 = process_cmd_list[process_UUID_list.index(cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
							except:
								col5 = "null"

							if (col5 == "null") :
								try:
									col5 = process_name_list[process_UUID_list.index(cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
								except:
									col5 = "null"

								try:
									col5 = objects_name_list[objects_UUID_list.index(cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
								except:
									col5 = "null"

							try:
								object_uid = process_uid_list[process_UUID_list.index(cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
							except:
								object_uid = "null"

							if (object_uid == "null"):
								try:
									object_uid = objects_uid_list[objects_UUID_list.index(cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
								except:
									object_uid = "null"

							col5 = col5 + ":" + object_uid

							if (cdm_record['hostId'] == 'DF4AF963-C31C-DAFC-B5C6-D86F33322775'):
								col6 = 'ta1-trace-2'
							elif (cdm_record['hostId'] == '37345038-89F2-5899-8FD2-B6D0844A7DBF'):
								col6 = 'ta1-theia-1'
							else:
								col6 = 'null'

							thewriter.writerow([col1,col2,col3,col4,col5,col6])

							try:
								backward_object_list.index(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])
							except ValueError :
								backward_object_list.append(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])
								backward_object_path_length.append(0)


						elif  (event_type == "EVENT_CHANGE_PRINCIPAL" and (predicate_object == key_object or predicate_object == backward_object)):
							timestampmilliseconds = str(cdm_record_values['timestampNanos'])[:10] + '.' + str(cdm_record_values['timestampNanos'])[10:13]
							col1 = timestampmilliseconds + ':' + str(cdm_record_values['sequence']['long'])

							try:

								col2 = cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'] + ':' + process_name_list[process_UUID_list.index(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
							except:
								col2 = cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'] + ':' + "null"

							col3 = event_type[6:]
							col4 = cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID']

							try:
								col5 = process_name_list[process_UUID_list.index(cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID'])]
							except:
								col5 = "null"

							if (cdm_record['hostId'] == 'DF4AF963-C31C-DAFC-B5C6-D86F33322775'):
								col6 = 'ta1-trace-2'
							elif (cdm_record['hostId'] == '37345038-89F2-5899-8FD2-B6D0844A7DBF'):
								col6 = 'ta1-theia-1'
							else:
								col6 = 'null'

							thewriter.writerow([col1,col2,col3,col4,col5,col6])

							try:
								backward_object_list.index(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])
							except ValueError :
								backward_object_list.append(cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'])
								backward_object_path_length.append(0)

						#elif  (event_type == "EVENT_SENDTO" and (predicate_object == key_object or predicate_object == backward_object)):
						#	timestampmilliseconds = str(cdm_record_values['timestampNanos'])[:10] + '.' + str(cdm_record_values['timestampNanos'])[10:13]
						#	col1 = timestampmilliseconds + ':' + str(cdm_record_values['sequence']['long'])
						#	col2 = cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'] + ':' + cdm_record_values['properties']['map']['exec']
						#	col3 = event_type[6:]
						#	col4 = cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID']
						#	#print(predicateObjectPathList)
						#	# predicateObjectPath is missing in the READ and WRITE events, so fill in them from OPEN events
						#	col5 = 'null'
						#	for predicateObject_UUID in predicateObjectUUIDLlist:
						#		if (predicateObject_UUID == col4):
						#			col5 = predicateObjectPathLlist[predicateObjectUUIDLlist.index(predicateObject_UUID)]
						#			break
						#	if (cdm_record['hostId'] == 'A3702F4C-5A0C-11E9-B8B9-D4AE52C1DBD3'):
						#		col6 = 'ta1-cadets-1'
						#	elif (cdm_record['hostId'] == '3A541941-5B04-11E9-B2DB-D4AE52C1DBD3'):
						#		col6 = 'ta1-cadets-2'
						#	elif (cdm_record['hostId'] == 'CB02303B-654E-11E9-A80C-6C2B597E484C'):
						#		col6 = 'ta1-cadets-3'
						#	else:
						#		col6 = 'null'
						#	thewriter.writerow([col1,col2,col3,col4,col5,col6])
						#	backward_object = cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID']
						#	path_len +=1

			print("backwardObjectPathLengths:")
			print(backward_object_path_length)
			elapsed_time = time.time() - start_time_slice
			print("")
			print ("Time taken (in minutes) for processing ", log_file , "is:" , elapsed_time/60)
			try:
				# with open('./extraction_proof/' + log_file, 'x') as file:
				# 	file.write("")
				# 	file.close()
				open('./extraction_proof/' + log_file, 'x').close()
			except FileExistsError:
				open('./extraction_proof/' + log_file, 'a').close()




#print("backwardlist_at_end:")
#print(backward_object_list)

#print("backwardObjectPathLengths:")
#print(backward_object_path_length)
print ("Done...")
elapsed_time = time.time() - start_time
print("")
print ("Total Time taken (min):", elapsed_time/60)



# now filling in the missing predicateObjectPath
#print ("Whoami analysis is ready. Starting filling Null values")
#outfile.close()
#outfile2.close()


#with open('whoami_forward.csv') as csv_file1:
#	csv_reader1 = csv.reader(csv_file1, delimiter=',')
#	with open('whoami_forward_final.csv', 'w') as outfile_final:
#		thewriter_final = csv.writer(outfile_final)
 #
#		for row in csv_reader1:
#			if row[4] <> "null":
#				thewriter_final.writerow([row[0], row[1], row[2], row[3], row[4]])
#				print ("not null")
#			else :
#				for predicateObject_UUID in predicateObjectUUIDLlist:
#					print ("Comparison predicateObject_UUID:", predicateObject_UUID, "and row 3:" , row[3])
#					if (predicateObject_UUID == row[3]):
#						col5 = row[3] + ':' + predicateObjectPathLlist[predicateObjectUUIDLlist.index(predicateObject_UUID)]
#						print ("match found in case of null", col5)
#						break
#					else:
#						col5 = row[3] + ':' + "null"
#				thewriter_final.writerow([row[0], row[1], row[2], row[3], col5])





				#if (col5 == "null" and (event_type == "EVENT_CLOSE" or event_type == "EVENT_EXIT" or event_type == "EVENT_WRITE" or event_type == "EVENT_FORK" or event_type == "EVENT_READ")):
				#	with open('ta1-cadets-1-e5-official-2.bin.100.json.1') as jsondata1:
				#	    for line1 in jsondata1:
				#		cdm_record1 = json.loads(line1.strip())
				#		cdm_record_type1 = cdm_record1['datum'].keys()[0]
				#		cdm_record_values1 = cdm_record1['datum'][cdm_record_type1]
				#		if (cdm_record_type1 == "com.bbn.tc.schema.avro.cdm20.Event" and cdm_record_values1['type'] == "EVENT_OPEN"):
				#			if (cdm_record_values1['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID'] == col4):
				#				col5 = cdm_record_values1['predicateObjectPath']['string']
				#	thewriter.writerow([col1,col2,col3,col4,col5])
#			if (cdm_record_values["timestampNanos"] >= DateFrom and cdm_record_values["timestampNanos"] <= DateTo):
#				#   print("Record ", i,"is", cdm_record_values)
#				#    i = i + 1;
#				json.dump(cdm_record_values, outfile)
#				outfile.write(",\n")
#				print("Record ", i,"is", cdm_record_values)
#				i =i +1
#
#print ("total number of records:", i)
#print ("Attack stage extracted successfuly")
# Search data based on key and value using filter and list method
#print(list(filter(lambda x:x["timestampNanos"]=="1522949718807923603",data)))

# Input the key value that you want to search
#Val = input("Enter value: \n")

# load the json data
#event = json.loads(eventData)
# Search the key value using 'in' operator
#if cdm_record["datum"]["com.bbn.tc.schema.avro.cdm18.Event"]["timestampNanos"] == Val:
    # Print the success message and the value of the key
#    print("%s is found in JSON data" %Val)
#    print("The record of", Val,"is", cdm_record)
#else:
    # Print the message if the value does not exist
#    print("%s is not found in JSON data" %Val)









