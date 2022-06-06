#!/usr/bin/env python3


###################################
######   DARPA Parser  ############
## This script extracts    #######
# attack data events    ##########
###    in stages     #############
# based on the ground truth ######
## Author: Moustafa Mahmoud ######
## Concordia University #########
#################################

# Import json module
import json
import csv

i =1
# Open the existing JSON file for loading into a variable
#Val = input("Enter value: \n")
#DateFrom = 1523028060000000000
DateFrom  = 1558015140000000000
#DateTo   = 1523031000000000000
DateTo    = 1558015860000000000
#with open('attack-initial-comp', 'w') as outfile:
with open('nginx_A28B-D4AE52C1DBD3_backwards.csv', 'w') as outfile2:
	with open('nginx_A28B-D4AE52C1DBD3_forward.csv', 'w') as outfile:
		thewriter = csv.writer(outfile)
		thewriter2 = csv.writer(outfile2)		
		predicateObjectUUIDLlist = []
		predicateObjectPathLlist = []
		predicateObjectPath_index=0
		with open('nginx_A28B-D4AE52C1DBD3.json') as jsondata:
		    for line in jsondata:
			cdm_record = json.loads(line.strip())
			cdm_record_type = cdm_record['datum'].keys()[0]
			cdm_record_values = cdm_record['datum'][cdm_record_type]
			if (cdm_record_type == "com.bbn.tc.schema.avro.cdm20.Event"):			
				event_type = cdm_record_values['type']
				if  (event_type == "EVENT_OPEN"):
					# EVENT_OPEN format: timestampNanos:sequence,subject_UUID:exec,type,predicateObject_UUID,predicateObjectPath
					timestampmilliseconds = str(cdm_record_values['timestampNanos'])[:10] + '.' + str(cdm_record_values['timestampNanos'])[10:13]			
					col1 = timestampmilliseconds + ':' + str(cdm_record_values['sequence']['long'])
					col2 = cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'] + ':' + cdm_record_values['properties']['map']['exec']
					col3 = event_type[6:]
					col4 = cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID']
					col5 = cdm_record_values['predicateObjectPath']['string']
					thewriter.writerow([col1,col2,col3,col4,col5])
					predicateObjectUUIDLlist.append(col4)
					predicateObjectPathLlist.append(col5)
		#			print(cdm_record_values)
		#			print(predicateObjectPathList)
				elif  (event_type == "EVENT_READ"):
					# EVENT_READ format: timestampNanos:sequence,subject_UUID:exec,type,predicateObject_UUID,predicateObjectPath
					timestampmilliseconds = str(cdm_record_values['timestampNanos'])[:10] + '.' + str(cdm_record_values['timestampNanos'])[10:13]			
					col1 = timestampmilliseconds + ':' + str(cdm_record_values['sequence']['long'])
					col2 = cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'] + ':' + cdm_record_values['properties']['map']['exec']
					col3 = event_type[6:]
					col4 = cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID']
					#print(predicateObjectPathList)
					# predicateObjectPath is missing in the READ and WRITE events, so fill in them from OPEN events
					col5 = 'null'				
					for predicateObject_UUID in predicateObjectUUIDLlist:
						if (predicateObject_UUID == col4):
							col5 = predicateObjectPathLlist[predicateObjectUUIDLlist.index(predicateObject_UUID)]
							break					
					#thewriter.writerow([col1,col2,col3,col4,col5])
				elif  (event_type == "EVENT_FORK"):
					# EVENT_FORK format: timestampNanos:sequence,subject_UUID:exec,type,predicateObject_UUID,predicateObjectPath
					timestampmilliseconds = str(cdm_record_values['timestampNanos'])[:10] + '.' + str(cdm_record_values['timestampNanos'])[10:13]			
					col1 = timestampmilliseconds + ':' + str(cdm_record_values['sequence']['long'])
					col2 = cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'] + ':' + cdm_record_values['properties']['map']['exec']
					col3 = event_type[6:]
					col4 = cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID']
					#print(predicateObjectPathList)
					# predicateObjectPath is missing in the READ and WRITE events, so fill in them from OPEN events
					col5 = 'null'
					for predicateObject_UUID in predicateObjectUUIDLlist:
						if (predicateObject_UUID == col4):
							col5 = predicateObjectPathLlist[predicateObjectUUIDLlist.index(predicateObject_UUID)]
							break					
					#thewriter.writerow([col1,col2,col3,col4,col5])			
				elif  (event_type == "EVENT_EXECUTE"):
					timestampmilliseconds = str(cdm_record_values['timestampNanos'])[:10] + '.' + str(cdm_record_values['timestampNanos'])[10:13]			
					col1 = timestampmilliseconds + ':' + str(cdm_record_values['sequence']['long'])
					#omit the path from predicateObjectPath, to make the subject executable same as in other EVENTS (no path there). 
					col2 = cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'] + ':' + cdm_record_values['predicateObjectPath']['string'].split('/')[-1]
					col3 = event_type[6:]
					col4 = 0
					col5 = cdm_record_values['properties']['map']['cmdLine']
					thewriter.writerow([col1,col2,col3,col4,col5])
				elif  (event_type == "EVENT_WRITE"):
					# EVENT_WRITE format: timestampNanos:sequence,subject_UUID:exec,type,predicateObject_UUID,predicateObjectPath
					timestampmilliseconds = str(cdm_record_values['timestampNanos'])[:10] + '.' + str(cdm_record_values['timestampNanos'])[10:13]			
					col1 = timestampmilliseconds + ':' + str(cdm_record_values['sequence']['long'])
					col2 = cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'] + ':' + cdm_record_values['properties']['map']['exec']
					col3 = event_type[6:]
					col4 = cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID']
					#print(predicateObjectPathList)
					# predicateObjectPath is missing in the READ and WRITE events, so fill in them from OPEN events
					col5 = 'null'
					for predicateObject_UUID in predicateObjectUUIDLlist:
						if (predicateObject_UUID == col4):
							col5 = predicateObjectPathLlist[predicateObjectUUIDLlist.index(predicateObject_UUID)]
							break						
					#thewriter2.writerow([col1,col2,col3,col4,col5])
				elif  (event_type == "EVENT_CLOSE" or event_type == "EVENT_EXIT"):
					# EVENT_CLOSE format: timestampNanos:sequence,subject_UUID:exec,type,predicateObject_UUID,predicateObjectPath
					timestampmilliseconds = str(cdm_record_values['timestampNanos'])[:10] + '.' + str(cdm_record_values['timestampNanos'])[10:13]			
					col1 = timestampmilliseconds + ':' + str(cdm_record_values['sequence']['long'])
					col2 = cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'] + ':' + cdm_record_values['properties']['map']['exec']
					col3 = event_type[6:]
					col4 = cdm_record_values['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID']
					#print(predicateObjectPathList)
					# predicateObjectPath is missing in the READ and WRITE events, so fill in them from OPEN events
					col5 = 'null'
					for predicateObject_UUID in predicateObjectUUIDLlist:
						if (predicateObject_UUID == col4):
							col5 = predicateObjectPathLlist[predicateObjectUUIDLlist.index(predicateObject_UUID)]
							break							
					#thewriter2.writerow([col1,col2,col3,col4,col5])	
				elif  (event_type == "EVENT_ACCEPT"):
					# EVENT_READ format: timestampNanos:sequence,subject_UUID:exec,type,predicateObject_UUID,predicateObjectPath
					timestampmilliseconds = str(cdm_record_values['timestampNanos'])[:10] + '.' + str(cdm_record_values['timestampNanos'])[10:13]			
					col1 = timestampmilliseconds + ':' + str(cdm_record_values['sequence']['long'])
					col2 = cdm_record_values['subject']['com.bbn.tc.schema.avro.cdm20.UUID'] + ':' + cdm_record_values['properties']['map']['exec']
					col3 = event_type[6:]
					col4 = cdm_record_values['predicateObject2']['com.bbn.tc.schema.avro.cdm20.UUID']
					#print(predicateObjectPathList)
					# predicateObjectPath is missing in the READ and WRITE events, so fill in them from OPEN events
					col5 = cdm_record_values['properties']['map']['address']
					thewriter.writerow([col1,col2,col3,col4,col5])
				if (col5 == "null" and (event_type == "EVENT_CLOSE" or event_type == "EVENT_EXIT" or event_type == "EVENT_WRITE" or event_type == "EVENT_FORK" or event_type == "EVENT_READ")):
					with open('ta1-cadets-1-e5-official-2.bin.100.json.1') as jsondata1:
					    for line1 in jsondata1:
						cdm_record1 = json.loads(line1.strip())
						cdm_record_type1 = cdm_record1['datum'].keys()[0]
						cdm_record_values1 = cdm_record1['datum'][cdm_record_type1]						
						if (cdm_record_type1 == "com.bbn.tc.schema.avro.cdm20.Event" and cdm_record_values1['type'] == "EVENT_OPEN"):
							if (cdm_record_values1['predicateObject']['com.bbn.tc.schema.avro.cdm20.UUID'] == col4):
								col5 = cdm_record_values1['predicateObjectPath']['string']
					thewriter.writerow([col1,col2,col3,col4,col5])		
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









