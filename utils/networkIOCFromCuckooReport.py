import json
import sys
import time

input_file=open(sys.argv[1], 'r')
#output_file=open(sys.argv[2], 'w')
output_file=sys.stdout
json_decode=json.load(input_file)

line = "Parsing report ... " 
if "pubsub_msg_id" in json_decode["info"]["options"]:
   line += "msg_id: " + json_decode["info"]["options"]["pubsub_msg_id"]
   if "function" in json_decode["info"]["options"]:
      line += " functon: " + json_decode["info"]["options"]["function"]

else:
   line += "task # " + str(json_decode["info"]["id"]) 

line += "\n"


#import requests
#params = {'apikey': 'e90566743fd453ed78a64d7a39f8ed3dc9b7006a2c9c528e34749cabdb3c4574', 'resource': ''}
#headers = {
#  "Accept-Encoding": "gzip, deflate",
#  "User-Agent" : "gzip,  My Python requests library example client or username"
#  }
linePrefix = json_decode["target"]["file"]["sha256"] + ","
for entry in json_decode["network"]["domains"]:
   line += linePrefix + ",domain,"
   line += entry["domain"] + "\n"
for entry in json_decode["network"]["http"]:
   line += linePrefix + ",http,"
   line += entry["host"] + "," + entry["method"] + "," + str(entry["port"]) + "," + entry["uri"] + "," + entry["path"] + "," + entry["user-agent"] + "\n"

for entry in json_decode["network"]["tcp"]:
   line += linePrefix + ",tcp,"
   line += "src," + entry["src"] + ":" + str(entry["sport"]) + "\n"
   line += linePrefix + ",tcp,"
   line += "dest," + entry["dst"] + ":" + str(entry["dport"]) + "\n"
for entry in json_decode["network"]["udp"]:
   line += linePrefix + ",udp,"
   line += "src," + entry["src"] + ":" + str(entry["sport"]) + "\n"
   line += linePrefix + ",udp,"
   line += "dest," + entry["dst"] + ":" + str(entry["dport"]) + "\n"

#for entry in json_decode["network"]["http"]:
#   line += linePrefix + ",http-details,"
#   line += entry["host"] + "," + entry["method"] + "," + str(entry["port"]) + "," + entry["uri"] + "," + entry["path"] + entry["user-agent"] + "," + entry["data"] + "\n"

output_file.write(line)

output_file.close() 
