import json
import sys
import time

input_file=open(sys.argv[1], 'r')
#output_file=open(sys.argv[2], 'w')
json_decode=json.load(input_file)

entry = json_decode["signatures"]
line = ( 
         
         "sha256" +
         ",vt" +
         "\n"
       )

sys.stdout.write(line)

line = json_decode["target"]["file"]["sha256"]  + ","
for entry in json_decode["signatures"]:
   #line = entry["id"]
   #line += "," + entry["info"]["file"]["originalFilePath"]
   #lengthHashes = len(entry["info"]["file"]["hashes"]["hash_list"])
   #line += "," + entry["info"]["file"]["hashes"]["hash_list"][lengthHashes-1]["value"]
   #line += "," + entry["info"]["file"]["hashes"]["hash_list"][lengthHashes-3]["value"]

   if "name" in entry and entry["name"] == "antivirus_virustotal":
      for d in entry["data"]:
         line += d.keys()[0] + ":" + d.values()[0] + ","
      line += "\n"
      
sys.stdout.write(line)
