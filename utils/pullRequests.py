#!/usr/bin/env python

import base64
import sys
import json
import os
import traceback
from google.cloud import pubsub

PUBSUB_TOPIC="zoombox-requests"
SUBSCRIPTION_NAME="zoombox-recieveRequests"

#Usage: pullRequests.py <path to store samples to> 

def create_subscription(topic_name, subscription_name):
    """Create a new pull subscription on the given topic."""
    pubsub_client = pubsub.Client()
    topic = pubsub_client.topic(topic_name)

    subscription = topic.subscription(subscription_name)
    subscription.create()

    print('Subscription {} created on topic {}.'.format(
        subscription.name, topic.name))

def get_topic_policy(topic_name):
    """Prints the IAM policy for the given topic."""
    pubsub_client = pubsub.Client()

    topic = pubsub_client.topic(topic_name)

    policy = topic.get_iam_policy()

    print('Policy for topic {}:'.format(topic.name))
    print('Version: {}'.format(policy.version))
    print('Owners: {}'.format(policy.owners))
    print('Editors: {}'.format(policy.editors))
    print('Viewers: {}'.format(policy.viewers))
    print('Publishers: {}'.format(policy.publishers))
    print('Subscribers: {}'.format(policy.subscribers))

def create_subscription(topic_name, subscription_name):
    """Create a new pull subscription on the given topic."""
    pubsub_client = pubsub.Client()
    topic = pubsub_client.topic(topic_name)

    subscription = topic.subscription(subscription_name)
    subscription.create()

    print('Subscription {} created on topic {}.'.format(
        subscription.name, topic.name))

def receive_message(topic_name, subscription_name):
    """Receives a message from a pull subscription."""
    pubsub_client = pubsub.Client()
    topic = pubsub_client.topic(topic_name)
    subscription = topic.subscription(subscription_name)

    # Change return_immediately=False to block until messages are
    # received.
    results = subscription.pull(return_immediately=False)

    print('Received {} messages.'.format(len(results)))

    # Acknowledge received messages. If you do not acknowledge, Pub/Sub will
    # redeliver the message.
    if results:
        for ack_id, message in results:
           print('processing message: {}'.format(message.message_id))
           subscription.acknowledge(ack_id)
           process_message(message.message_id, json.loads(base64.decodestring(message.data)))
           print('     done processing message: {}:'.format(message.message_id))

def copyFileFromCloud(filehash, dest):
   os.system("gsutil -m cp gs://a1s-zoombox/files/" + filehash[0:2] + "/" + filehash[2:4] +  "/" + filehash + " " + dest)

def process_message(msg_id, json_decode):
   for entry in json_decode["coreReport"]["entries"]["entry_list"]:
      try:
         lengthHashes = len(entry["info"]["file"]["hashes"]["hash_list"])
         filehash =  entry["info"]["file"]["hashes"]["hash_list"][lengthHashes-1]["value"] 
         dst = sys.argv[1] 
         if entry["info"]["file"]["fileType"] == "Document":
            copyFileFromCloud(filehash, dst)
            os.system("./submit.py  --machine Win7 --package doc --enforce-timeout --timeout 120 --options=pubsub_msg_id=" + msg_id + " " +  dst + "/" + filehash)
         elif entry["info"]["file"]["fileSubype"] == "Dll"  and entry["info"]["file"]["fileType"] == "PE": 
            copyFileFromCloud(filehash, dst)
            os.system("sample=" + dst + "/" + filehash + ";for i in `pedump -E $sample | grep -E '^ *[0-9]' | sed -e 's/  */ /g' | cut -f 4 -d ' '`;do ./submit.py  --machine Win7 --package dll --options function=$i,pubsub_msg_id=" + msg_id + " $sample;done")
            # run with cuckoo's own determination of using approporate package such as regserver
            os.system("sample=" + dst + "/" + filehash + ";./submit.py  --machine Win7 --options pubsub_msg_id=" + msg_id + " $sample;done")

            grepForServiceMain = os.system("sample=" + dst + "/" + filehash + ';pedump -E $sample | grep -E "^ *[0-9]" | sed -e "s/  */ /g" | cut -f 4 -d " "  | grep "ServiceMain"') 
            if grepForServiceMain == 0:
               os.system("sample=" + dst + "/" + filehash + ';./submit.py  --machine Win7 --package service --options pubsub_msg_id=' + msg_id + " $sample")
              
         elif entry["info"]["file"]["fileSubype"] == "Dll"  and entry["info"]["file"]["fileType"] == "PE+": 
            copyFileFromCloud(filehash, dst)
            os.system("sample=" + dst + "/" + filehash + ";for i in `pedump -E $sample | grep -E '^ *[0-9]' | sed -e 's/  */ /g' | cut -f 4 -d ' '`;do ./submit.py  --machine win7x64 --package dll --options function=$i,pubsub_msg_id=" + msg_id + " $sample;done")
            # run with cuckoo's own determination of using approporate package such as regserver
            os.system("sample=" + dst + "/" + filehash + ";./submit.py  --machine win7x64 --options pubsub_msg_id=" + msg_id + " $sample;done")
         elif  entry["info"]["file"]["fileType"] == "SWF" or entry["info"]["file"]["fileType"] == "Video": 
            copyFileFromCloud(filehash, dst)
            os.system("sample=" + dst + "/" + filehash + ";./submit.py  --package swf --machine Win7 --options pubsub_msg_id=" + msg_id + " $sample;done")
         elif  entry["info"]["file"]["fileType"] == "PE+": 
            copyFileFromCloud(filehash, dst)
            os.system("sample=" + dst + "/" + filehash + ";./submit.py  --machine win7x64 --options pubsub_msg_id=" + msg_id + " $sample;done")
         elif  entry["info"]["file"]["fileType"] == "PE": 
            copyFileFromCloud(filehash, dst)
            os.system("sample=" + dst + "/" + filehash + ";./submit.py  --machine Win7 --options pubsub_msg_id=" + msg_id + " $sample;done")
         elif entry["info"]["file"]["fileType"] == "blah 2":
           print "Detonating ..."
         else:
            os.system("echo can\\'t detonate fileType:" + entry["info"]["file"]["fileType"] )  
      except Exception as e:
          error_exc = traceback.format_exc()
          print error_exc


def check_topic_permissions(topic_name):
    """Checks to which permissions are available on the given topic."""
    pubsub_client = pubsub.Client()
    topic = pubsub_client.topic(topic_name)

    permissions_to_check = [
        'pubsub.subscriptions.create',
        'pubsub.topics.attachSubscription',
        'pubsub.topics.publish',
        'pubsub.topics.update'
    ]

    allowed_permissions = topic.check_iam_permissions(permissions_to_check)

    print('Allowed permissions for topic {}: {}'.format(
        topic.name, allowed_permissions))


if __name__ == '__main__':

   
   #get_topic_policy(PUBSUB_TOPIC)
   #check_topic_permissions(PUBSUB_TOPIC)
   #create_subscription(PUBSUB_TOPIC, SUBSCRIPTION_NAME)
   while True:
      try:
         receive_message(PUBSUB_TOPIC, SUBSCRIPTION_NAME)
      except Exception as e:
          error_exc = traceback.format_exc()
          print error_exc
