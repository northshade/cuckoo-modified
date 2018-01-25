# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import json
import logging
from google.cloud import pubsub
from urllib import quote

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooReportError

log = logging.getLogger(__name__)

class PublishResultToGooglePubSub(Report):
    """Saves analysis results in JSON format."""

    def run(self, results):
        """Publishes to google pubsub results topic
        @param results: Cuckoo results dict.
        @raise CuckooReportError: if fails.
        """
 

        try:
           processed_msg_id = results["info"]["options"].get("pubsub_msg_id", None)
           if (processed_msg_id != None):
              pubsub_client = pubsub.Client()

              sample_sha256 = results["target"]["file"]["sha256"]
              analysis_path = self.analysis_path
              os.system("python utils/networkIOCFromCuckooReport.py " + analysis_path + "/reports/report.json | grep -vf utils/networkWhiteList.txt | sed -e \"s/\./\.\./g\" > " + self.analysis_path + "/networkIOC.txt")

              if "function" in results["info"]["options"]:
                 results_folder = "gs://a1s-zoombox/zOOmed/" + sample_sha256[0:2] + "/" + sample_sha256[2:4] +  "/" + sample_sha256 + "/" + processed_msg_id + "/" + results["info"]["package"] + "/" + results["info"]["options"]["function"] + "/"
                 os.system("gsutil -m cp -r " + analysis_path + "/* gs://" + quote("a1s-zoombox/zOOmed/" + sample_sha256[0:2] + "/" + sample_sha256[2:4] +  "/" + sample_sha256 + "/" + processed_msg_id + "/" + results["info"]["package"] + "/" + results["info"]["options"]["function"] + "/" ))
              else:
                 os.system("gsutil -m cp -r " + analysis_path + "/* gs://" +  quote("a1s-zoombox/zOOmed/" + sample_sha256[0:2] + "/" + sample_sha256[2:4] +  "/" + sample_sha256 + "/" + processed_msg_id + "/" + results["info"]["package"] + "/"))
                 results_folder = "gs://a1s-zoombox/zOOmed/" + sample_sha256[0:2] + "/" + sample_sha256[2:4] +  "/" + sample_sha256 + "/" + processed_msg_id + "/" + results["info"]["package"] + "/"




              #publish completion message to topic
              topic = pubsub_client.topic(self.options['pubsub_topic'])
              message_id = topic.publish(u'Detonation complete. Results uploaded.', upload_folder = results_folder, processed_msg_id = processed_msg_id, sha256 = sample_sha256)

              log.info(u"Message published to pubsub with message_id %s at: %s" % (message_id, results_folder))
        except (UnicodeError, TypeError, IOError) as e:
           raise CuckooReportError("Failed to publish results: %s" % e)
