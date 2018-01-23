#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

"""
  (1,"High","*high* means sophisticated APT malware or 0-day attack","Sophisticated APT malware or 0-day attack"),
  (2,"Medium","*medium* means APT malware","APT malware"),
  (3,"Low","*low* means mass-malware","Mass-malware"),
  (4,"Undefined","*undefined* no risk","No risk");
"""

import os
import json
import logging
import threading
from collections import deque
from datetime import datetime
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.constants import CUCKOO_ROOT
from tldextract import extract

# import for creating objects
from pymisp.tools import make_binary_objects, GenericObjectGenerator
import traceback

#######################

PYMISP = False
try:
    from pymisp import PyMISP
    from pymisp.mispevent import MISPObjectReference
    PYMISP = True
except ImportError:
    pass

log = logging.getLogger(__name__)

class MISP(Report):
    """MISP Analyzer."""

    order = 1

    def add_file(self, event_id, path, filename, object_type):

        fo = None
        peo = None
        seos = None

       # try:
        if not object_type == "master":
            dap = {"category": "Artifacts dropped"}#, "self.sharing_group_id": None, "distribution": 5}
            fo, peo, seos = make_binary_objects(path, filename=filename, default_attributes_parameters=dap)
        else:
            fo, peo, seos = make_binary_objects(path, filename=filename)
     #   except Exception as e:
      #      traceback.print_exc()

        if seos and self.options.get("seo", False):
            for s in seos:
                template_id = self.misp.get_object_template_id(s.template_uuid)
                r = self.misp.add_object(event_id, template_id, s)

        if peo and self.options.get("peo", False):
            template_id = self.misp.get_object_template_id(peo.template_uuid)
            r = self.misp.add_object(event_id, template_id, peo)
            for ref in peo.ObjectReference:
                r = self.misp.add_object_reference(ref)

        if fo:
            template_id = self.misp.get_object_template_id(fo.template_uuid)
            response = self.misp.add_object(event_id, template_id, fo)
            if self.options.get("seo", False) or self.options.get("peo", False): 
                for ref in fo.ObjectReference:
                    r = self.misp.add_object_reference(ref)

        if fo and object_type == 'master':
            self.master_obj = fo
        else:
            self.slaves_id.append(fo.uuid)


    def cuckoo2misp_thread(self, iocs, event):
        event_id = event['Event']['id']

        while iocs:

            ioc = iocs.pop()
            if ioc.get("md5"):
                self.misp.add_hashes(event,
                                 md5=ioc["md5"],
                                 sha1=ioc["sha1"],
                                 sha256=ioc["sha256"]
                )
            elif ioc.get("file_obj", ""):
                self.add_file(event_id, ioc["path"], ioc["filename"], ioc["file_obj"])
            elif ioc.get("domain_obj", ""):
                template_id = [x['ObjectTemplate']['id'] for x in self.misp.get_object_templates_list() if x['ObjectTemplate']['name'] == 'domain-ip'][0]
                misp_object = GenericObjectGenerator('domain-ip')
                misp_object.generate_attributes(json.loads(ioc['domain_obj']))
                self.misp.add_object(event_id, template_id, misp_object)
                self.slaves_id.append(misp_object.uuid)
            elif ioc.get("uri_obj", ""):
                template_id = [x['ObjectTemplate']['id'] for x in self.misp.get_object_templates_list() if x['ObjectTemplate']['name'] == 'http-request'][0]
                misp_object = GenericObjectGenerator('http-request')
                misp_object.generate_attributes(json.loads(ioc['uri_obj']))
                self.misp.add_object(event_id, template_id, misp_object)
                self.slaves_id.append(misp_object.uuid)
            elif ioc.get("uri", ""):
                self.misp.add_url(event, ioc["uri"])
            elif ioc.get("mutex", ""):
                self.misp.add_mutex(event, ioc["mutex"])
            elif ioc.get("regkey", ""):
                self.misp.add_regkey(event, ioc["regkey"])

    def cuckoo2misp(self, results, whitelist, whitelist_ua, tag_ids):

        distribution = int(self.options.get("distribution", 0))
        threat_level_id = int(self.options.get("threat_level_id", 2))
        analysis = int(self.options.get("analysis", 2))

        iocs = deque()
        malfamily = ""
        filtered_iocs = deque()
        threads_list = list()

        if results.get("malfamily", ""):
            malfamily = " - {}".format(results["malfamily"])

        comment = "{} {}{}".format(self.options.get("title", ""), results.get('info', {}).get('id'), malfamily)
        
        if results.get("target", {}).get("url", "") and extract(results["target"]["url"]).registered_domain not in whitelist:                      
            iocs.append({"uri": results["target"]["url"]})
            filtered_iocs.append(extract(results["target"]["url"]).registered_domain)

        if self.options.get("network", False) and "network" in results.keys():
            for block in results["network"].get("hosts", []):
                if block.get("hostname", "") and block.get("ip", "") and (extract(block["hostname"]).registered_domain not in whitelist and extract(block["hostname"]).registered_domain not in filtered_iocs) and (block["ip"] not in whitelist and block["ip"] not in filtered_iocs):
                    iocs.append({"domain_obj": """[{"domain": "%s"}, {"ip": "%s"}]""" % (block["hostname"], block["ip"])})
                    filtered_iocs.append(extract(block["hostname"]).registered_domain)
                    filtered_iocs.append(block["ip"])

            for req in results["network"].get("http", []):
                if "uri" in req and extract(req["uri"]).registered_domain not in whitelist and "user-agent" in req and not req["user-agent"].startswith(tuple(whitelist_ua)): 
                    if req["uri"] not in filtered_iocs:
                        iocs.append({"uri_obj": """[{"uri": "%s"}, {"method": "%s"}, {"user-agent": "%s"}]""" % (req["uri"], req['method'], req["user-agent"])})
                        filtered_iocs.append(req["uri"])
                       
        if self.options.get("ids_files", False) and "suricata" in results.keys():
            for surifile in results["suricata"]["files"]:
                if "file_info" in surifile.keys():
                    iocs.append({"md5": surifile["file_info"]["md5"],
                                "sha1": surifile["file_info"]["sha1"],
                                "sha256": surifile["file_info"]["sha256"]
                    })

        if self.options.get("mutexes", False) and "behavior" in results and "summary" in results["behavior"]:
            if "mutexes" in results.get("behavior", {}).get("summary", {}):
                for mutex in results["behavior"]["summary"]["mutexes"]:
                    if mutex not in whitelist and mutex not in filtered_iocs:
                        iocs.append({"mutex": mutex})
                        filtered_iocs.append(mutex)

        if self.options.get("dropped", False) and "dropped" in results:
            for entry in results["dropped"]:
                if entry["md5"] and (entry["md5"] not in filtered_iocs and entry["md5"] not in whitelist) and "PE32" in entry["type"]:
                    filtered_iocs.append(entry["md5"])
                    #iocs.append({"md5": entry["md5"], "sha1": entry["sha1"], "sha256": entry["sha256"] })
                    iocs.append({"file_obj": "dropped", "path": entry['path'], "filename": entry['name']})
                    
        if self.options.get("registry", False) and "behavior" in results and "summary" in results["behavior"]:
            if "read_keys" in results["behavior"].get("summary", {}):
                for regkey in results["behavior"]["summary"]["read_keys"]:
                    if regkey not in whitelist and regkey not in filtered_iocs:
                        iocs.append({"regkey": regkey})
                        filtered_iocs.append(regkey)


        if "target" in results and "file" in results['target'] and "path" in results['target']['file']:
            file_obj = results['target']['file']
            iocs.append({"file_obj": "master", "path": file_obj['path'], "filename": file_obj['name']})

        ########## creo evento
        event = self.misp.new_event(distribution, threat_level_id, analysis, comment, date=datetime.now().strftime('%Y-%m-%d'), published=True)
        event_id = event['Event']['id']

        if tag_ids:
            for tag_id in tag_ids.split(","):
                try:
                    self.misp.tag(event['Event']['uuid'], tag_id)
                except Exception as e:
                    log.error(e)

        for thread_id in xrange(int(self.threads)):
            thread = threading.Thread(target=self.cuckoo2misp_thread, args=(iocs, event))
            thread.daemon = True
            thread.start()
            threads_list.append(thread)

        for thread in threads_list:
            thread.join()

        while(self.slaves_id):
            obj_uuid = self.slaves_id.pop()
            if obj_uuid != self.master_obj.uuid:
                self.master_obj.add_reference(obj_uuid, 'dropped-by')

        for ref in self.master_obj.ObjectReference:
            r = self.misp.add_object_reference(ref)


    def misper_thread(self, url):
        while self.iocs:
            ioc = self.iocs.pop()
            try:
                response = self.misp.search_all(ioc)
                if not response or not response.get("response", {}):
                    continue
                self.lock.acquire()
                try:
                    for res in response.get("response", {}):
                        event = res.get("Event", {})

                        self.misp_full_report.setdefault(ioc, list())
                        self.misp_full_report[ioc].append(event)

                        eid = event.get("id", 0)
                        if eid:
                            if eid in self.misper and ioc not in self.misper[eid]["iocs"]:
                                self.misper[eid]["iocs"].append(ioc)
                            else:
                                tmp_misp = dict()
                                tmp_misp.setdefault(eid, dict())
                                date = event.get("date", "")
                                if "iocs" not in tmp_misp[eid]:
                                    tmp_misp[eid].setdefault("iocs", list())
                                tmp_misp[eid]["iocs"].append(ioc)
                                tmp_misp[eid].setdefault("eid", eid)
                                tmp_misp[eid].setdefault("url", os.path.join(url, "events/view/"))
                                tmp_misp[eid].setdefault("date", date)
                                tmp_misp[eid].setdefault("level", event.get("threat_level_id",""))
                                tmp_misp[eid].setdefault("info", event.get("info", "").strip())
                                self.misper.update(tmp_misp)
                finally:
                    self.lock.release()
            except Exception as e:
                log.error(e)

    def run(self, results):
        """Run analysis.
        @return: MISP results dict.
        """

        if not PYMISP:
            log.error("pyMISP dependency is missing.")
            return

        url = self.options.get("url", "")
        apikey = self.options.get("apikey", "")

        if not url or not apikey:
            log.error("MISP URL or API key not configured.")
            return

        self.threads = self.options.get("threads", "")
        if not self.threads:
            self.threads = 5

        whitelist = list()
        whitelist_ua = list()
        self.iocs = deque()
        self.misper = dict()
        threads_list = list()
        self.misp_full_report = dict()
        self.lock = threading.Lock()

        self.master_obj = None
        self.slaves_id = deque()

        try:
            # load whitelist if exists
            if os.path.exists(os.path.join(CUCKOO_ROOT, "conf", "misp.conf")):
                whitelist = Config("misp").whitelist.whitelist
                if whitelist:
                    whitelist = [ioc.strip() for ioc in whitelist.split(",")]
                whitelist_ua = Config("misp").whitelist.whitelist_ua
                if whitelist_ua:
                    whitelist_ua = [ioc.strip() for ioc in whitelist_ua.split(",")]

            self.misp = PyMISP(url, apikey, False, "json")

            if self.options.get("extend_context", ""):
 
                for drop in results.get("dropped", []):
                    if drop.get("md5", "") and drop["md5"] not in self.iocs and drop["md5"] not in whitelist and "PE32" in drop["type"] :
                        self.iocs.append(drop["md5"])

                if results.get("target", {}).get("file", {}).get("md5", "") and results["target"]["file"]["md5"] not in whitelist:
                    self.iocs.append(results["target"]["file"]["md5"])
                    
                for block in results.get("network", {}).get("hosts", []):
                    if block.get("ip", "") and block["ip"] not in self.iocs and block["ip"] not in whitelist:
                        self.iocs.append(block["ip"])
                    if block.get("hostname", "") and block["hostname"] not in self.iocs and block["hostname"] not in whitelist:
                        self.iocs.append(block["hostname"])

                if not self.iocs:
                    return

                for thread_id in xrange(int(self.threads)):
                    thread = threading.Thread(target=self.misper_thread, args=(url,))
                    thread.daemon = True
                    thread.start()

                    threads_list.append(thread)

                for thread in threads_list:
                    thread.join()

                if self.misper:
                    results["misp"] = sorted(self.misper.values(), key=lambda x: datetime.strptime(x["date"], "%Y-%m-%d"), reverse=True)
                    misp_report_path = os.path.join(self.reports_path, "misp.json")
                    full_report = open(misp_report_path, "wb")
                    full_report.write(json.dumps(self.misp_full_report))
                    full_report.close()

            tag_ids = self.options.get("tag", None)
            if self.options.get("upload_iocs", False) and results.get("malscore", 0) >= self.options.get("min_malscore", 0):
                self.cuckoo2misp(results, whitelist, whitelist_ua, tag_ids)

        except Exception as e:
            log.error("Failed to generate JSON report: %s" % e)





