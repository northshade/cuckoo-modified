#!/usr/bin/env python
# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import shutil
import sys
import time
import json
jdec = json.JSONDecoder()

import hashlib
import logging
logging.basicConfig(format="%(levelname)s:%(module)s:%(threadName)s - %(message)s")
import tarfile
import tempfile
import argparse
import threading
import Queue

from datetime import datetime
from itertools import combinations

import zipfile
import StringIO

CUCKOO_ROOT = os.path.join(os.path.abspath(os.path.dirname(__file__)), "..")
sys.path.append(CUCKOO_ROOT)

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.utils import store_temp_file
from lib.cuckoo.core.database import Database, TASK_COMPLETED, TASK_REPORTED, TASK_RUNNING, TASK_PENDING, TASK_FAILED_REPORTING

# we need original db to reserve ID in db,
# to store later report, from master or slave
reporting_conf = Config("reporting")

dead_count = 5
if reporting_conf.distributed.dead_count:
    dead_count = reporting_conf.distributed.dead_count

INTERVAL = 10
RESET_LASTCHECK = 20

# controller of dead nodes
failed_count = dict()
# status controler count to reset number
status_count = dict()

lock_retriever = threading.Lock()
dist_lock = threading.BoundedSemaphore(int(reporting_conf.distributed.dist_threads))
remove_lock = threading.BoundedSemaphore(20)
notification_lock = threading.BoundedSemaphore(20)

def required(package):
    sys.exit("The %s package is required: pip install %s" %
             (package, package))

try:
    from flask import Flask, request, make_response
except ImportError:
    required("flask")

try:
    import requests
    from requests.auth import HTTPBasicAuth
except ImportError:
    required("requests")

try:
    requests.packages.urllib3.disable_warnings()
except AttributeError:
    pass

try:
    from flask_restful import abort, reqparse
    from flask_restful import Api as RestApi, Resource as RestResource
except ImportError:
    required("flask-restful")

try:
    from sqlalchemy import DateTime
    from sqlalchemy import or_, and_
except ImportError:
    required("sqlalchemy")

try:
    from flask_sqlalchemy import SQLAlchemy
    db = SQLAlchemy(session_options=dict(autoflush=True))
except ImportError:
    required("flask-sqlalchemy")


class Retriever(threading.Thread):

    def run(self):
        self.cleaner_queue = Queue.Queue()
        self.fetcher_queue = Queue.Queue()
        self.notification_queue = Queue.Queue()
        self.t_is_none = dict()
        self.status_count = dict()
        self.current_queue = dict()
        self.current_two_queue = dict()

        for x in xrange(int(reporting_conf.distributed.dist_threads)):
            if dist_lock.acquire(blocking=False):
                thread = threading.Thread(target=self.fetch_latest_reports, args=())
                thread.daemon = True
                thread.start()

        thread = threading.Thread(target=self.fetcher, args=())
        thread.daemon = True
        thread.start()

        for x in xrange(20):
            if remove_lock.acquire(blocking=False):
                thread = threading.Thread(target=self.cleaner, args=())
                thread.start()

        thread = threading.Thread(target=self.failed_cleaner, args=())
        thread.daemon = True
        thread.start()

        if reporting_conf.notification.enabled:
            for x in xrange(20):
                if notification_lock.acquire(blocking=False):
                    thread = threading.Thread(target=self.notification_loop, args=())
                    thread.daemon = True
                    thread.start()

    def notification_loop(self):
        while True:
                main_task_id = self.notification_queue.get()
                try:
                    res = requests.post(reporting_conf.notification.url, data=json.dumps({"task_id":main_task_id}))
                    if res and res.ok:
                        log.info("reported main_task_id: {}".format(main_task_id))
                    else:
                        log.info("failed to report: {}".format(main_task_id))
                except Exception as e:
                    log.info("failed to report: {}".format(main_task_id))

    def failed_cleaner(self):
        with app.app_context():
            while True:
                for node in Node.query.filter_by(enabled=True).all():
                    for task in node.fetch_tasks("failed_analysis"):
                        t = Task.query.filter_by(task_id=task["id"], node_id=node.id).order_by(Task.id.desc()).first()
                        if t is not None:
                            log.info("Cleaning failed_analysis for id:{}, node:{}".format(t.id, t.node_id))
                            main_db.set_status(t.main_task_id, TASK_FAILED_REPORTING)
                            t.finished = True
                            t.retrieved = True
                            db.session.commit()
                            lock_retriever.acquire()
                            if (t.node_id, t.task_id) not in self.cleaner_queue.queue:
                                self.cleaner_queue.put((t.node_id, t.task_id))
                            lock_retriever.release()
                        else:
                            log.debug("failed_cleaner t is None for: {} - node_id: {}".format(task["id"], t.node_id))

                time.sleep(60)

    def cleaner(self):
        """ Method that runs forever """
        with app.app_context():
            while True:
                node, task_id = self.cleaner_queue.get()
                self.remove_from_slave(node, task_id)
                if task_id in self.t_is_none.get(node, list()):
                    self.t_is_none[node].remove(task_id)

    def fetcher(self):
        """ Method that runs forever """
        with app.app_context():
            while True:

                for node in Node.query.filter_by(enabled=True).all():
                    self.status_count.setdefault(node.name, 0)

                    for task in node.fetch_tasks("reported"):
                        try:
                            if (task["id"] not in self.t_is_none.get(node.id, list()) and \
                                (task, node.id) not in self.fetcher_queue.queue and \
                                task["id"] not in self.current_queue.get(node.id, []) and \
                                (node.id, task["id"]) not in self.cleaner_queue.queue):

                                self.fetcher_queue.put((task, node.id))

                        except Exception as e:
                            self.status_count[node.name] += 1
                            log.exception(e)

                            if self.status_count[node.name] == dead_count:
                                log.info('[-] {} dead'.format(node.name))
                                node_data = Node.query.filter_by(name=node.name).first()
                                node_data.enabled = False
                                db.session.commit()

                time.sleep(30)


    # This should be executed as external thread as it generates bottle neck
    def fetch_latest_reports(self):

        with app.app_context():
            while True:
                    task, node_id = self.fetcher_queue.get()
                    self.current_queue.setdefault(node_id, list()).append(task["id"])

                    try:
                        # In the case that a Cuckoo node has been reset over time it's
                        # possible that there are multiple combinations of
                        # node-id/task-id, in this case we take the last one available.
                        # (This makes it possible to re-setup a Cuckoo node).
                        t = Task.query.filter_by(node_id=node_id, task_id=task["id"]).order_by(Task.id.desc()).first()
                        if t is None:
                            self.t_is_none.setdefault(node_id, list()).append(task["id"])
                            """
                            else:
                                # sometime it not deletes tasks in slaves of some fails or something
                                # this will do the trick
                                log.debug("tf else,")
                                if (node_id, task.get("id")) not in self.cleaner_queue.queue:
                                    self.cleaner_queue.put((node_id, task.get("id")))
                            """
                            continue
                        log.debug("Fetching dist report for: id: {}, task_id: {}, main_task_id:{} from node_id: {}".format(t.id, t.task_id, t.main_task_id, t.node_id))
                        # Fetch each requested report.
                        node = Node.query.filter_by(id = node_id).first()
                        report = node.get_report(t.task_id, "dist", stream=True)

                        if report.ok is False or report.status_code != 200:
                            log.info("dist report retrieve failed: {} - task_id: {}".format(report.status_code, t.task_id))
                            continue

                        report_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", "{}".format(t.main_task_id))
                        if not os.path.isdir(report_path):
                            os.makedirs(report_path, mode=0755)
                        try:
                            fileobj = StringIO.StringIO(report.content)
                            if fileobj.len:
                                file = tarfile.open(fileobj=fileobj, mode="r:bz2") # errorlevel=0
                                try:
                                    file.extractall(report_path)
                                except OSError:
                                    log.error("Permission denied: {}".format(report_path))
                                # set complated_on time
                                main_db.set_status(t.main_task_id, TASK_COMPLETED)
                                # set reported time
                                main_db.set_status(t.main_task_id, TASK_REPORTED)
                                t.finished = True
                                t.retrieved = True
                                db.session.commit()
                                if (t.node_id, t.task_id) not in self.cleaner_queue.queue:
                                    self.cleaner_queue.put((t.node_id, t.task_id))

                                self.notification_queue.put(t.main_task_id)

                                if os.path.exists(t.path):
                                    sample = open(t.path, "rb").read()
                                    sample_sha256 = hashlib.sha256(sample).hexdigest()
                                    destination = os.path.join(CUCKOO_ROOT, "storage", "binaries")
                                    if not os.path.exists(destination):
                                        os.mkdir(destination, mode=0755)
                                    destination = os.path.join(destination, sample_sha256)
                                    if not os.path.exists(destination):
                                        shutil.move(t.path, destination)
                                    # creating link to analysis folder
                                    try:
                                        os.symlink(destination, os.path.join(report_path, "binary"))
                                    except Exception as e:
                                        pass
                            else:
                                log.error("Tar file is empty")
                                # closing StringIO objects
                                fileobj.close()
                        except tarfile.ReadError:
                            log.error("Task id: {} from node.id: {} Read error, fileobj.len: {}".format(t.task_id, t.node_id, fileobj.len))
                        except Exception as e:
                            logging.exception("Exception: %s" % e)
                            if os.path.exists(os.path.join(report_path, "reports", "report.json")):
                                os.remove(os.path.join(report_path, "reports", "report.json"))
                    except Exception as e:
                        logging.exception(e)
                    self.current_queue[node_id].remove(task["id"])

    def remove_from_slave(self, node_id, task_id):
        # Delete the task and all its associated files.
        # (It will still remain in the nodes' database, though.)
        if reporting_conf.distributed.remove_task_on_slave:
            node = Node.query.filter_by(id = int(node_id))
            node = node.first()
            if node:
                try:
                    url = os.path.join(node.url, "tasks", "delete", "%d" % task_id)
                    log.info("Removing task id: {0} - from node: {1}".format(task_id, node.name))
                    res = requests.get(url,auth = HTTPBasicAuth(node.ht_user, node.ht_pass),
                                        verify = False)
                    if res and res.status_code != 200:
                        log.info("{} - {}".format(res.status_code, res.content))
                except Exception as e:
                    log.critical("Error deleting task (task #%d, node %s): %s", task_id, node.name, e)

class StringList(db.TypeDecorator):
    """List of comma-separated strings as field."""
    impl = db.Text

    def process_bind_param(self, value, dialect):
        return ", ".join(value)

    def process_result_value(self, value, dialect):
        return value.split(", ")


class Node(db.Model):
    """Cuckoo node database model."""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Text, nullable=False)
    url = db.Column(db.Text, nullable=False)
    enabled = db.Column(db.Boolean, nullable=False)
    ht_user = db.Column(db.String(255), nullable=False)
    ht_pass = db.Column(db.String(255), nullable=False)
    last_check = db.Column(db.DateTime(timezone=False))
    machines = db.relationship("Machine", backref="node", lazy="dynamic")

    def __init__(self, name, url, ht_user="", ht_pass="", enabled=True):
        self.name = name
        self.url = url
        self.enabled = enabled
        self.ht_user = ht_user
        self.ht_pass = ht_pass

    def list_machines(self):
        try:
            r = requests.get(os.path.join(self.url, "machines", "list"),
                            auth = HTTPBasicAuth(self.ht_user, self.ht_pass),
                            verify = False)

            for machine in r.json()["machines"]:
                yield Machine(name=machine["name"],
                              platform=machine["platform"],
                              tags=machine["tags"])
        except Exception as e:
            abort(404,
                  message="Invalid Cuckoo node (%s): %s" % (self.name, e))

    def delete_machine(self, name):
        try:
            r = requests.get(os.path.join(self.url, "machines", "delete", "%s" % name),
                            auth = HTTPBasicAuth(self.ht_user, self.ht_pass),
                            verify = False)
        except Exception as e:
            abort(404,
                  message="Cuckoo failed machine deletion (%s): %s" % (self.name, e))

        if jdec.decode(r.text)["status"] == "success":
            log.info("[Node %s] %s " % (self.name, jdec.decode(r.text)["data"]) )
            return True
        else:
            log.info("[Node %s] Could not delete VM: %s" % (self.name, name) )
            return False

    def status(self):
        try:
            r = requests.get(os.path.join(self.url, "cuckoo", "status"),
                            auth = HTTPBasicAuth(self.ht_user, self.ht_pass),
                            verify = False, timeout = 200)
            return r.json()["tasks"]
        except Exception as e:
            log.critical("Possible invalid Cuckoo node (%s): %s",
                         self.name, e)

        return {}

    def submit_task(self, task, node):
        try:
            url = os.path.join(self.url, "tasks", "create", "file")

            # Remove the earlier appended comma
            if task.tags:
                if task.tags[-1] == ',': task.tags = task.tags[:-1]

            data = dict(
                package=task.package, timeout=task.timeout,
                priority=task.priority, options=task.options,
                machine=task.machine, platform=task.platform,
                tags=task.tags, custom=task.custom,
                memory=task.memory, clock=task.clock,
                enforce_timeout=task.enforce_timeout,
            )
            # If the file does not exist anymore, ignore it and move on
            # to the next file.
            if not os.path.isfile(task.path):
                task.finished = True
                task.retrieved = True
                try:
                    db.session.commit()
                except:
                    db.session.rollback()
                return

            if self.name != "master":
                files = dict(file=open(task.path, "rb"))
                r = requests.post(url, data=data, files=files,
                                auth = HTTPBasicAuth(self.ht_user, self.ht_pass),
                                verify = False)

                # Zip files preprocessed, so only one id
                if r and r.status_code == 200 and "task_ids" in r.json() and len(r.json()["task_ids"]) > 0:
                    task.task_id = r.json()["task_ids"][0]
                    log.info("Submitted task to slave: {}".format(task.task_id))
                elif r.status_code == 500:
                    return
                else:
                    log.info("Node: {} - Task submit to slave failed: {} - {}".format(self.id, r.status_code, r.content))
                    return

            task.node_id = self.id

            if task.main_task_id:
                main_db.set_status(task.main_task_id, TASK_RUNNING)

            # we don't need create extra id in master
            # reserving id in main db, to later store in mongo with the same id
            elif self.name != "master":
                main_task_id = main_db.add_path(
                    file_path=task.path,
                    package=task.package,
                    timeout=task.timeout,
                    options=task.options,
                    priority=task.priority,
                    machine=task.machine,
                    custom=task.custom,
                    memory=task.memory,
                    enforce_timeout=task.enforce_timeout,
                    tags=task.tags
                )
                main_db.set_status(main_task_id, TASK_RUNNING)
                task.main_task_id = main_task_id

            # We have to refresh() the task object because otherwise we get
            # the unmodified object back in further sql queries..
            # TODO Commit once, refresh() all at once. This could potentially
            # become a bottleneck.
            db.session.commit()
            #db.session.refresh(task)
        except Exception as e:
            log.critical("Error submitting task (task #%d, node %s): %s",
                         task.id, self.name, e)

    def fetch_tasks(self, status):
        try:
            url = os.path.join(self.url, "tasks", "list")
            params = dict(status=status, ids=True)
            r = requests.get(url, params=params,
                            auth = HTTPBasicAuth(self.ht_user, self.ht_pass),
                            verify = False)
            return r.json()["tasks"]
        except Exception as e:
            log.critical("Error listing completed tasks (node %s): %s",
                         self.name, e)

        return []

    def get_report(self, task_id, fmt, stream=False):
        try:
            url = os.path.join(self.url, "tasks", "report",
                               "%d" % task_id, fmt)
            return requests.get(url, stream=stream,
                                auth = HTTPBasicAuth(self.ht_user, self.ht_pass),
                                verify = False)
        except Exception as e:
            log.critical("Error fetching report (task #%d, node %s): %s",
                         task_id, self.url, e)


class Machine(db.Model):
    """Machine database model related to a Cuckoo node."""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Text, nullable=False)
    platform = db.Column(db.Text, nullable=False)
    tags = db.Column(StringList)
    node_id = db.Column(db.Integer, db.ForeignKey("node.id"))

    def __init__(self, name, platform, tags):
        self.name = name
        self.platform = platform
        self.tags = tags


class Task(db.Model):
    """Analysis task database model."""
    id = db.Column(db.Integer, primary_key=True)
    path = db.Column(db.Text)
    package = db.Column(db.Text)
    timeout = db.Column(db.Integer)
    priority = db.Column(db.Integer)
    options = db.Column(db.Text)
    machine = db.Column(db.Text)
    platform = db.Column(db.Text)
    tags = db.Column(db.Text)
    custom = db.Column(db.Text)
    memory = db.Column(db.Text)
    clock = db.Column(DateTime(timezone=False),
                   default=datetime.now(),
                   nullable=False)
    enforce_timeout = db.Column(db.Text)

    # Cuckoo node and Task ID this has been submitted to.
    node_id = db.Column(db.Integer, db.ForeignKey("node.id"))
    task_id = db.Column(db.Integer)
    finished = db.Column(db.Boolean, nullable=False)
    main_task_id = db.Column(db.Integer)
    retrieved = db.Column(db.Boolean, nullable=False)

    def __init__(self, path, package, timeout, priority, options, machine,
                 platform, tags, custom, memory, clock, enforce_timeout, main_task_id=None, retrieved=False):
        self.path = path
        self.package = package
        self.timeout = timeout
        self.priority = priority
        self.options = options
        self.machine = machine
        self.platform = platform
        self.tags = tags
        self.custom = custom
        self.memory = memory
        self.clock = clock
        self.enforce_timeout = enforce_timeout
        self.node_id = None
        self.task_id = None
        self.main_task_id = main_task_id
        self.finished = False
        self.retrieved = False


class StatusThread(threading.Thread):

    def submit_tasks(self, node, pend_tasks_num):

        if node.name != "master":
            # Get tasks from main_db submitted through web interface
            for t in main_db.list_tasks(status=TASK_PENDING, limit=pend_tasks_num):
                if not Task.query.filter_by(main_task_id=t.id).all():
                    # Convert array of tags into comma separated list
                    tags = ','.join([tag.name for tag in t.tags])
                    # Append a comma, to make LIKE searches more precise
                    if tags: tags += ','
                    args = dict(package=t.package, timeout=t.timeout, priority=t.priority,
                                options=t.options+",main_task_id={}".format(t.id), machine=t.machine, platform=t.platform,
                                tags=tags, custom=t.custom, memory=t.memory, clock=t.clock,
                                enforce_timeout=t.enforce_timeout, main_task_id=t.id)
                    task = Task(path=t.target, **args)
                    db.session.add(task)
                try:
                    db.session.commit()
                except Exception as e:
                    main_db.set_status(t.id, TASK_FAILED_REPORTING)
                    db.session.rollback()

        # Only get tasks that have not been pushed yet.
        q = Task.query.filter(or_(Task.node_id==None, Task.task_id==None), Task.finished==False)

        # Order by task priority and task id.
        q = q.order_by(-Task.priority, Task.main_task_id)

        if reporting_conf.distributed.enable_tags:
            # Get available node tags
            machines = Machine.query.filter_by(node_id=node.id).all()

            # Get available tag combinations
            ta = set()
            for m in machines:
                for i in xrange(1, len(m.tags)+1):
                    for t in combinations(m.tags, i):
                        ta.add(','.join(t))
            ta = list(ta)

            # Create filter query from tasks in ta
            tags = [ getattr(Task, "tags")=="" ]
            for t in ta:
                if len(t.split(',')) == 1:
                    tags.append(getattr(Task, "tags")==(t+','))
                else:
                    t = t.split(',')
                    # ie. LIKE '%,%,%,'
                    t_combined = [ getattr(Task, "tags").like("%s" % ('%,'*len(t)) ) ]
                    for tag in t:
                        t_combined.append(getattr(Task, "tags").like("%%%s%%" % (tag+',') ))
                    tags.append( and_(*t_combined) )

            # Filter by available tags
            q = q.filter(or_(*tags))

        # Submit appropriate tasks to node
        if pend_tasks_num > 0:
            for task in q.limit(pend_tasks_num).all():
                node.submit_task(task, node)

    def run(self):
        global main_db
        global retrieve
        global STATUSES
        global RESET_LASTCHECK
        MINIMUMQUEUE = dict()

        # run once
        with app.app_context():
            # handle another user case,
            # when master used to only store data and not process samples

            if reporting_conf.distributed.master_storage_only == "no":
                master = Node.query.filter_by(name="master").first()
                if master is None:
                    master_storage_only = True
                elif Machine.query.filter_by(node_id=master.id).count() == 0:
                    master_storage_only = True
            else:
                master_storage_only = True

            #MINIMUMQUEUE but per Node depending of number vms
            for node in Node.query.filter_by(enabled=True).all():
                MINIMUMQUEUE[node.name] = Machine.query.filter_by(node_id=node.id).count()

            statuses = {}
            while True:
                # Request a status update on all Cuckoo nodes.
                for node in Node.query.filter_by(enabled=True).all():
                    status = node.status()
                    if not status:
                        failed_count.setdefault(node.name, 0)
                        failed_count[node.name] += 1

                        # This will declare slave as dead after X failed connections checks
                        if failed_count[node.name] == dead_count:
                            log.info('[-] {} dead'.format(node.name))
                            node_data = Node.query.filter_by(name=node.name).first()
                            node_data.enabled = False
                            db.session.commit()

                        continue

                    failed_count[node.name] = 0
                    log.debug("Status.. %s -> %s", node.name, status)
                    statuses[node.name] = status
                    # If - master only used for storage, not check master queue
                    # elif -  master also analyze samples, check master queue
                    # send tasks to slaves if master queue has extra tasks(pending)
                    if master_storage_only:
                        self.submit_tasks(node, MINIMUMQUEUE[node.name] - status["pending"])
                    elif statuses.get("master", {}).get("pending", 0) > MINIMUMQUEUE.get("master", 0) and \
                         status["pending"] < MINIMUMQUEUE[node.name]:
                       self.submit_tasks(node, MINIMUMQUEUE[node.name] - status["pending"])

                STATUSES = statuses

                time.sleep(INTERVAL)


class NodeBaseApi(RestResource):
    def __init__(self, *args, **kwargs):
        RestResource.__init__(self, *args, **kwargs)

        self._parser = reqparse.RequestParser()
        self._parser.add_argument("name", type=str)
        self._parser.add_argument("url", type=str)
        self._parser.add_argument("ht_user", type=str, default="")
        self._parser.add_argument("ht_pass", type=str, default="")
        self._parser.add_argument("enabled", action='store_true')


class NodeRootApi(NodeBaseApi):
    def get(self):
        nodes = {}
        for node in Node.query.all():
            machines = []
            for machine in node.machines.all():
                machines.append(dict(
                    name=machine.name,
                    platform=machine.platform,
                    tags=machine.tags,
                ))

            nodes[node.name] = dict(
                name=node.name,
                url=node.url,
                machines=machines,
            )
        return dict(nodes=nodes)

    def post(self):
        args = self._parser.parse_args()
        node = Node(name=args["name"], url=args["url"], ht_user=args["ht_user"],
                ht_pass=args["ht_pass"])

        if Node.query.filter_by(name=args["name"]).first():
            return dict(success=False, message="Node called %s already exists" % args["name"])

        machines = []
        for machine in node.list_machines():
            machines.append(dict(
                name=machine.name,
                platform=machine.platform,
                tags=machine.tags,
            ))
            node.machines.append(machine)
            db.session.add(machine)

        db.session.add(node)
        db.session.commit()
        return dict(name=node.name, machines=machines)


class NodeApi(NodeBaseApi):
    def get(self, name):
        node = Node.query.filter_by(name=name).first()
        return dict(name=node.name, url=node.url)

    def put(self, name):
        args = self._parser.parse_args()
        node = Node.query.filter_by(name=name).first()

        if not node: return dict(error=True, error_value="Node doesn't exist")

        for k,v in args.items():
            if v: setattr(node, k, v)
        db.session.commit()
        return dict(error=False, error_value="Successfully modified node: %s" % node.name)

    def delete(self, name):
        node = Node.query.filter_by(name=name).first()
        node.enabled = False
        db.session.commit()


class TaskBaseApi(RestResource):
    def __init__(self, *args, **kwargs):
        RestResource.__init__(self, *args, **kwargs)

        self._parser = reqparse.RequestParser()
        self._parser.add_argument("package", type=str, default="")
        self._parser.add_argument("timeout", type=int, default=0)
        self._parser.add_argument("priority", type=int, default=1)
        self._parser.add_argument("options", type=str, default="")
        self._parser.add_argument("machine", type=str, default="")
        self._parser.add_argument("platform", type=str, default="windows")
        self._parser.add_argument("tags", type=str, default="")
        self._parser.add_argument("custom", type=str, default="")
        self._parser.add_argument("memory", type=str, default="0")
        self._parser.add_argument("clock", type=int)
        self._parser.add_argument("enforce_timeout", type=bool, default=False)


class StatusRootApi(RestResource):
    def get(self):
        null = None

        tasks = Task.query.filter(Task.node_id != null)

        tasks = dict(
            processing=tasks.filter_by(finished=False).count(),
            processed=tasks.filter_by(finished=True).count(),
            pending=Task.query.filter_by(node_id=None).count(),
        )
        return dict(nodes=STATUSES, tasks=tasks)


def output_json(data, code, headers=None):
    resp = make_response(json.dumps(data), code)
    resp.headers.extend(headers or {})
    return resp


class DistRestApi(RestApi):
    def __init__(self, *args, **kwargs):
        RestApi.__init__(self, *args, **kwargs)
        self.representations = {
            "application/json": output_json,
        }

def update_machine_table(app, node_name):
    with app.app_context():
        node = Node.query.filter_by(name=node_name).first()

        # get new vms
        new_machines = node.list_machines()

        # delete all old vms
        machines = Machine.query.filter_by(node_id=node.id).delete()

        log.info("Available VM's on %s:" % node_name)
        # replace with new vms
        for machine in new_machines:
            log.info("-->\t%s" % machine.name)
            node.machines.append(machine)
            db.session.add(machine)

        db.session.commit()

        log.info("Updated the machine table for node: %s" % node_name)

def delete_vm_on_node(app, node_name, vm_name):
    with app.app_context():
        node = Node.query.filter_by(name=node_name).first()
        vm   = Machine.query.filter_by(name=vm_name, node_id=node.id).first()

        if not vm:
            log.error("The selected VM does not exist")
            return

        status = node.delete_machine(vm_name)

        if status:
            # delete vm in dist db
            vm   = Machine.query.filter_by(name=vm_name, node_id=node.id).delete()
            db.session.commit()

def node_enabled(app, node_name, status):
    with app.app_context():
        node = Node.query.filter_by(name=node_name).first()
        node.enabled = status
        db.session.commit()

def create_app(database_connection):
    # http://flask-sqlalchemy.pocoo.org/2.1/config/
    # https://github.com/tmeryu/flask-sqlalchemy/blob/master/flask_sqlalchemy/__init__.py#L787
    app = Flask("Distributed Cuckoo")
    app.config["SQLALCHEMY_DATABASE_URI"] = database_connection
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
    app.config['SQLALCHEMY_POOL_SIZE'] = int(reporting_conf.distributed.dist_threads) + 5
    app.config["SECRET_KEY"] = os.urandom(32)
    app.config["SQLALCHEMY_MAX_OVERFLOW"] = 100
    app.config["SQLALCHEMY_POOL_TIMEOUT"] = 200

    restapi = DistRestApi(app)
    restapi.add_resource(NodeRootApi, "/node")
    restapi.add_resource(NodeApi, "/node/<string:name>")
    restapi.add_resource(StatusRootApi, "/status")

    db.init_app(app)
    with app.app_context():
        db.create_all()
    return app

app = create_app(database_connection=reporting_conf.distributed.db)

# init
logging.getLogger("elasticsearch").setLevel(logging.WARNING)
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)

STATUSES = {}
main_db = Database()

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("host", nargs="?", default="0.0.0.0", help="Host to listen on")
    p.add_argument("port", nargs="?", type=int, default=9003, help="Port to listen on")
    p.add_argument("-d", "--debug", action="store_true", help="Enable debug logging")
    p.add_argument("--uptime-logfile", type=str, help="Uptime logfile path")
    p.add_argument("--node", type=str, help="Node name to update in distributed DB")
    p.add_argument("--delete-vm", type=str, help="VM name to delete from Node")
    p.add_argument("--disable", action="store_true", help="Disable Node provided in --node")
    p.add_argument("--enable", action="store_true", help="Enable Node provided in --node")
    args = p.parse_args()

    log = logging.getLogger(__name__)
    if args.debug:
        log.setLevel(logging.DEBUG)
    else:
        log.setLevel(logging.INFO)

    if args.node:
        if args.delete_vm:
            delete_vm_on_node(app, args.node, args.delete_vm)
        if args.enable:
            node_enabled(app, args.node, True)
        if args.disable:
            node_enabled(app, args.node, False)
        if not args.delete_vm and not args.disable and not args.enable:
            update_machine_table(app, args.node)

    elif reporting_conf.distributed.samples_directory:

        if not reporting_conf.distributed.samples_directory:
                p.error("Configure conf/reporting.conf distributed section please")

        if not os.path.isdir(reporting_conf.distributed.samples_directory):
            os.makedirs(reporting_conf.distributed.samples_directory)

        if reporting_conf.distributed.samples_directory:
            app.config["SAMPLES_DIRECTORY"] = reporting_conf.distributed.samples_directory
            app.config["UPTIME_LOGFILE"] = reporting_conf.distributed.uptime_logfile


        retrieve = Retriever()
        retrieve.daemon = True
        retrieve.start()

        t = StatusThread()
        t.daemon = True
        t.start()

        app.run(host=args.host, port=args.port, debug=False, use_reloader=False)

    else:
        p.error("Configure conf/reporting.conf distributed section please")
else:
    # this allows run it with gunicorn/uwsgi
    log = logging.getLogger(__name__)
    log.setLevel(logging.DEBUG)

    if not os.path.isdir(reporting_conf.distributed.samples_directory):
        os.makedirs(reporting_conf.distributed.samples_directory)

    if reporting_conf.distributed.samples_directory:
        app.config["SAMPLES_DIRECTORY"] = reporting_conf.distributed.samples_directory

    retrieve = Retriever()
    retrieve.daemon = True
    retrieve.start()

    t = StatusThread()
    t.daemon = True
    t.start()
