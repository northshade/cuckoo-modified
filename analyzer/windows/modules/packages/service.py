# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import shutil
import sys

from lib.common.abstracts import Package
import logging
from lib.common.defines import ADVAPI32
import traceback
import ctypes

log = logging.getLogger(__name__)

class Service(Package):
    """Service analysis package."""

    PATHS = [
	("SystemRoot", "system32", "sc.exe"),
    ]
    def start(self, path):

      try:
        sc = self.get_path("sc.exe")
        servicename = self.options.get("servicename", "zOOmService")
        servicedesc = self.options.get("servicedesc", "zOOmService (inc.)")
        arguments = self.options.get("arguments")



	#sc_handle = ADVAPI32.OpenSCManagerA(None, None, 0x0001)

	# Check file extension.
        #ext = os.path.splitext(path)[-1].lower()
        # If the file doesn't have the proper .dll extension force it
        # and rename it. This is needed for rundll32 to execute correctly.
        # See ticket #354 for details.
        """ 
        if ext != ".dll":
            new_path = path + ".dll"
            os.rename(path, new_path)
            path = new_path
        """ 



        binPath = "\"{0}\"".format(path)
        if arguments:
            binPath += " {0}".format(arguments)
        # we expect the service to be already defined in the guest VM as using ServiceDll pointed to by self.options["service-dll-of-interest"]
        shutil.copy(path, self.options["service-dll-of-interest"]) 
        #os.system("copy " + path + " C:\\Windows\\system32\\Nwsapagent2.dll > c:\\copyRes.txt" ) 
	
	"""
	serv_handle = ADVAPI32.CreateServiceA(
		sc_handle,
		servicename,
		servicedesc,
		0x000F003F,    # SERVICE_ALL_ACCESS,
		0x00000010, # SERVICE_WIN32_OWN_PROCESS,
		0x00000002, # SERVICE_AUTO_START,
		0x00000001, # SERVICE_ERROR_NORMAL,
                binPath, None, None, None, None, None)
        if serv_handle == 0:
           log.info(ctypes.FormatError())
        log.info("serv_handle")
        log.info(serv_handle)
    	ADVAPI32.CloseServiceHandle(sc_handle)
	"""

        #os.system(sc  +  " create " + servicename + " start= auto binPath= " + binPath)
        #log.info(ctypes.FormatError())

        sc_arg = "start " + "Nwsapagent" #servicename
        if arguments:
            sc_arg += " {0}".format(arguments)

        return self.execute(sc, sc_arg, sc)


      except Exception as e:
        log.info(sys.exc_info()[0])  
        log.info(e)
        log.info(e.__dict__)  
        log.info(e.__class__)  
        log.exception(e)
