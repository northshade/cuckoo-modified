# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import shutil
import sys

from lib.common.abstracts import Package
import logging

log = logging.getLogger(__name__)
log.info("dll package initialized")

class Dll(Package):
    """DLL analysis package."""
    PATHS = [
        ("SystemRoot", "system32", "rundll32.exe"),
    ]

    def start(self, path):
      try:
        rundll32 = self.get_path("rundll32.exe")
        function = self.options.get("function", "DllMain")
        arguments = self.options.get("arguments")
        loadername = self.options.get("loader")

        # Check file extension.
        ext = os.path.splitext(path)[-1].lower()
        # If the file doesn't have the proper .dll extension force it
        # and rename it. This is needed for rundll32 to execute correctly.
        # See ticket #354 for details.
        if ext != ".dll":
            new_path = path + ".dll"
            os.rename(path, new_path)
            path = new_path

        args = "\"{0}\",{1}".format(path, function)
 
        if arguments:
            args += " {0}".format(arguments)

        if loadername:
            newname = os.path.join(os.path.dirname(rundll32), loadername)
            shutil.copy(rundll32, newname)
            rundll32 = newname
        return self.execute(rundll32, args, path)
      except Exception as e:
        log.info(sys.exc_info()[0])  
        log.info(e)
        log.info(e.__dict__)  
        log.info(e.__class__)  

