# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import shutil

from lib.common.abstracts import Package

class Jar(Package):
    """Java analysis package."""
    PATHS = [
        ("ProgramFiles", "Java", "jre*", "bin", "java.exe"),
    ]

    def start(self, path):
        java = self.get_path_glob("Java")
        class_path = self.options.get("class")

        # Check file extension.
        ext = os.path.splitext(path)[-1].lower()
        # If the file doesn't have the proper .jar extension force it
        # and rename it. This is needed for some executable jar to execute correctly
        if ext != ".jar":
            new_path = path + ".jar"
            os.rename(path, new_path)
            path = new_path

        if class_path:
            args = "-cp \"%s\" %s" % (path, class_path)
        else:
            args = "-jar \"%s\"" % path

        return self.execute(java, args, path)
