# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import xml.etree.ElementTree as ET

from lib.cuckoo.common.abstracts import LibVirtMachinery

class KVM(LibVirtMachinery):
    """Virtualization layer for KVM based on python-libvirt."""

    # Set KVM connection string.
    dsn = "qemu:///system"

    def _get_interface(self, label):
        xml = ET(self._lookup(label).XMLDesc())
        elem = xml.find("./devices/interface[@type='network']")
        if elem is None:
            return elem
        elem = elem.find("target")
        if elem is None:
            return None

        return elem.attrib["dev"]

    def start(self, label):
        super(LibVirtMachinery, self).start(label)
        # If per-machine interface is not set, find it on start
        if self.interface is None:
            self.interface = self._get_interface()



