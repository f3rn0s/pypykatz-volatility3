import datetime
import logging
import sys

import pypykatz
from pypykatz.commons.readers.volatility3.volreader import Vol3Reader, vol3_generator

from typing import Callable, Iterable, List, Type
from volatility3.framework import renderers, interfaces, layers, constants
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.windows.extensions import pe
from volatility3.plugins.windows import pslist

class Mimikatz(interfaces.plugins.PluginInterface):
    """Attempts to grab information from the lsass process in a memory dump"""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)
    PHYSICAL_DEFAULT = False

    @classmethod
    def get_requirements(cls):
        return [
                requirements.TranslationLayerRequirement(
                    name='primary',
                    description='Memory layer for the kernel',
                    architectures=["Intel32", "Intel64"]
                    ),
                requirements.SymbolTableRequirement(
                    name="nt_symbols",
                    description="Windows kernel symbols"
                    ),
                requirements.PluginRequirement(
                    name='pslist',
                    plugin=pslist.PsList,
                    version=(2, 0, 0)
                    )
                ]

    def run(self):
        reader = Vol3Reader(self)
        sysinfo = reader.get_sysinfo()
        mimi = pypykatz.pypykatz.pypykatz(reader, sysinfo)
        mimi.start(['all'])

        print("", flush=True)

        for stuff in vol3_generator(mimi):
            credtype, domainname, username, \
              nthash, lmhash, shahash, masterkey, \
              masterkey_sha1, key_guid, password = stuff[1]

            if "$" in username and nthash:
                print(f"MACHINE ACCOUNT: {username}\nNTHash: {nthash}\n")
            elif (domainname and username) and (nthash or lmhash):
                print(f"""{domainname}\{username}:
NTHash: {nthash}
LMHash: {lmhash}
""")

        sys.exit(0)
