#!/usr/bin/python

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: ciscosmb_facts
author: "Petr Klima (@qaxi)"
short_description: Collect facts from remote devices running Cisco SMB
description:
  - Collects a base set of device facts from a remote device that
    is running Cisco SMB.  This module prepends all of the
    base network fact keys with C(ansible_net_<fact>).  The facts
    module will always collect a base set of facts from the device
    and can enable or disable collection of additional facts.
options:
  gather_subset:
    description:
      - When supplied, this argument will restrict the facts collected
        to a given subset.  Possible values for this argument include
        C(all), C(hardware), C(config), and C(interfaces).  Can specify a list of
        values to include a larger subset.  Values can also be used
        with an initial C(!) to specify that a specific subset should
        not be collected.
    required: false
    type: list
    elements: str
    choices: [ 'default', 'all', 'hardware', 'config', 'interfaces', '!hardware', '!config', '!interfaces' ]
    default: '!config'
"""

EXAMPLES = """
- name: Collect all facts from the device
  qaxi.ciscosmb.ciscosmb_facts:
    gather_subset: all

- name: Collect only the config and default facts
  qaxi.ciscosmb.ciscosmb_facts:
    gather_subset:
      - config

- name: Do not collect hardware facts
  qaxi.ciscosmb.ciscosmb_facts:
    gather_subset:
      - "!hardware"
"""

RETURN = """
ansible_net_gather_subset:
  description: The list of fact subsets collected from the device
  returned: always
  type: list

# default
ansible_net_model:
  description: The model name returned from the device
  returned: always
  type: str
ansible_net_serialnum:
  description: The serial number of the remote device
  returned: always
  type: str
ansible_net_version:
  description: The operating system version running on the remote device
  returned: always
  type: str
ansible_net_hostname:
  description: The configured hostname of the device
  returned: always
  type: str
ansible_net_arch:
  description: The CPU architecture of the device
  returned: always
  type: str
  version_added: 1.2.0
ansible_net_uptime:
  description: The uptime of the device
  returned: always
  type: str
  version_added: 1.2.0
ansible_net_cpu_load:
  description: Current CPU load
  returned: always
  type: str
  version_added: 1.2.0
ansible_net_stacked_models:
  description: The model names of each device in the stack
  returned: when multiple devices are configured in a stack
  type: list
ansible_net_stacked_serialnums:
  description: The serial numbers of each device in the stack
  returned: when multiple devices are configured in a stack
  type: list

# hardware
ansible_net_spacefree_mb:
  description: The available disk space on the remote device in MiB
  returned: when hardware is configured
  type: dict
ansible_net_spacetotal_mb:
  description: The total disk space on the remote device in MiB
  returned: when hardware is configured
  type: dict
ansible_net_memfree_mb:
  description: The available free memory on the remote device in MiB
  returned: when hardware is configured
  type: int
ansible_net_memtotal_mb:
  description: The total memory on the remote device in MiB
  returned: when hardware is configured
  type: int

# config
ansible_net_config:
  description: The current active config from the device
  returned: when config is configured
  type: str

# interfaces
ansible_net_all_ipv4_addresses:
  description: All IPv4 addresses configured on the device
  returned: when interfaces is configured
  type: list
ansible_net_all_ipv6_addresses:
  description: All IPv6 addresses configured on the device
  returned: when interfaces is configured
  type: list
ansible_net_interfaces:
  description: A hash of all interfaces running on the system
  returned: when interfaces is configured
  type: dict
ansible_net_neighbors:
  description: The list of neighbors from the remote device
  returned: when interfaces is configured
  type: dict

# routing
ansible_net_bgp_peer:
  description: The dict bgp peer
  returned: peer information
  type: dict
  version_added: 1.2.0
ansible_net_bgp_vpnv4_route:
  description: The dict bgp vpnv4 route
  returned: vpnv4 route information
  type: dict
  version_added: 1.2.0
ansible_net_bgp_instance:
  description: The dict bgp instance
  returned: bgp instance information
  type: dict
  version_added: 1.2.0
ansible_net_route:
  description: The dict routes in all routing table
  returned: routes information in all routing table
  type: dict
  version_added: 1.2.0
ansible_net_ospf_instance:
  description: The dict ospf instance
  returned: ospf instance information
  type: dict
  version_added: 1.2.0
ansible_net_ospf_neighbor:
  description: The dict ospf neighbor
  returned: ospf neighbor information
  type: dict
  version_added: 1.2.0
"""
import re

from ansible_collections.qaxi.ciscosmb.plugins.module_utils.network.ciscosmb.ciscosmb import (
    run_commands,
)
from ansible_collections.qaxi.ciscosmb.plugins.module_utils.network.ciscosmb.ciscosmb import (
    ciscosmb_argument_spec,
)
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.six import iteritems


class FactsBase(object):

    COMMANDS = list()

    def __init__(self, module):
        self.module = module
        self.facts = dict()
        self.responses = None

    def populate(self):
        self.responses = run_commands(
            self.module, commands=self.COMMANDS, check_rc=False
        )

    def run(self, cmd):
        return run_commands(self.module, commands=cmd, check_rc=False)


class Default(FactsBase):

    COMMANDS = [
        "show version",
        "show system",
        "show cpu utilization",
        "show inventory",
    ]

    def populate(self):
        super().populate()

        data = self.responses[0]
        if data:
            self.facts["version"] = self.parse_version(data)
            self.facts["boot_version"] = self.parse_boot_version(data)

        data = self.responses[1]
        if data:
            self.facts["uptime"] = self.parse_uptime(data)
            self.facts["hostname"] = self.parse_hostname(data)

        data = self.responses[2]
        if data:
            self.facts["cpu_load"] = self.parse_cpu_load(data)

        data = self.responses[3]
        if data:
            modules = self.parse_inventory(data)
            stacked_models = self.parse_stacked_models(modules)
            if len(stacked_models) >= 2:
                stacked_serialnums = self.parse_stacked_serialnums(modules)
                self.facts["stacked_models"] = stacked_models
                self.facts["stacked_serialnums"] = stacked_serialnums
            self.facts["model"] = self.parse_model(modules)
            self.facts["serialnum"] = self.parse_serialnum(modules)
            self.facts["hw_version"] = self.parse_hw_version(modules)
            self.facts["hw_modules"] = modules

    # show version
    def parse_version(self, data):
        # Cisco SMB 300 and 500 - fw 1.x.x.x
        match = re.search(r"^SW version\s*(\S+)\s*.*$", data, re.M)
        if match:
            return match.group(1)
        # Cisco SMB 350 and 550 - fw 2.x.x.x
        match = re.search(r"^  Version:\s*(\S+)\s*.*$", data, re.M)
        if match:
            return match.group(1)

    def parse_boot_version(self, data):
        match = re.search(r"Boot version\s*(\S+)\s*.*$", data, re.M)
        if match:
            return match.group(1)

    # show system
    def parse_uptime(self, data):
        match = re.search(r"^System Up Time \S+:\s+(\S+)\s*$", data, re.M)
        if match:
            (dayhour, mins, sec) = match.group(1).split(":")
            (day, hour) = dayhour.split(",")
            # output in seconds
            return (int(day) * 86400) + (int(hour) * 3600) + (int(mins) * 60) + int(sec)

    def parse_hostname(self, data):
        match = re.search(r"^System Name:\s*(\S+)\s*$", data, re.M)
        if match:
            return match.group(1)

    # show cpu utilization
    def parse_cpu_load(self, data):
        match = re.search(r"one minute:\s+(\d+)%;\s*", data, re.M)
        if match:
            return match.group(1)

    # show inventory
    def parse_inventory(self, data):
        # make 1 module 1 line
        data = re.sub(r"\nPID", "  PID", data, re.M)
        # delete empty lines
        data = re.sub(r"^\n", "", data, re.M)
        data = re.sub(r"\n\n", "", data, re.M)
        data = re.sub(r"\n\s*\n", r"\n", data, re.M)

        lines = data.splitlines()

        modules = {}
        for line in lines:
            # remove extra chars
            line = re.sub(r'"', r"", line, re.M)
            line = re.sub(r"\s+", r" ", line, re.M)
            # normalize lines
            line = re.sub(r":\s", r'"', line, re.M)
            line = re.sub(r'\s+DESCR"', r'"DESCR"', line, re.M)
            line = re.sub(r'\s+PID"', r'"PID"', line, re.M)
            line = re.sub(r'\s+VID"', r'"VID"', line, re.M)
            line = re.sub(r'\s+SN"', r'"SN"', line, re.M)
            line = re.sub(r"\s*$", r"", line, re.M)

            match = re.search(
                r'^NAME"(?P<name>[^"]+)"DESCR"(?P<descr>[^"]+)"PID"(?P<pid>[^"]+)"VID"(?P<vid>[^"]+)"SN"(?P<sn>\S+)\s*',
                line,
            )

            modul = match.groupdict()
            modules[modul["name"]] = modul

        if modules:
            return modules

    def parse_stacked_models(self, data):
        # every inventory has module with NAME: "1"
        # stacks have modules 2 3 ... 8
        models = []
        for n in range(1, 9):
            if f"{n}" in data:
                models.append(data[f"{n}"]["pid"])
        return models

    def parse_stacked_serialnums(self, data):
        # every inventory has module with NAME: "1"
        # stacks have modules 2 3 ... 8
        sn = []
        for n in range(1, 9):
            if f"{n}" in data:
                sn.append(data[f"{n}"]["sn"])
        return sn

    def parse_model(self, data):
        # every inventory has module with NAME: "1"
        model = data["1"]["pid"]
        if "stacked_models" in self.facts:
            model = re.sub(r"-.*$", "", model)
            model = "Stack " + model
        return model

    def parse_serialnum(self, data):
        # every inventory has module with NAME: "1"
        sn = data["1"]["sn"]
        return sn

    def parse_hw_version(self, data):
        # every inventory has module with NAME: "1"
        sn = data["1"]["vid"]
        return sn


class Hardware(FactsBase):

    COMMANDS = [
        "dir",
    ]

    def populate(self):
        super().populate()
        data = self.responses[0]
        if data:
            self.parse_filesystem_info(data)

    def parse_filesystem_info(self, data):
        match = re.search(r"Total size of (\S+): (\d+) bytes", data, re.M)

        if match:  # fw 1.x
            self.facts["spacetotal_mb"] = round(int(match[2]) / 1024 / 1024, 1)
            match = re.search(r"Free size of (\S+): (\d+) bytes", data, re.M)
            self.facts["spacefree_mb"] = round(int(match[2]) / 1024 / 1024, 1)

        else:
            match = re.search(r"(\d+)K of (\d+)K are free", data, re.M)
            if match:  # fw 2.x, 3.x
                self.facts["spacetotal_mb"] = round(int(match[2]) / 1024, 1)
                self.facts["spacefree_mb"] = round(int(match[1]) / 1024, 1)


class Config(FactsBase):

    COMMANDS = ["show running-config detailed"]

    def populate(self):
        super().populate()
        data = self.responses[0]
        if data:
            self.facts["config"] = data


class Interfaces(FactsBase):

    COMMANDS = [
        "show ports jumbo-frame",
        "show ip interface",
        "show ipv6 interface brief",
        "show interfaces status",
        "show interfaces configuration",
        "show interfaces description",
        "show lldp neighbors",
    ]

    DETAIL_RE = re.compile(
        r"([\w\d\-]+)=\"?(\w{3}/\d{2}/\d{4}\s\d{2}:\d{2}:\d{2}|[\w\d\-\.:/]+)"
    )
    WRAPPED_LINE_RE = re.compile(r"^\s+(?!\d)")

    def populate(self):
        super().populate()

        self.facts["interfaces"] = dict()
        self.facts["all_ipv4_addresses"] = list()
        self.facts["all_ipv6_addresses"] = list()
        self.facts["neighbors"] = list()

        data = self.responses[0]
        if data:
            self.populate_interfaces_mtu(data)

        data = self.responses[1]
        if data:
            self.populate_addresses_ipv4(data)

        data = self.responses[2]
        if data:
            self.populate_addresses_ipv6(data)

        data = self.responses[3]
        if data:
            self.populate_interfaces_status(data)

        data = self.responses[4]
        if data:
            self.populate_interfaces_configuration(data)

        data = self.responses[5]
        if data:
            self.populate_interfaces_description(data)

        data = self.responses[6]
        if data:
            self.populate_neighbors(data)

    def _split_to_tables(self, data):
        TABLE_HEADER = re.compile(r"^---+ +-+.*$")
        EMPTY_LINE = re.compile(r"^ *$")

        tables = dict()
        tableno = -1
        lineno = 0
        tabledataget = False

        for line in data.splitlines():
            if re.match(EMPTY_LINE, line):
                tabledataget = False
                continue

            if re.match(TABLE_HEADER, line):
                tableno += 1
                tabledataget = True
                lineno = 0
                tables[tableno] = dict()
                tables[tableno]["header"] = line
                tables[tableno]["data"] = dict()
                continue

            if tabledataget:
                tables[tableno]["data"][lineno] = line
                lineno += 1
                continue

        return tables

    def _parse_table(self, table, allow_overflow=True, allow_empty_fields=None):

        if allow_empty_fields is None:
            allow_empty_fields = list()

        fields_end = self.__get_table_columns_end(table["header"])
        data = self.__get_table_data(
            table["data"], fields_end, allow_overflow, allow_empty_fields
        )

        return data

    def __get_table_columns_end(self, headerline):
        """ fields length are diferent device to device, detect them on horizontal lin """
        fields_end = [m.start() for m in re.finditer("  *", headerline.strip())]
        # fields_position.insert(0,0)
        # fields_end.append(len(headerline))
        fields_end.append(10000)  # allow "long" last field

        return fields_end

    def __line_to_fields(self, line, fields_end):
        """ dynamic fields lenghts """
        line_elems = {}
        index = 0
        f_start = 0
        for f_end in fields_end:
            line_elems[index] = line[f_start:f_end].strip()
            index += 1
            f_start = f_end

        return line_elems

    def __get_table_data(
        self, tabledata, fields_end, allow_overflow=True, allow_empty_fields=None
    ):

        if allow_empty_fields is None:
            allow_empty_fields = list()
        data = dict()

        lasttablefullline = 0
        dataindex = 0
        for lineno in tabledata:
            owerflownfields = list()
            owerflow = False

            line = tabledata[lineno]
            line_elems = self.__line_to_fields(line, fields_end)

            if allow_overflow:
                # search for overflown fields
                for elemno in line_elems:
                    if elemno not in allow_empty_fields and line_elems[elemno] == "":
                        owerflow = True
                    else:
                        owerflownfields.append(elemno)

                if owerflow:
                    # concat owerflown elements to previous data
                    for fieldno in owerflownfields:
                        data[dataindex - 1][fieldno] += line_elems[fieldno]

                else:
                    lastfullline = lineno
                    data[dataindex] = line_elems
                    dataindex += 1
            else:
                lastfullline = lineno
                data[dataindex] = line_elems
                dataindex += 1

        return data

    def _merge_dicts(self, a, b, path=None):
        "merges b into a"
        if path is None:
            path = []

        # is b empty?
        if not bool(b):
            return a

        for key in b:
            if key in a:
                if isinstance(a[key], dict) and isinstance(b[key], dict):
                    self._merge_dicts(a[key], b[key], path + [str(key)])
                elif a[key] == b[key]:
                    pass  # same leaf value
                else:
                    raise Exception("Conflict at %s" % ".".join(path + [str(key)]))
            else:
                a[key] = b[key]
        return a

    def _populate_interfaces_status_interface(self, interface_table):
        interfaces = dict()

        for key in interface_table:

            i = interface_table[key]
            interface = dict()
            interface["state"] = i[6].lower()
            interface["type"] = i[1]
            interface["mtu"] = self._mtu
            interface["duplex"] = i[2].lower()
            interface["negotiation"] = i[4].lower()
            interface["control"] = i[5].lower()
            interface["presure"] = i[7].lower()
            interface["mode"] = i[8].lower()

            if i[6] == "Up":
                interface["bandwith"] = int(i[3]) * 1000  # to get speed in kb
            else:
                interface["bandwith"] = None

            for key in interface:
                if interface[key] == "--":
                    interface[key] = None

            # ToDo canonicalize iname
            interfaces[i[0]] = interface
        return interfaces

    def _populate_interfaces_status_portchanel(self, interface_table):
        interfaces = dict()

        for key in interface_table:

            interface = dict()
            i = interface_table[key]
            interface["state"] = i[6].lower()
            interface["type"] = i[1]
            interface["mtu"] = self._mtu
            interface["duplex"] = i[2].lower()
            interface["negotiation"] = i[4].lower()
            interface["control"] = i[5].lower()

            if i[6] == "Up":
                interface["bandwith"] = int(i[3]) * 1000  # to get speed in kb
            else:
                interface["bandwith"] = None

            for key in interface:
                if interface[key] == "--":
                    interface[key] = None

            # ToDo canonicalize iname
            interfaces[i[0]] = interface

        return interfaces

    def populate_interfaces_status(self, data):
        tables = self._split_to_tables(data)

        interface_table = self._parse_table(tables[0])
        portchanel_table = self._parse_table(tables[1])

        interfaces = self._populate_interfaces_status_interface(interface_table)
        self.facts["interfaces"] = self._merge_dicts(
            self.facts["interfaces"], interfaces
        )
        interfaces = self._populate_interfaces_status_portchanel(portchanel_table)
        self.facts["interfaces"] = self._merge_dicts(
            self.facts["interfaces"], interfaces
        )

    def _populate_interfaces_configuration_interface(self, interface_table):
        interfaces = dict()

        for key in interface_table:

            i = interface_table[key]
            interface = dict()
            interface["admin_state"] = i[6].lower()
            interface["mdix"] = i[8].lower()

            # ToDo canonicalize iname
            interfaces[i[0]] = interface
        return interfaces

    def _populate_interfaces_configuration_portchanel(self, interface_table):
        interfaces = dict()

        for key in interface_table:

            interface = dict()
            i = interface_table[key]

            interface["admin_state"] = i[5].lower()

            # ToDo canonicalize iname
            interfaces[i[0]] = interface

        return interfaces

    def populate_interfaces_configuration(self, data):
        tables = self._split_to_tables(data)

        interface_table = self._parse_table(tables[0])
        portchanel_table = self._parse_table(tables[1])

        interfaces = self._populate_interfaces_configuration_interface(interface_table)
        self.facts["interfaces"] = self._merge_dicts(
            self.facts["interfaces"], interfaces
        )
        interfaces = self._populate_interfaces_configuration_portchanel(
            portchanel_table
        )
        self.facts["interfaces"] = self._merge_dicts(
            self.facts["interfaces"], interfaces
        )

    def _populate_interfaces_description_interface(self, interface_table):
        interfaces = dict()

        for key in interface_table:

            i = interface_table[key]
            interface = dict()
            interface["description"] = i[1]

            if interface["description"] == "":
                interface["description"] = None

            # ToDo canonicalize iname
            interfaces[i[0]] = interface
        return interfaces

    def _populate_interfaces_description_portchanel(self, interface_table):
        interfaces = dict()

        for key in interface_table:

            interface = dict()
            i = interface_table[key]

            interface["description"] = i[1]

            if interface["description"] == "":
                interface["description"] = None

            # ToDo canonicalize iname
            interfaces[i[0]] = interface

        return interfaces

    def populate_interfaces_description(self, data):
        tables = self._split_to_tables(data)

        interface_table = self._parse_table(tables[0], False)
        portchanel_table = self._parse_table(tables[1], False)

        interfaces = self._populate_interfaces_description_interface(interface_table)
        self.facts["interfaces"] = self._merge_dicts(
            self.facts["interfaces"], interfaces
        )
        interfaces = self._populate_interfaces_description_portchanel(portchanel_table)
        self.facts["interfaces"] = self._merge_dicts(
            self.facts["interfaces"], interfaces
        )

    def _populate_address_ipv4(self, ip_table):
        ips = list()
        interfaces = dict()

        for key in ip_table:
            cidr = ip_table[key][0]

            # TODO interface canonicalization
            interface = ip_table[key][1]
            ip, mask = cidr.split("/")

            ips.append(ip)

            # add ips to interface
            self._new_interface(interface)
            if "ipv4" not in self.facts["interfaces"][interface]:
                self.facts["interfaces"][interface]["ipv4"] = list()

            self.facts["interfaces"][interface]["ipv4"].append(
                dict(address=ip, subnet=mask)
            )

        return ips

    def populate_addresses_ipv4(self, data):
        tables = self._split_to_tables(data)
        ip_table = self._parse_table(tables[0])

        ips = self._populate_address_ipv4(ip_table)
        self.facts["all_ipv4_addresses"] = ips

    def _populate_address_ipv6(self, ip_table):
        ips = list()

        for key in ip_table:
            ip = ip_table[key][3]
            interface = ip_table[key][0]

            ips.append(ip)

            # add ips to interface
            self._new_interface(interface)
            if "ipv6" not in self.facts["interfaces"][interface]:
                self.facts["interfaces"][interface]["ipv6"] = list()

            self.facts["interfaces"][interface]["ipv6"].append(dict(address=ip))

        return ips

    def _new_interface(self, interface):

        if interface in self.facts["interfaces"]:
            return
        else:
            self.facts["interfaces"][interface] = dict()
            self.facts["interfaces"][interface]["mtu"] = self._mtu
            self.facts["interfaces"][interface]["admin_state"] = "up"
            self.facts["interfaces"][interface]["description"] = None
            self.facts["interfaces"][interface]["state"] = "up"
            self.facts["interfaces"][interface]["bandwith"] = None
            self.facts["interfaces"][interface]["duplex"] = None
            self.facts["interfaces"][interface]["negotiation"] = None
            self.facts["interfaces"][interface]["control"] = None
            return

    def populate_addresses_ipv6(self, data):
        tables = self._split_to_tables(data)

        ip_table = self._parse_table(tables[0])
        ips = self._populate_address_ipv6(ip_table)
        self.facts["all_ipv6_addresses"] = ips

    def populate_interfaces_mtu(self, data):
        # by documentation SG350
        match = re.search(r"Jumbo frames are enabled", data, re.M)
        if match:
            mtu = 9000
        else:
            mtu = 1518

        self._mtu = mtu

    def populate_neighbors(self, data):
        tables = self._split_to_tables(data)

        neighbor_table = self._parse_table(tables[0], allow_empty_fields=[3])

        neighbors = dict()
        for key in neighbor_table:
            neighbor = neighbor_table[key]

            # TODO: canonicalize interfaces
            ifcname = neighbor[0]

            host = neighbor[3]
            port = neighbor[2]

            hostport = {"host": host, "port": port}

            if ifcname not in neighbors:
                neighbors[ifcname] = list()

            neighbors[ifcname].append(hostport)

        self.facts["neighbors"] = neighbors


# class Routing(FactsBase):
#
#     COMMANDS = [
#         '/routing bgp peer print detail without-paging',
#         '/routing bgp vpnv4-route print detail without-paging',
#         '/routing bgp instance print detail without-paging',
#         '/ip route print detail without-paging',
#         '/routing ospf instance print detail without-paging',
#         '/routing ospf neighbor print detail without-paging'
#     ]
#
#     DETAIL_RE = re.compile(r'([\w\d\-]+)=\"?(\w{3}/\d{2}/\d{4}\s\d{2}:\d{2}:\d{2}|[\w\d\-\.:/]+)')
#     WRAPPED_LINE_RE = re.compile(r'^\s+(?!\d)')
#
#     def populate(self):
#         super().populate()
#         self.facts['bgp_peer'] = dict()
#         self.facts['bgp_vpnv4_route'] = dict()
#         self.facts['bgp_instance'] = dict()
#         self.facts['route'] = dict()
#         self.facts['ospf_instance'] = dict()
#         self.facts['ospf_neighbor'] = dict()
#         data = self.responses[0]
#         if data:
#             peer = self.parse_bgp_peer(data)
#             self.populate_bgp_peer(peer)
#         data = self.responses[1]
#         if data:
#             vpnv4 = self.parse_vpnv4_route(data)
#             self.populate_vpnv4_route(vpnv4)
#         data = self.responses[2]
#         if data:
#             instance = self.parse_instance(data)
#             self.populate_bgp_instance(instance)
#         data = self.responses[3]
#         if data:
#             route = self.parse_route(data)
#             self.populate_route(route)
#         data = self.responses[4]
#         if data:
#             instance = self.parse_instance(data)
#             self.populate_ospf_instance(instance)
#         data = self.responses[5]
#         if data:
#             instance = self.parse_ospf_neighbor(data)
#             self.populate_ospf_neighbor(instance)
#
#     def preprocess(self, data):
#         preprocessed = list()
#         for line in data.split('\n'):
#             if len(line) == 0 or line[:5] == 'Flags':
#                 continue
#
#             if not re.match(self.WRAPPED_LINE_RE, line):
#                 preprocessed.append(line)
#             else:
#                 preprocessed[-1] += line
#         return preprocessed
#
#     def parse_name(self, data):
#         match = re.search(r'name=.(\S+\b)', data, re.M)
#         if match:
#             return match.group(1)
#
#     def parse_interface(self, data):
#         match = re.search(r'interface=([\w\d\-]+)', data, re.M)
#         if match:
#             return match.group(1)
#
#     def parse_instance_name(self, data):
#         match = re.search(r'instance=([\w\d\-]+)', data, re.M)
#         if match:
#             return match.group(1)
#
#     def parse_routing_mark(self, data):
#         match = re.search(r'routing-mark=([\w\d\-]+)', data, re.M)
#         if match:
#             return match.group(1)
#         else:
#             match = 'main'
#             return match
#
#     def parse_bgp_peer(self, data):
#         facts = dict()
#         data = self.preprocess(data)
#         for line in data:
#             name = self.parse_name(line)
#             facts[name] = dict()
#             for (key, value) in re.findall(self.DETAIL_RE, line):
#                 facts[name][key] = value
#         return facts
#
#     def parse_instance(self, data):
#         facts = dict()
#         data = self.preprocess(data)
#         for line in data:
#             name = self.parse_name(line)
#             facts[name] = dict()
#             for (key, value) in re.findall(self.DETAIL_RE, line):
#                 facts[name][key] = value
#         return facts
#
#     def parse_vpnv4_route(self, data):
#         facts = dict()
#         data = self.preprocess(data)
#         for line in data:
#             name = self.parse_interface(line)
#             facts[name] = dict()
#             for (key, value) in re.findall(self.DETAIL_RE, line):
#                 facts[name][key] = value
#         return facts
#
#     def parse_route(self, data):
#         facts = dict()
#         data = self.preprocess(data)
#         for line in data:
#             name = self.parse_routing_mark(line)
#             facts[name] = dict()
#             for (key, value) in re.findall(self.DETAIL_RE, line):
#                 facts[name][key] = value
#         return facts
#
#     def parse_ospf_instance(self, data):
#         facts = dict()
#         data = self.preprocess(data)
#         for line in data:
#             name = self.parse_name(line)
#             facts[name] = dict()
#             for (key, value) in re.findall(self.DETAIL_RE, line):
#                 facts[name][key] = value
#         return facts
#
#     def parse_ospf_neighbor(self, data):
#         facts = dict()
#         data = self.preprocess(data)
#         for line in data:
#             name = self.parse_instance_name(line)
#             facts[name] = dict()
#             for (key, value) in re.findall(self.DETAIL_RE, line):
#                 facts[name][key] = value
#         return facts
#
#     def populate_bgp_peer(self, data):
#         for key, value in iteritems(data):
#             self.facts['bgp_peer'][key] = value
#
#     def populate_vpnv4_route(self, data):
#         for key, value in iteritems(data):
#             self.facts['bgp_vpnv4_route'][key] = value
#
#     def populate_bgp_instance(self, data):
#         for key, value in iteritems(data):
#             self.facts['bgp_instance'][key] = value
#
#     def populate_route(self, data):
#         for key, value in iteritems(data):
#             self.facts['route'][key] = value
#
#     def populate_ospf_instance(self, data):
#         for key, value in iteritems(data):
#             self.facts['ospf_instance'][key] = value
#
#     def populate_ospf_neighbor(self, data):
#         for key, value in iteritems(data):
#             self.facts['ospf_neighbor'][key] = value

FACT_SUBSETS = dict(
    default=Default,
    hardware=Hardware,
    interfaces=Interfaces,
    config=Config,
    #    routing=Routing,
)

VALID_SUBSETS = frozenset(FACT_SUBSETS.keys())

warnings = list()


def main():
    """main entry point for module execution"""
    argument_spec = dict(
        gather_subset=dict(
            default=["!config"],
            type="list",
            elements="str",
            choices=[
                "default",
                "all",
                "hardware",
                "config",
                "interfaces",
                "!hardware",
                "!config",
                "!interfaces",
            ],
        )
    )

    argument_spec.update(ciscosmb_argument_spec)

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    gather_subset = module.params["gather_subset"]

    runable_subsets = set()
    exclude_subsets = set()

    for subset in gather_subset:
        if subset == "all":
            runable_subsets.update(VALID_SUBSETS)
            continue

        if subset.startswith("!"):
            subset = subset[1:]
            if subset == "all":
                exclude_subsets.update(VALID_SUBSETS)
                continue
            exclude = True
        else:
            exclude = False

        if subset not in VALID_SUBSETS:
            module.fail_json(msg="Bad subset: %s" % subset)

        if exclude:
            exclude_subsets.add(subset)
        else:
            runable_subsets.add(subset)

    if not runable_subsets:
        runable_subsets.update(VALID_SUBSETS)

    runable_subsets.difference_update(exclude_subsets)
    runable_subsets.add("default")

    facts = dict()
    facts["gather_subset"] = list(runable_subsets)

    instances = list()
    for key in runable_subsets:
        instances.append(FACT_SUBSETS[key](module))

    for inst in instances:
        inst.populate()
        facts.update(inst.facts)

    ansible_facts = dict()
    for key, value in iteritems(facts):
        key = "ansible_net_%s" % key
        ansible_facts[key] = value

    module.exit_json(ansible_facts=ansible_facts, warnings=warnings)


if __name__ == "__main__":
    main()
