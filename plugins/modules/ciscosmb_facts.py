#!/usr/bin/python

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = '''
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
'''

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

from ansible_collections.qaxi.ciscosmb.plugins.module_utils.network.ciscosmb.ciscosmb import run_commands
from ansible_collections.qaxi.ciscosmb.plugins.module_utils.network.ciscosmb.ciscosmb import ciscosmb_argument_spec
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.six import iteritems


class FactsBase(object):

    COMMANDS = list()

    def __init__(self, module):
        self.module = module
        self.facts = dict()
        self.responses = None

    def populate(self):
        self.responses = run_commands(self.module, commands=self.COMMANDS, check_rc=False)

    def run(self, cmd):
        return run_commands(self.module, commands=cmd, check_rc=False)


class Default(FactsBase):

    COMMANDS = [
        'show version',
        'show system',
        'show cpu utilization',
        'show inventory',
    ]

    def populate(self):
        super().populate()

        data = self.responses[0]
        if data:
            self.facts['version'] = self.parse_version(data)
            self.facts['boot_version'] = self.parse_boot_version(data)

        data = self.responses[1]
        if data:
            self.facts['uptime'] = self.parse_uptime(data)
            self.facts['hostname'] = self.parse_hostname(data)

        data = self.responses[2]
        if data:
            self.facts['cpu_load'] = self.parse_cpu_load(data)

        data = self.responses[3]
        if data:
            modules = self.parse_inventory(data)
            stacked_models = self.parse_stacked_models(modules)
            if len(stacked_models) >= 2:
                stacked_serialnums = self.parse_stacked_serialnums(modules)
                self.facts['stacked_models'] = stacked_models
                self.facts['stacked_serialnums'] = stacked_serialnums
            self.facts['model'] = self.parse_model(modules)
            self.facts['serialnum'] = self.parse_serialnum(modules)
            self.facts['hw_version'] = self.parse_hw_version(modules)
            self.facts['hw_modules'] = modules

    # show version
    def parse_version(self, data):
        # Cisco SMB 300 and 500 - fw 1.x.x.x
        match = re.search(r'^SW version\s*(\S+)\s*.*$', data, re.M)
        if match:
            return match.group(1)
        # Cisco SMB 350 and 550 - fw 2.x.x.x
        match = re.search(r'^  Version:\s*(\S+)\s*.*$', data, re.M)
        if match:
            return match.group(1)

    def parse_boot_version(self, data):
        match = re.search(r'Boot version\s*(\S+)\s*.*$', data, re.M)
        if match:
            return match.group(1)

    # show system
    def parse_uptime(self, data):
        match = re.search(r'^System Up Time \S+:\s+(\S+)\s*$', data, re.M)
        if match:
            (dayhour, mins, sec) = match.group(1).split(':')
            (day, hour) = dayhour.split(',')
            # output in seconds
            return (int(day) * 86400) + (int(hour) * 3600) + (int(mins) * 60) + int(sec)

    def parse_hostname(self, data):
        match = re.search(r'^System Name:\s*(\S+)\s*$', data, re.M)
        if match:
            return match.group(1)

    # show cpu utilization
    def parse_cpu_load(self, data):
        match = re.search(r'one minute:\s+(\d+)%;\s*', data, re.M)
        if match:
            return match.group(1)

    # show inventory
    def parse_inventory(self, data):
        # make 1 module 1 line
        data = re.sub(r'\nPID', '  PID', data, re.M)
        # delete empty lines
        data = re.sub(r'^\n', '', data, re.M)
        data = re.sub(r'\n\n', '', data, re.M)
        data = re.sub(r'\n\s*\n', r'\n', data, re.M)

        lines = data.splitlines()

        modules = {}
        for line in lines:
            # remove extra chars
            line = re.sub(r'"', r'', line, re.M)
            line = re.sub(r'\s+', r' ', line, re.M)
            # normalize lines
            line = re.sub(r':\s', r'"', line, re.M)
            line = re.sub(r'\s+DESCR"', r'"DESCR"', line, re.M)
            line = re.sub(r'\s+PID"', r'"PID"', line, re.M)
            line = re.sub(r'\s+VID"', r'"VID"', line, re.M)
            line = re.sub(r'\s+SN"', r'"SN"', line, re.M)
            line = re.sub(r'\s*$', r'', line, re.M)

            match = re.search(r'^NAME"(?P<name>[^"]+)"DESCR"(?P<descr>[^"]+)"PID"(?P<pid>[^"]+)"VID"(?P<vid>[^"]+)"SN"(?P<sn>\S+)\s*', line)

            modul = match.groupdict()
            modules[modul['name']] = modul

        if modules:
            return modules

    def parse_stacked_models(self, data):
        # every inventory has module with NAME: "1"
        # stacks have modules 2 3 ... 8
        models = []
        for n in range(1, 9):
            if f'{n}' in data:
                models.append(data[f'{n}']['pid'])
        return models

    def parse_stacked_serialnums(self, data):
        # every inventory has module with NAME: "1"
        # stacks have modules 2 3 ... 8
        sn = []
        for n in range(1, 9):
            if f'{n}' in data:
                sn.append(data[f'{n}']['sn'])
        return sn

    def parse_model(self, data):
        # every inventory has module with NAME: "1"
        model = data['1']['pid']
        if 'stacked_models' in self.facts:
            model = re.sub(r'-.*$', '', model)
            model = 'Stack ' + model
        return model

    def parse_serialnum(self, data):
        # every inventory has module with NAME: "1"
        sn = data['1']['sn']
        return sn

    def parse_hw_version(self, data):
        # every inventory has module with NAME: "1"
        sn = data['1']['vid']
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
        match = re.search(r'Total size of (\S+): (\d+) bytes', data, re.M)

        if match:  # fw 1.x
            self.facts['spacetotal_mb'] = round(int(match[2]) / 1024 / 1024, 1)
            match = re.search(r'Free size of (\S+): (\d+) bytes', data, re.M)
            self.facts['spacefree_mb'] = round(int(match[2]) / 1024 / 1024, 1)

        else:
            match = re.search(r'(\d+)K of (\d+)K are free', data, re.M)
            if match:  # fw 2.x, 3.x
                self.facts['spacetotal_mb'] = round(int(match[2]) / 1024, 1)
                self.facts['spacefree_mb'] = round(int(match[1]) / 1024, 1)


class Config(FactsBase):

    COMMANDS = ['show running-config detailed']

    def populate(self):
        super().populate()
        data = self.responses[0]
        if data:
            self.facts['config'] = data


class Interfaces(FactsBase):

    COMMANDS = [
        '/interface print detail without-paging',
        '/ip address print detail without-paging',
        '/ipv6 address print detail without-paging',
        '/ip neighbor print detail without-paging'
    ]

    DETAIL_RE = re.compile(r'([\w\d\-]+)=\"?(\w{3}/\d{2}/\d{4}\s\d{2}:\d{2}:\d{2}|[\w\d\-\.:/]+)')
    WRAPPED_LINE_RE = re.compile(r'^\s+(?!\d)')

    def populate(self):
        super().populate()

        self.facts['interfaces'] = dict()
        self.facts['all_ipv4_addresses'] = list()
        self.facts['all_ipv6_addresses'] = list()
        self.facts['neighbors'] = list()

        data = self.responses[0]
        if data:
            interfaces = self.parse_interfaces(data)
            self.populate_interfaces(interfaces)

        data = self.responses[1]
        if data:
            data = self.parse_detail(data)
            self.populate_addresses(data, 'ipv4')

        data = self.responses[2]
        if data:
            data = self.parse_detail(data)
            self.populate_addresses(data, 'ipv6')

        data = self.responses[3]
        if data:
            self.facts['neighbors'] = list(self.parse_detail(data))

    def populate_interfaces(self, data):
        for key, value in iteritems(data):
            self.facts['interfaces'][key] = value

    def populate_addresses(self, data, family):
        for value in data:
            key = value['interface']
            if family not in self.facts['interfaces'][key]:
                self.facts['interfaces'][key][family] = list()
            addr, subnet = value['address'].split("/")
            ip = dict(address=addr.strip(), subnet=subnet.strip())
            self.add_ip_address(addr.strip(), family)
            self.facts['interfaces'][key][family].append(ip)

    def add_ip_address(self, address, family):
        if family == 'ipv4':
            self.facts['all_ipv4_addresses'].append(address)
        else:
            self.facts['all_ipv6_addresses'].append(address)

    def preprocess(self, data):
        preprocessed = list()
        for line in data.split('\n'):
            if len(line) == 0 or line[:5] == 'Flags':
                continue

            if not re.match(self.WRAPPED_LINE_RE, line):
                preprocessed.append(line)
            else:
                preprocessed[-1] += line
        return preprocessed

    def parse_interfaces(self, data):
        facts = dict()
        data = self.preprocess(data)
        for line in data:
            parsed = dict(re.findall(self.DETAIL_RE, line))
            if "name" not in parsed:
                continue
            facts[parsed["name"]] = dict(re.findall(self.DETAIL_RE, line))
        return facts

    def parse_detail(self, data):
        data = self.preprocess(data)
        for line in data:
            parsed = dict(re.findall(self.DETAIL_RE, line))
            if "interface" not in parsed:
                continue
            yield parsed


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
    """main entry point for module execution
    """
    argument_spec = dict(
        gather_subset=dict(
            default=['!config'],
            type='list',
            elements='str',
            choices=[
                'default',
                'all',
                'hardware',
                'config',
                'interfaces',
                '!hardware',
                '!config',
                '!interfaces'
            ]
        )
    )

    argument_spec.update(ciscosmb_argument_spec)

    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True)

    gather_subset = module.params['gather_subset']

    runable_subsets = set()
    exclude_subsets = set()

    for subset in gather_subset:
        if subset == 'all':
            runable_subsets.update(VALID_SUBSETS)
            continue

        if subset.startswith('!'):
            subset = subset[1:]
            if subset == 'all':
                exclude_subsets.update(VALID_SUBSETS)
                continue
            exclude = True
        else:
            exclude = False

        if subset not in VALID_SUBSETS:
            module.fail_json(msg='Bad subset: %s' % subset)

        if exclude:
            exclude_subsets.add(subset)
        else:
            runable_subsets.add(subset)

    if not runable_subsets:
        runable_subsets.update(VALID_SUBSETS)

    runable_subsets.difference_update(exclude_subsets)
    runable_subsets.add('default')

    facts = dict()
    facts['gather_subset'] = list(runable_subsets)

    instances = list()
    for key in runable_subsets:
        instances.append(FACT_SUBSETS[key](module))

    for inst in instances:
        inst.populate()
        facts.update(inst.facts)

    ansible_facts = dict()
    for key, value in iteritems(facts):
        key = 'ansible_net_%s' % key
        ansible_facts[key] = value

    module.exit_json(ansible_facts=ansible_facts, warnings=warnings)


if __name__ == '__main__':
    main()
