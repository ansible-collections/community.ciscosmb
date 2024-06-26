# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

# Make coding more python3-ish
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from ansible_collections.community.ciscosmb.tests.unit.compat.mock import patch
from ansible_collections.community.ciscosmb.plugins.modules import facts
from ansible_collections.community.ciscosmb.tests.unit.plugins.modules.utils import set_module_args
from .ciscosmb_module import TestCiscoSMBModule, load_fixture


class TestCiscoSMBFactsModule(TestCiscoSMBModule):

    module = facts

    def setUp(self):
        super(TestCiscoSMBFactsModule, self).setUp()
        self.mock_run_commands = patch('ansible_collections.community.ciscosmb.plugins.modules.facts.run_commands')
        self.run_commands = self.mock_run_commands.start()

    def tearDown(self):
        super(TestCiscoSMBFactsModule, self).tearDown()
        self.mock_run_commands.stop()

    def load_fixtures(self, commands=None):
        def load_from_file(*args, **kwargs):
            module = args
            commands = kwargs['commands']
            output = list()

            for command in commands:
                filename = str(command).split(' | ', 1)[0].replace(' ', '_')
                output.append(load_fixture('ciscosmb_facts-SG500-52-K9-%s' % filename))
            return output

        self.run_commands.side_effect = load_from_file

    def test_ciscosmb_facts_default(self):
        set_module_args(dict(gather_subset='default'))
        result = self.execute_module()
        self.assertEqual(
            result['ansible_facts']['ansible_net_version'], '1.4.8.6'
        )
        self.assertEqual(
            result['ansible_facts']['ansible_net_boot_version'], '1.3.7.01'
        )
        self.assertEqual(
            result['ansible_facts']['ansible_net_hw_version'], 'V02'
        )
        self.assertEqual(
            result['ansible_facts']['ansible_net_uptime'], 41737187
        )
        self.assertEqual(
            result['ansible_facts']['ansible_net_hostname'], 'sw-abcdefg-1'
        )
        self.assertEqual(
            result['ansible_facts']['ansible_net_cpu_load'], '7'
        )

        self.assertEqual(
            result['ansible_facts']['ansible_net_model'], 'SG500-52-K9'
        )
        self.assertEqual(
            result['ansible_facts']['ansible_net_serialnum'], 'ABC12345678'
        )

    def test_ciscosmb_facts_hardware(self):
        set_module_args(dict(gather_subset='hardware'))
        result = self.execute_module()
        self.assertEqual(
            result['ansible_facts']['ansible_net_spacefree_mb'], 6.8
        )
        self.assertEqual(
            result['ansible_facts']['ansible_net_spacetotal_mb'], 31.4
        )

    def test_ciscosmb_facts_config(self):
        set_module_args(dict(gather_subset='config'))
        result = self.execute_module()
        self.assertIsInstance(
            result['ansible_facts']['ansible_net_config'], str
        )

    def test_ciscosmb_facts_interfaces(self):
        set_module_args(dict(gather_subset='interfaces'))
        result = self.execute_module()

        self.assertIn(
            result['ansible_facts']['ansible_net_all_ipv4_addresses'][0], ['11.30.5.12']
        )
        self.assertEqual(
            result['ansible_facts']['ansible_net_all_ipv6_addresses'], ['fe80::36db:fdff:fe64:5bce']
        )
        self.assertEqual(
            result['ansible_facts']['ansible_net_all_ipv6_addresses'][0],
            result['ansible_facts']['ansible_net_interfaces']['vlan1']['ipv6'][0]['address']
        )
        self.assertEqual(
            len(result['ansible_facts']['ansible_net_interfaces'].keys()), 85
        )
        self.assertEqual(
            len(result['ansible_facts']['ansible_net_neighbors']), 9
        )

        interfaces = result['ansible_facts']['ansible_net_interfaces']
        ge42 = interfaces['GigabitEthernet1/42']

        self.assertEqual(ge42['bandwidth'], 1000000)

        self.assertEqual(ge42['bandwidth'], ge42['bandwith'])

#     def test_ciscosmb_facts_routing(self):
#         set_module_args(dict(gather_subset='routing'))
#         result = self.execute_module()
#         self.assertIn(
#             result['ansible_facts']['ansible_net_bgp_peer']['iBGP_BRAS.TYRMA']['name'], ['iBGP_BRAS.TYRMA']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_bgp_peer']['iBGP_BRAS.TYRMA']['instance'], ['MAIN_AS_STARKDV']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_bgp_peer']['iBGP_BRAS.TYRMA']['remote-address'], ['10.10.100.1']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_bgp_peer']['iBGP_BRAS.TYRMA']['remote-as'], ['64520']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_bgp_peer']['iBGP_BRAS.TYRMA']['nexthop-choice'], ['default']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_bgp_peer']['iBGP_BRAS.TYRMA']['multihop'], ['no']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_bgp_peer']['iBGP_BRAS.TYRMA']['route-reflect'], ['yes']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_bgp_peer']['iBGP_BRAS.TYRMA']['hold-time'], ['3m']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_bgp_peer']['iBGP_BRAS.TYRMA']['ttl'], ['default']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_bgp_peer']['iBGP_BRAS.TYRMA']['address-families'], ['ip']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_bgp_peer']['iBGP_BRAS.TYRMA']['update-source'], ['LAN_KHV']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_bgp_peer']['iBGP_BRAS.TYRMA']['default-originate'], ['never']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_bgp_peer']['iBGP_BRAS.TYRMA']['remove-private-as'], ['no']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_bgp_peer']['iBGP_BRAS.TYRMA']['as-override'], ['no']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_bgp_peer']['iBGP_BRAS.TYRMA']['passive'], ['no']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_bgp_peer']['iBGP_BRAS.TYRMA']['use-bfd'], ['yes']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_bgp_vpnv4_route']['GRE_TYRMA']['route-distinguisher'], ['64520:666']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_bgp_vpnv4_route']['GRE_TYRMA']['dst-address'], ['10.10.66.8/30']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_bgp_vpnv4_route']['GRE_TYRMA']['gateway'], ['10.10.100.1']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_bgp_vpnv4_route']['GRE_TYRMA']['interface'], ['GRE_TYRMA']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_bgp_vpnv4_route']['GRE_TYRMA']['in-label'], ['6136']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_bgp_vpnv4_route']['GRE_TYRMA']['out-label'], ['6136']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_bgp_vpnv4_route']['GRE_TYRMA']['bgp-local-pref'], ['100']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_bgp_vpnv4_route']['GRE_TYRMA']['bgp-origin'], ['incomplete']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_bgp_vpnv4_route']['GRE_TYRMA']['bgp-ext-communities'], ['RT:64520:666']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_bgp_instance']['default']['name'], ['default']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_bgp_instance']['default']['as'], ['65530']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_bgp_instance']['default']['router-id'], ['0.0.0.0']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_bgp_instance']['default']['redistribute-connected'], ['no']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_bgp_instance']['default']['redistribute-static'], ['no']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_bgp_instance']['default']['redistribute-rip'], ['no']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_bgp_instance']['default']['redistribute-ospf'], ['no']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_bgp_instance']['default']['redistribute-other-bgp'], ['no']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_bgp_instance']['default']['client-to-client-reflection'], ['yes']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_bgp_instance']['default']['ignore-as-path-len'], ['no']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_route']['altegro']['dst-address'], ['10.10.66.0/30']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_route']['altegro']['pref-src'], ['10.10.66.1']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_route']['altegro']['gateway'], ['bridge1']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_route']['altegro']['gateway-status'], ['bridge1']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_route']['altegro']['distance'], ['0']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_route']['altegro']['scope'], ['10']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_route']['altegro']['routing-mark'], ['altegro']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_ospf_instance']['default']['name'], ['default']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_ospf_instance']['default']['router-id'], ['10.10.50.1']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_ospf_instance']['default']['distribute-default'], ['never']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_ospf_instance']['default']['redistribute-connected'], ['no']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_ospf_instance']['default']['redistribute-static'], ['no']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_ospf_instance']['default']['redistribute-rip'], ['no']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_ospf_instance']['default']['redistribute-bgp'], ['no']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_ospf_instance']['default']['redistribute-other-ospf'], ['no']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_ospf_instance']['default']['metric-default'], ['1']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_ospf_instance']['default']['metric-connected'], ['20']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_ospf_instance']['default']['metric-static'], ['20']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_ospf_instance']['default']['metric-rip'], ['20']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_ospf_instance']['default']['metric-bgp'], ['auto']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_ospf_instance']['default']['metric-other-ospf'], ['auto']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_ospf_instance']['default']['in-filter'], ['ospf-in']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_ospf_instance']['default']['out-filter'], ['ospf-out']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_ospf_neighbor']['default']['instance'], ['default']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_ospf_neighbor']['default']['router-id'], ['10.10.100.1']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_ospf_neighbor']['default']['address'], ['10.10.1.2']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_ospf_neighbor']['default']['interface'], ['GRE_TYRMA']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_ospf_neighbor']['default']['priority'], ['1']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_ospf_neighbor']['default']['dr-address'], ['0.0.0.0']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_ospf_neighbor']['default']['backup-dr-address'], ['0.0.0.0']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_ospf_neighbor']['default']['state'], ['Full']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_ospf_neighbor']['default']['state-changes'], ['15']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_ospf_neighbor']['default']['ls-retransmits'], ['0']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_ospf_neighbor']['default']['ls-requests'], ['0']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_ospf_neighbor']['default']['db-summaries'], ['0']
#         )
#         self.assertIn(
#             result['ansible_facts']['ansible_net_ospf_neighbor']['default']['adjacency'], ['6h8m46s']
#         )
