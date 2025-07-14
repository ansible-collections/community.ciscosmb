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
                output.append(load_fixture('ciscosmb_facts-SX550X-24F-K9-%s' % filename))
            return output

        self.run_commands.side_effect = load_from_file

    def test_ciscosmb_facts_default(self):
        set_module_args(dict(gather_subset='default'))
        result = self.execute_module()

        self.assertEqual(
            result['ansible_facts']['ansible_net_hw_version'], 'V02'
        )
        self.assertEqual(
            result['ansible_facts']['ansible_net_model'], 'SX550X-24F-K9'
        )
        self.assertEqual(
            result['ansible_facts']['ansible_net_serialnum'], 'DNI22500E5F'
        )
