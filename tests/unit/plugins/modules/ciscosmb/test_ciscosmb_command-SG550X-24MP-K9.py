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

from ansible_collections.community.network.tests.unit.compat.mock import patch
from ansible_collections.community.network.tests.unit.plugins.modules.utils import set_module_args
from .ciscosmb_module import TestCiscoSMBModule, load_fixture

from ansible_collections.qaxi.ciscosmb.plugins.modules import ciscosmb_command


class TestCiscoSMBCommandModule(TestCiscoSMBModule):

    module = ciscosmb_command

    def setUp(self):
        super().setUp()
        self.mock_run_commands = patch('ansible_collections.qaxi.ciscosmb.plugins.modules.ciscosmb_command.run_commands')
        self.run_commands = self.mock_run_commands.start()

    def tearDown(self):
        super().tearDown()
        self.mock_run_commands.stop()

    def load_fixtures(self, commands=None):
        def load_from_file(*args, **kwargs):
            module, commands = args
            output = list()

            for command in commands:
                filename = str(command).split(' | ')[0].replace(' ', '_')
                output.append(load_fixture('ciscosmb_command-SG550X-24MP-K9-%s' % filename))
            return output

        self.run_commands.side_effect = load_from_file

    def test_ciscosmb_command_simple(self):
        set_module_args(dict(commands=["show version"]))
        result = self.execute_module()
        self.assertEqual(len(result["stdout"]), 1)
        self.assertTrue(result["stdout"][0].startswith("Active-image: flash:"))

    def test_ciscosmb_command_multiple(self):
        set_module_args(dict(commands=["show version", "show version"]))
        result = self.execute_module()
        self.assertEqual(len(result["stdout"]), 2)
        self.assertTrue(result["stdout"][0].startswith("Active-image: flash:"))

    def test_ciscosmb_command_wait_for(self):
        wait_for = 'result[0] contains "tesla_hybrid"'
        set_module_args(dict(commands=["show version"], wait_for=wait_for))
        self.execute_module()

    def test_ciscosmb_command_wait_for_fails(self):
        wait_for = 'result[0] contains "test string"'
        set_module_args(dict(commands=["show version"], wait_for=wait_for))
        self.execute_module(failed=True)
        self.assertEqual(self.run_commands.call_count, 10)

    def test_ciscosmb_command_retries(self):
        wait_for = 'result[0] contains "test string"'
        set_module_args(
            dict(commands=["show version"], wait_for=wait_for, retries=2)
        )
        self.execute_module(failed=True)
        self.assertEqual(self.run_commands.call_count, 2)

    def test_ciscosmb_command_match_any(self):
        wait_for = [
            'result[0] contains "tesla_hybrid"',
            'result[0] contains "test string"',
        ]
        set_module_args(
            dict(commands=["show version"], wait_for=wait_for, match="any")
        )
        self.execute_module()

    def test_ciscosmb_command_match_all(self):
        wait_for = [
            'result[0] contains "Active-image"',
            'result[0] contains "tesla_hybrid"',
        ]
        set_module_args(
            dict(commands=["show version"], wait_for=wait_for, match="all")
        )
        self.execute_module()

    def test_ciscosmb_command_match_all_failure(self):
        wait_for = [
            'result[0] contains "tesla_hybrid"',
            'result[0] contains "test string"',
        ]
        commands = ["show version", "show version"]
        set_module_args(
            dict(commands=commands, wait_for=wait_for, match="all")
        )
        self.execute_module(failed=True)