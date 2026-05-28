from __future__ import absolute_import, division, print_function
__metaclass__ = type

import json
import contextlib

from ansible_collections.community.ciscosmb.tests.unit.compat import unittest
from ansible_collections.community.ciscosmb.tests.unit.compat.mock import patch
from ansible.module_utils import basic
from ansible.module_utils._text import to_bytes


@contextlib.contextmanager
def set_module_args(args):
    if '_ansible_remote_tmp' not in args:
        args['_ansible_remote_tmp'] = '/tmp'
    if '_ansible_keep_remote_files' not in args:
        args['_ansible_keep_remote_files'] = False

    try:
        from ansible.module_utils.testing import patch_module_args
    except ImportError:
        args = json.dumps({'ANSIBLE_MODULE_ARGS': args})
        with patch.object(basic, '_ANSIBLE_ARGS', to_bytes(args)):
            yield
    else:
        with patch_module_args(args):
            yield


class AnsibleExitJson(Exception):
    pass


class AnsibleFailJson(Exception):
    pass


def exit_json(*args, **kwargs):
    if 'changed' not in kwargs:
        kwargs['changed'] = False
    raise AnsibleExitJson(kwargs)


def fail_json(*args, **kwargs):
    kwargs['failed'] = True
    raise AnsibleFailJson(kwargs)


class ModuleTestCase(unittest.TestCase):

    def setUp(self):
        self.mock_module = patch.multiple(basic.AnsibleModule, exit_json=exit_json, fail_json=fail_json)
        self.mock_module.start()
        self.mock_sleep = patch('time.sleep')
        self.mock_sleep.start()
        self.addCleanup(self.mock_module.stop)
        self.addCleanup(self.mock_sleep.stop)
