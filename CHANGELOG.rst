=====================================
CiscoSMB Ansible module Release Notes
=====================================

.. contents:: Topics


v1.0.5
======

Minor Changes
-------------

- CI  change <plugin_type> <name> to name <name> for validate-module
- CI - add ansible 2.13 to test matrix

v1.0.4
======

Release Summary
---------------

Release Date: 2021-09-13


Bugfixes
--------

- Module command does not support check_mode - https://github.com/ansible-collections/community.ciscosmb/pull/45

v1.0.3
======

Release Summary
---------------

Release Date: 2019-10-31
Minor changes in documentation, adding Python 3.6 as a supported version


Minor Changes
-------------

- Add Py 3.6 to supported python versions (https://github.com/ansible-collections/community.ciscosmb/pull/44)
- Fix link to issue tracker in galaxy.yml (https://github.com/ansible-collections/community.ciscosmb/pull/42)
- Misc doc fixes for collection inclusion (https://github.com/ansible-collections/community.ciscosmb/pull/41)

v1.0.2
======

Release Summary
---------------

Release Date: 2021-08-09 bugfix release

Minor Changes
-------------

- remove unnecersary parameters on function re.sub()

Bugfixes
--------

- solves issue

v1.0.1
======

Release Summary
---------------

Minor fixes for ansible collections inclusion

Minor Changes
-------------

- Added Releasing, CoC and Contributing to README.md
- Added author
- Added license header
- Release policy, versioning, deprecation
- Updated CoC, added email address
- more descriptiove Release section on README.md

v1.0.0
======

Major Changes
-------------

- transform collection qaxi.ciscosmb to community.ciscosmb
- transform community.ciscosmb.ciscosmb_command to community.ciscosmb.command
- transform community.ciscosmb.ciscosmb_facts to community.ciscosmb.facts

Minor Changes
-------------

- setup standard Ansible CI

v0.9.1
======

Minor Changes
-------------

- correct version bumping

v0.9.0
======

Major Changes
-------------

- interface name canonicalization

v0.8.0
======

Major Changes
-------------

- add antsibull-changelog support

Minor Changes
-------------

- Python 2.6, 2.7, 3.5 compatibility
- add Code of conduct
- add Contribution
- add required files for community inclusion
- added ansible dev-guide manual test
- better tests requirements
- check tags and add tag switch
- cluter removed
- code cleaning
- update my tests

v0.1.1
======

Major Changes
-------------

- Python 2.6, 2.7, 3.5 is required
- add antsibull-changelog support

Minor Changes
-------------

- add Code of conduct
- add Contribution
- add required files for community inclusion
- check tags and add tag switch
- cluter removed
- code cleaning

v0.1.0
======

Major Changes
-------------

- added facts subset "interfaces"

Minor Changes
-------------

- remove mock warning

v0.0.6
======

Major Changes
-------------

- add CBS350 support
- unit tests for CBS350

Minor Changes
-------------

- doc update

v0.0.5
======

Major Changes
-------------

- add ciscosmb_command

v0.0.4
======

Minor Changes
-------------

- uptime in seconds

v0.0.2
======

Major Changes
-------------

- ciscosmb_facts with default subset and unit tests
