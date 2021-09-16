# Ansible Cisco Small Bussiness Switches (SMB) module

Ansible Galaxy module for Cisco SMB switches - SG300, SG500, SG350, SG550, CBS350

## Install

```
ansible-galaxy collection install community.ciscosmb
```

## Use
Tested on devices:
* SG350-28-K9
* SG500-52-K9
* SG550X-24MP-K9
* CBS350-24P-4G
* SG550X-48 stack

Tested on Python versions:
* 2.6
* 2.7
* 3.6
* 3.7
* 3.8
* 3.9

file `cismosmb_inventory.yml`
```yaml
all:
  vars:
    # no automatic facts
    gather_facts: no  
    
    ansible_connection: network_cli
    ### change what you need
    # ansible_ssh_private_key_file: /dir/private.key
    # ansible_ssh_user: user
    # ansible_ssh_pass: password

  hosts:
    switch1:
      ansible_host: AAA.BBB.CCC.DDD
      ansible_network_os: community.ciscosmb.ciscosmb
    switch2:
      ansible_host: WWW.XXX.YYY.ZZZ
      ansible_network_os: community.ciscosmb.ciscosmb

```

playbook `ciscosmb_gather_facts.yml`
```yaml
- name: Gather Facts
  gather_facts: no
  hosts: all
  vars:
    - configs_dir: configs

  tasks:
    ###
    # Collect data
    #
    - name: CiscoSMB - Gather Facts - subset default
      communtity.ciscosmb.facts:
        gather_subset:
          - default
      # when: ansible_network_os == 'community.ciscosmb.ciscosmb'

    - name: CiscoSMB - Gather Facts - subset config
      community.ciscosmb.facts:
        gather_subset:
          - config
      # when: ansible_network_os == 'community.ciscosmb.ciscosmb'

    - name: Create configuration directory
      local_action: file path={{ configs_dir }} state=directory
      run_once: true
      check_mode: no
      changed_when: no

    - name: Save running config
      local_action: copy content={{ ansible_net_config }} dest={{ configs_dir }}/{{ inventory_hostname }}_net_config
```

Run
```
ansible-playbook -i ciscosmb_inventory.yml ciscosmb_gather_facts.yml
```

## Developement

### Setup environment
```
git clone https://github.com/ansible-collections/community.ciscosmb ansible_collections/community/ciscosmb
git clone --depth=1 --single-branch https://github.com/ansible-collections/ansible.netcommon.git ansible_collections/ansible/netcommon

cd ansible_collections/community/ciscosmb

python3 -m venv .venv
. .venv/bin/activate

pip install ansible
pip install -r tests/unit/requirements.txt # -r requirements-dev.txt

```

### Develop 
```
cd ansible_collections/community/ciscosmb
git pull
. .venv/bin/activate

# edit files
vim file
git commit -m "xxx" file
```

### Testing

```
cd ansible_collections/community/ciscosmb
. .venv/bin/activate

# PY="--python 3.8" # set your version or unset
METHOD="--docker" # or --local if you have no Docker installed
ansible-test sanity ${METHOD} ${PY}  \
    && ansible-test units  ${METHOD} ${PY} \
    && rm -f ./community-ciscosmb-*.tar.gz  \
    && ansible-galaxy collection build -v --force  \
    && export GALAXY_IMPORTER_CONFIG=./galaxy-importer.cfg  \
    && python3 -m galaxy_importer.main ./community-ciscosmb-*.tar.gz  \
    && rm -f ./community-ciscosmb-*.tar.gz
```

### Release 
```
cd ansible_collections/community/ciscosmb
git pull
. .venv/bin/activate

# edit version in galaxy.yml
vim galaxy.yml

# edit changelog fragments (template in changelogs/fragments/.keep)
vim changelogs/fragments/fragment.yml

# generate CHANGELOG.rst
antsibull-changelog lint -v
antsibull-changelog release -v

git commit -m "version bump to x.y.z" .
git tag x.y.z
git push 
```


## Releasing, Versioning and Deprecation

See [RELEASE_POLICY.md](https://github.com/ansible-collections/community.ciscosmb/blob/main/RELEASE_POLICY.md)

## Code of Conduct

See [CODE_OF_CONDUCT.md](https://github.com/ansible-collections/community.ciscosmb/blob/main/CODE_OF_CONDUCT.md)

## Contributing

See [CONTRIBUTING.md](https://github.com/ansible-collections/community.ciscosmb/blob/main/CONTRIBUTING.md)
