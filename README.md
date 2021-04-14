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

Limited capabilities - Work in progress

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
      communtity.ciscosmb.ciscosmb_facts:
        gather_subset:
          - default
      # when: ansible_network_os == 'community.ciscosmb.ciscosmb'

    - name: CiscoSMB - Gather Facts - subset config
      community.ciscosmb.ciscosmb_facts:
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
git clone https://github.com/ansible-collections/community.ciscosmb
cd community.ciscosmb
python3 -m venv .venv
. .venv/bin/activate
pip install ansible
pip install -r tests/unit/requirements.txt
ansible-galaxy collection install ansible.netcommon
```

### Develop 
```
cd community.ciscosmb
. .venv/bin/activate
git pull
```

### Testing

```
export PY="--python 3.8" # set your version or unset
   ansible-test sanity --local ${PY}  \
&& ansible-test units  --local ${PY} \
&& rm -f ./community-ciscosmb-*.tar.gz  \
&& ansible-galaxy collection build -v --force  \
&& export GALAXY_IMPORTER_CONFIG=./galaxy-importer.cfg  \
&& python3 -m galaxy_importer.main ./community-ciscosmb-*.tar.gz  \
&& rm -f ./community-ciscosmb-*.tar.gz
```


Heavy influenced by Egor Zaitsev (@heuels) RouterOS driver https://galaxy.ansible.com/community/routeros
