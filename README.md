# Ansible Cisco Small Bussiness Switches (SMB) module

Ansible Galaxy module for Cisco SMB switches - SG300, SG500, SG350, SG550

## Install

```
ansible-galaxy collection install qaxi.ciscosmb
```

## Use
Tested on SG350-28-K9, SG500-52-K9, SG550X-24MP-K9 and SG550X-48 stack

Limited capabilities - Work in progress

file `cismosmb_inventory.yml`
```
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
      ansible_network_os: qaxi.ciscosmb.ciscosmb
    switch2:
      ansible_host: WWW.XXX.YYY.ZZZ
      ansible_network_os: qaxi.ciscosmb.ciscosmb

```

playbook `ciscosmb_gather_facts.yml`
```
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
      qaxi.ciscosmb.ciscosmb_facts:
        gather_subset:
          - default
      # when: ansible_network_os == 'qaxi.ciscosmb.ciscosmb'

    - name: CiscoSMB - Gather Facts - subset config
      qaxi.ciscosmb.ciscosmb_facts:
        gather_subset:
          - config
      # when: ansible_network_os == 'qaxi.ciscosmb.ciscosmb'

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

### Needs installed
```
git
pip install -r requirements-dev.txt
ansible-galaxy collection install ansible.netcommon
```

### Testing

```
export PY="--python 3.8" # set your version or unset
   ansible-test sanity --local ${PY}  \
&& ansible-test units  --local ${PY} \
&& rm -f ./qaxi-ciscosmb-*.tar.gz  \
&& ansible-galaxy collection build -v --force  \
&& export GALAXY_IMPORTER_CONFIG=./galaxy-importer.cfg  \
&& python3 -m galaxy_importer.main ./qaxi-ciscosmb-*.tar.gz  \
&& rm -f ./qaxi-ciscosmb-*.tar.gz
```

## Publish
```
ansible-galaxy collection build -v --force \
&& ansible-galaxy collection publish ./qaxi-ciscosmb-X.X.X.tar.gz --token <TOKEN> 

```

Heavy influence by Egor Zaitsev (@heuels) RouterOS dirver
