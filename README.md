# Ansible Cisco Small Bussiness Switches (SMB) module

Ansible Galaxy module for Cisco SMB switches - SG300, SG500, SG350, SG550


Tested on SG350-28-K9, SG500-52-K9, SG550X-24MP-K9 and SG550X-48 stack
```
qaxi.ciscosmb.ciscosmb_facts
    gather_subset: default
```

Work in progress (in order)
```
qaxi.ciscosmb.ciscosmb_facts
    gather_subset - config

qaxi.ciscosmb.ciscosmb_command
initial Ansible Galaxy publication
qaxi.ciscosmb.ciscosmb_facts
    gather_subset - config, interfaces, hardware
```

### Install

```
ansible-galaxy collection install qaxi.ciscosmb
```

## Developement

### Needs installed
```
git
pip install -r requires-dev.txt
ansible-galaxy collection install ansible.netcommon
```

### Testing


```
ansible-test sanity --local # or --docker
ansible-test units  --local # or --docker
rm -f ./qaxi-ciscosmb-*.tar.gz
ansible-galaxy collection build -v --force
export GALAXY_IMPORTER_CONFIG=./galaxy-importer.cfg
python3 -m galaxy_importer.main ./qaxi-ciscosmb-*.tar.gz
rm -f ./qaxi-ciscosmb-*.tar.gz
```

## Publish
```
ansible-galaxy collection build -v --force \
&& ansible-galaxy collection publish ./qaxi-ciscosmb-X.X.X.tar.gz --token <TOKEN> 

```


Heavy influence by Egor Zaitsev (@heuels) RouterOS dirver
