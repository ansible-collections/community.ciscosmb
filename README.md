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

## Install

```
ansible-galaxy collection install qaxi.ciscosmb
```

## Testing

```
ansible-test sanity --local # or --docker
ansible-test units  --local # or --docker
```

## Publish
```
ansible-galaxy collection build -v --force \
&& ansible-galaxy collection publish ./qaxi-ciscosmb-X.X.X.tar.gz --token <TOKEN> 

```


Heavy influence by Egor Zaitsev (@heuels) RouterOS dirver
