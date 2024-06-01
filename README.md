# Implementation of MARTINI 

This is the implementation of "Multi-task aware resouce efficient traffic classification via in-network inference" based on P4 BMv2 software switch. 

## Dependencies

To run the code, basic dependencies such as p4c, Bmv2 and Mininet should be installed. We strongly recommend you to place those dependencies identically on the home directory. I post links for detailed information below.

p4c: https://github.com/p4lang/p4c

Bmv2: https://github.com/p4lang/behavioral-model

Mininet: https://github.com/mininet/mininet

## Instructions

This repository is to show the feasibility of our idea which is to conduct multi-task learning for in-network inference. There are three scenarios included:
MARTINI scenario
STL scenario 1
STL scenario 2

Network topology:
* MARTINI scenario
         (MARTINI)   (only fwd) <br/>
host0 ⸺ switch1 ⸺ switch2  ⸺ host1 <br/>

* STL scenario 1
     (STL model 1, STL model 2)  (only fwd) <br/>
host0 ⸺⸺  switch1 ⸺⸺⸺  switch2  ⸺⸺  host1 <br/>

* STL scenario 2
     (STL model 1)  (STL model 2) <br/>
host0 ⸺ switch1 ⸺ switch2  ⸺ host1 <br/>


These are instructions you can follow.

### Preliminaries

1. Download the repository to the local.

2. Compile .p4 files.
```
p4c --target bmv2 --arch v1model --std p4-16 ~/MARTINI/p4src/p4_fwd.p4 -o ~/MARTINI/p4src
```
```
p4c --target bmv2 --arch v1model --std p4-16 ~/MARTINI/p4src/p4_mtl.p4 -o ~/MARTINI/p4src
```
```
p4c --target bmv2 --arch v1model --std p4-16 ~/MARTINI/p4src/p4_stl1.p4 -o ~/MARTINI/p4src
```
```
p4c --target bmv2 --arch v1model --std p4-16 ~/MARTINI/p4src/p4_stl2.p4 -o ~/MARTINI/p4src
```
```
p4c --target bmv2 --arch v1model --std p4-16 ~/MARTINI/p4src/p4_stlset.p4 -o ~/MARTINI/p4src
```

3. Set up virtual network interfaces.
```
sudo bash veth.sh
```

### Excution steps

The following steps are common to the MARTINI scenario, STL scenario 1, and STL scenario 2. The only difference between each scenario is the shell script file executed, while the rest of the process remains the same.

1. (terminal 1) Run the execution program corresponding to the selected scenario. It will take a few seconds to be completely activated.
```
MARTINI scenario: bash run_topology_mtlfwd.sh
STL scenario 1: bash run_topology_stlsetfwd.sh
STL scenario 2: bash run_topology_stl12.sh
```

2. (terminal 2) Insert model weights to the switches written in P4 rules after switches are completely activated. 
```
MARTINI scenario: bash insert_rules_MTLfwd.sh
STL scenario 1: bash insert_rules_STLsetfwd.sh
STL scenario 2: bash insert_rules_STLdist.sh
```

3. (terminal 1) We're now in the Mininet environment. Turn on the xterm terminals for the hosts.
```
xterm host0 host1
```

4. (xterm for host1) For the destination host, prepare to detect received packets. 
```
python3 receive.py
```

5. (xterm for host0) Send packets on the source host. 
```
python3 send.py
```