##########################
BMV2_PATH=~/behavioral-model
##########################

THIS_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )


CLI_PATH=$BMV2_PATH/targets/simple_switch/simple_switch_CLI

sudo PYTHONPATH=$PYTHONPATH:$BMV2_PATH/mininet/ python3 /home/p4/MARTINI/Topology.py \
   --behavioral-exe $BMV2_PATH/targets/simple_switch/simple_switch \
   --l2switch1 ~/MARTINI/p4src/p4_stlset.json \
   --l2switch2 ~/MARTINI/p4src/p4_fwd.json \
   --cli $CLI_PATH