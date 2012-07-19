#!/bin/bash

RULE_INSTALLED=`sudo ip rule list | grep cs144 | awk '{print $3}'`
if [ $RULE_INSTALLED != '10.0.1.0/24' ]; then 
  echo Installing source routing rule
  sudo ip rule add from 10.0.1.0/24 table cs144
  sudo ip route add default dev eth1 table cs144
  sudo ip route flush cache
  sudo ip route list table cs144
  sudo ip rule list
else
  echo routing table is ready
fi

BR_INSTALLED=`sudo ovs-vsctl show | grep br0 | grep Bridge | awk '{print $2}'`
if [ ! -n $BR_INSTALLED ]; then
  echo setup bridge br0
  sudo ovs-vsctl add-br br0
  sudo ovs-vsctl add-port br0 eth1
  sudo ovs-vsctl add-port br0 root-eth0
  sudo ovs-vsctl show
else
  echo bridge is ready
fi

echo kill stale sessions
screen -S mininet -X quit
screen -S pox -X quit
echo start new sessions 
screen -S mininet -d -m sudo python lab3.py
screen -S pox -d -m ./pox/pox.py cs144.ofhandler cs144.srhandler
echo Your mininet and pox are running inside the follow screen sessions, use 'screen -r mininet' or 'screen -r pox' to obtain the session
screen -ls 
echo Now it's time to run your sr program, or you can try out the ./sr_solution 
echo After running your sr program, try "ping <SERVER1_IP>" from myth machine
