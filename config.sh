#!/bin/bash

cd pox_module
sudo python setup.py develop

#echo kill stale sessions
#screen -S mininet -X quit
#screen -S pox -X quit
pkill -9 sr_solution
pkill -9 sr
#sudo pkill -9 python

RULE_INSTALLED=`sudo ip rule list | grep cs144 | awk '{print $3}'`
if [ ! -n "$RULE_INSTALLED" ]; then 
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
if [ ! -n "$BR_INSTALLED" ]; then
  echo setup bridge br0
  sudo ovs-vsctl add-br br0
  sudo ovs-vsctl add-port br0 eth1
  sudo ovs-vsctl add-port br0 root-eth0
  sudo ovs-vsctl show
else
  echo bridge is ready
fi

