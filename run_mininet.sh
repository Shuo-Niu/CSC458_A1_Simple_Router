#!/bin/bash

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
sudo python lab3.py
