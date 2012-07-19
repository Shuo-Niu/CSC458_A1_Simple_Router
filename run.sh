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

screen -S mininet -D -R sudo python lab3.py
screen -S pox -D -R ./pox/pox.py cs144.ofhandler cs144.srhandler

