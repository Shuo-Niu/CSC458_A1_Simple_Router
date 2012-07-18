#!/bin/bash

sudo ip rule add from 10.0.1.0/24 table cs144
sudo ip route add default dev eth1 table cs144
sudo ip route flush cache
sudo ip route list table cs144
sudo ip rule list

screen -S mininet -D -R sudo python mininet.py
screen -S pox -D -R ./pox/pox.py cs144.ofhandler cs144.srhandler

