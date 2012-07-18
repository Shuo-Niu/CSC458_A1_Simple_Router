#!/bin/bash
screen -S mininet -D -R sudo python mininet.py
screen -S pox -D -R ./pox/pox.py cs144.ofhandler cs144.srhandler
