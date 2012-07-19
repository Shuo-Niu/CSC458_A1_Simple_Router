#!/bin/bash
screen -S mininet -X quit
screen -S pox -X quit
pkill -9 sr_solution
pkill -9 sr
