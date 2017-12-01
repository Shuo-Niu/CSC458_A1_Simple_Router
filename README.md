# CSC458_A1_Simple_Router

### Launch on CDF machines
#### 1. Start VM
```cvm csc458``` (login: "mininet", pswd: \<the password you set>)
#### 2. Run POX controller
```ssh -p 8022 mininet@localhost``` (open a new terminal and ssh to the VM from the same host)

```cd ~/cs144_lab3/```

```./run_pox.sh```
#### 3. Start Mininet emulation
```ssh -p 8022 mininet@localhost``` (open a new terminal and ssh to the VM from the same host)

```cd ~/cs144_lab3/```

```./run_mininet.sh```
#### 4. Build and run the router
```ssh -p 8022 mininet@localhost``` (open a new terminal and ssh to the VM from the same host)

```cd ~/cs144_lab3/router/```

```make```

```./sr```

---
### Clone from Github to update the code on VM
Remove the original project folder on VM and clone the latest version from Github.

```cd ~```

```sudo rm -rf cs144_lab3/```

**Copying my code for your assignment is an academic offence. You have been warned.**

```git clone https://github.com/Shuo-Niu/CSC458_A1_Simple_Router.git cs144_lab3/```

```cd cs144_lab3/```

```git checkout --track remotes/origin/standalone```

```./config.sh```

```ln -s ../pox```

```cd router/```

```make```

```./sr```

---
### Auto-marker test description
- **ICMP-Shows-ARP-1:** verifies that when the router receives an ICMP echo request, it initiates an ARP request, instead of simply swapping source IP and destination IP in the reply.

- **ARP-Request-[1-2]:** sends an ARP request to one of the router's interfaces and waits for a matching ARP reply.

- **ARP-Caching-1:** sends two successive -identical- ICMP echo requests to one of the router's interfaces, and makes sure that only the first one triggers an ARP request. Notes: 1) We make sure that this is the first time that the router has to send an IP packet to this address, thus making an ARP request necessary. 2) The second ICMP echo request is only sent after the first ICMP echo reply has been sent by the router, so there is no race condition with the ARP request / reply.

- **ICMP-Request-Forwarding-[1-2]:** sends an ICMP echo request to the router. This request is not addressed to the router, which needs to forward it (the route is known). We check that the forwarded packet is identical to the original one, apart from the modified IP header.

- **ICMP-Reply-Forwarding-1:** same as above but the packet forwarded is now an ICMP echo reply instead of an ICMP echo request.

- **ICMP-Reply-[1-2]:** checks that the router correctly replies to ICMP echo requests addressed to one of its interfaces. This is different from earlier tests (e.g. ICMP-Shows-ARP-1), which was only interested in the ARP packets involved.

- **ICMP-TTL-Decrease-1:** sends an IP packet to the router (in our case an ICMP echo request) for forwarding and makes sure that the router correctly decrements the TTL field.

- **ICMP-Reply-TTL1-1:** sends an ICMP echo request addressed to one of the router's interfaces with a TTL of 1, and verifies that the router is generating a reply.

- **TCP-Forwarding-1:** same as ICMP-Request-Forwarding and ICMP-Reply-Forwarding, but this time with a TCP packet instead of an ICMP packet. In other words, checks that the router correctly forwards TCP traffic.

- **UDP-Forwarding-1:** same as above but this time we send a UDP packet instead of a TCP one.

- **Port-Unreachable-[1-2]:** sends a TCP packet addressed to one of the router's interfaces, expects an ICMP port unreachable message.
Port-Unreachable-3: same as above but with a UDP packet.

- **Net-Unreachable-1:** sends an ICMP packet to the router for forwarding, but makes sure that the router has no entry for the IP address. Expects an ICMP net unreachable message.

- **Net-Unreachable-2:** same as above but with a TCP packet instead of an ICMP one.

- **Host-Unreachable-1:** sends an ICMP packet to the router for forwarding. The router has a matching entry for the destination IP in its routing table, but the next hop is not replying to ARP requests. Expects an ICMP host unreachable message after roughly 5 seconds (5 timed out ARP requests).

- **Time-Exceed-1:** sends an ICMP packet to the router for forwarding, but with a TTL of 1. The router should drop the packet and generate an ICMP Time Exceed message.

- **Time-Exceed-2:** same as above but with a UDP packet instead of an ICMP one.
