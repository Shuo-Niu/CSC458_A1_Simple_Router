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
### Pull from Github to update the code on VM
Remove the original project folder on VM and pull the latest version from Github.

```cd ~```

```sudo rm -f -r cs144_lab3/```

```git clone https://github.com/Shuo-Niu/CSC458_A1_Simple_Router.git cs144_lab3/```

```cd cs144_lab3/```

```git checkout --track remotes/origin/standalone```

```./config.sh```

```ln -s ../pox```

```cd router/```

```make```

```./sr```
