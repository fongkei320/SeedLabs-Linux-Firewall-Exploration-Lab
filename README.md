

# Introduction

This project provides the insights on how firewalls work from seedlab.
Ubuntu 16.04 LTS is the target operating system for this project. The
lab includes four task which will be covered in this report. A
conclusion including the summary of this project and some learning
experiences also introduced.

# Environments

- The project includes a VM setup for the UNIX environment, Ubuntu 16.04
LTS desktop version installation media can be downloaded at
<https://releases.ubuntu.com/16.04/> 
- Vmware VM workstation is used as a
virtual platform.

The setup of the VMs is shown as follows.

Machine A

<img src="./media/image1.png" style="width:4.98062in;height:5.05909in"
alt="Machine A" />

Machine B

<img src="./media/image2.png" style="width:4.94586in;height:5.02378in"
alt="Machine B" />



The network configuration will be as follows

|                                       | Machine A     | Machine B     |
|---------------------------------------|---------------|---------------|
| VM Network adapter Network connection | NAT           | NAT           |
| VM Network subnet                     | 172.16.0.0/24 | 172.16.0.0/24 |
| Network adapter in OS                 | ens33         | ens33         |
| Assigned IP by DHCP                   | no            | no            |
| IP Address                            | 172.16.0.5    | 172.16.0.4    |
| Subnet mask                           | 255.255.255.0 | 255.255.255.0 |
| Default Gateway                       | 172.16.0.254  | 172.16.0.254  |

# Project Task

## Task 1: Using Firewall

This is the task the linux firewall-iptables operation is required. The
following is the screenshot for the bash shell operation

### Preparation

The ensure the firewall iptables is in install and in active, the
following command is used to ensure the iptables is installed and
operate without any policy.

Use the following commnad to check the application is installed and
is in active status.
> sudo service ufw status 

<img src="./media/image3.png" style="width:7.00833in;height:5.44514in"
alt="Screenshot for sudo service ufw status" />



Then run the following command to flush the iptables policy table and
list the policy to ensure the policy table is empty

> $sudo iptables -F</p>
> $sudo iptables -L</p></th>

<img src="./media/image4.png" style="width:7.00833in;height:5.44514in"
alt="Screenshot for the command and its output" />



### Lab Task

#### To Prevent A from doing telnet to Machine B

##### Implementation

The following command is used to implement the firewall for the task
objective

> sudo iptables -A OUTPUT -p tcp --dport 23 -d 172.16.0.4 -j DROP

<img src="./media/image5.png" style="width:4.20142in;height:3.2643in"
alt="Screenshot of implementation" />



##### Verification

The verification is start the telnet from machine A to Machine B, the
following command is used

> telnet 172.16.0.4

The command result a connection timeout since the tcp packet from
machine A to machine B is dropped by the iptables firewall at machine A

<img src="./media/image6.png" style="width:4.70269in;height:3.65376in"
alt="Screenshot for vertification" />



#### Prevent B from doing telnet to Machine A.

##### Implementation

The following command is used to implement the firewall for the task
objective

> sudo iptables -A INPUT -p tcp --dport 23 -s 172.16.0.4 -j REJECT

<img src="./media/image7.png" style="width:4.97523in;height:3.86551in"
alt="Screenshot of implementation" />

#### Prevent A from visiting an external web site. 

##### Implementation

The following command is used to implement the firewall for the task
objective, we use [www.nyit.edu](http://www.nyit.edu) as target website
for testing

> sudo iptables -A OUTPUT -d www.nyit.edu -j REJECT 

<img src="./media/image9.png" style="width:4.75321in;height:3.69301in"
alt="Screenshot of implementation" />



## Task 2: Implementing a Simple Firewall

### Preparation

In this task, implementation of simple firewall with packeting filtering
features. In this task, some programming and kernel module installation
is required. Before the implementation, to remove the iptables policy is
required in order to eliminate the effect from iptables. The following
is the command to do so.

<img src="./media/image4.png" style="width:7.00833in;height:5.44514in"
alt="Screenshot for the preparation" />

### Implemetation

The following is the sourcecode and the procedure to compile, install
and verification. The simple firewall contains 5 rules.

#### Firewall Policy design

The following is the policy in high level, the policy design default
allow, when only filtered the listed items.

| Policy \# | Direction | Protocol | Src IP     | Src Port | Dest IP       | Dest Port | Description                                                                              |
|-----------|-----------|----------|------------|----------|---------------|-----------|------------------------------------------------------------------------------------------|
| 1         | Outbound  | TCP      | ANY        | ANY      | 172.16.0.4    | 23        | Prohibit the telnet traffic from Machine A to Machine B                                  |
| 2         | Inbound   | TCP      | 172.16.0.4 | ANY      | 172.16.0.5    | 23        | Prohibit the telnet traffic from Machine B to Machine A                                  |
| 3         | Outbound  | TCP      | ANY        | ANY      | 61.35.176.173 | 80        | Prohibit the HTTP traffic from Machine A to [www.nyit.edu](http://www.nyit.edu) website  |
| 4         | Outbound  | TCP      | ANY        | ANY      | 61.35.176.173 | 443       | Prohibit the HTTPS traffic from Machine A to [www.nyit.edu](http://www.nyit.edu) website |
| 5         | Outbound  | UDP      | ANY        | ANY      | 172.16.0.4    | ANY       | Prohibit the UDP traffic from Machine A to Machine B                                     |

#### Sourcecode listing

The following is the sourcecode of the simple firewall(locate at simplefirewall folder ), there are 3
files for the whole application setup, the following is the list and its
content.

| \#  | File Name        | Description                                                                                                                                             |
|-----|------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1   | Makefile         | The make configuration file for the kernel module build, additional mode ‘debug’ is added in order to generate more log for debugging                   |
| 2   | simplefirewall.h | The C header file for the simple firewall application, which include the required header file and structure for the policy table                        |
| 3   | simplefirewall.c | The C source code which contains the application logic and the the system calls for the packet filtering operation. The policy table build is included. |

#### Command for kernel module nuild and implementation

Command to Build the application
> make all

<img src="./media/image23.png" style="width:3.63445in;height:2.66966in"
alt="Text Description automatically generated" />

Debug build
> make debug

<img src="./media/image24.png" style="width:3.56667in;height:2.61987in"
alt="Text Description automatically generated" />

To Install the kernel module, the insmod command can do the work and the
lsmod command can list the installed kernel module

To install the module
> sudo insmod simplefirewall.ko
To verify the module is installed
> sudo lsmod | grep simple

<img src="./media/image25.png" style="width:3.57571in;height:2.62651in"
alt="Text Description automatically generated" />

To remove the kernel module, use the rmmod command
> sudo rmmod simplefirewall.ko

<img src="./media/image26.png" style="width:3.56696in;height:2.62009in"
alt="Text Description automatically generated" />

#### troubleshoot the kernel module

To troubleshoot the kernel module, this printk function in the
application will print out the message to the kernel log. Use dmesg will
able to capture the log message. The switch -wH will keep the console
continuing to capture the kernel log.

> dmesg -wH

<img src="./media/image27.png" style="width:4.01143in;height:2.94656in"
alt="Kernel log screenshot" />



<img src="./media/image28.png" style="width:4.00757in;height:2.94373in"
alt="Kernel log for module installation" />



<img src="./media/image29.png" style="width:4.00941in;height:2.94508in"
alt="Kernel log for module removal" />

## Task 3: Evading Egress Filtering

### Preparation

In this task, evading egress filtering by tunneling is the primary
objectives. In this task, some knowledge of SSH tunneling and iptables
is required. Before the implementation, to prepare the iptables policy
is required in order to ensure the proper firwall . The following is the
command to do so.

#### Remove the simplefirewall module

<img src="./media/image41.png" style="width:7.00833in;height:4.42569in"
alt="Remove the simplefirewall module" />

#### Ensure iptables is active and no pervious rules

<img src="./media/image42.png" style="width:7.00833in;height:4.42569in"
alt="Ensure iptables is active and no pervious rules" />

#### Block all the outgoing traffic to external telnet servers
At Machine A
> sudo iptables -A OUTPUT -p tcp --dport 23 -j REJECT

<img src="./media/image43.png" style="width:7.00833in;height:4.42569in"
alt="Screenshot of the command" />

#### Block all the outgoing traffic to www.facebook.com

<img src="./media/image44.png" style="width:7.00833in;height:4.42569in"
alt="Block all the outgoing traffic to www.facebook.com" />

#### Vertification of telnet traffic is blocked

<img src="./media/image45.png" style="width:7.00833in;height:4.42569in"
alt="Vertification of telnet traffic is blocked" />

#### Vertification of outgoing traffic to www.facebook.com is blocked

Vertification of outgoing traffic to www.facebook.com is blocked

<img src="./media/image46.png" style="width:7.00833in;height:4.42569in"
alt="wget screenshot" />



<img src="./media/image47.png" style="width:7.00833in;height:5.60694in"
alt="Browser Screenshot" />



### Implemetation

To implement the tunnel, we need to do the following to setup the tunnel
in between machine A and machine B. the following is the command to do
so.

#### Task 3a – the SSH tunnel for telnet service

<img src="./media/image48.png" style="width:6.31455in;height:3.98757in"
alt="Text Description automatically generated" />

#### Task 3b – the SSH tunnel for facebook website

<img src="./media/image49.png" style="width:5.74337in;height:3.62688in"
alt="Text Description automatically generated" />

Configuration for proxy at machine A
<img src="./media/image50.png" style="width:6.20968in;height:4.96799in"
alt="Configuration for proxy at machine A" />



## Task 4: Evading Ingress Filtering

### Preparation

In this task, evading ingress filtering by reserve tunneling is the
primary objectives. In this task, some knowledge of SSH tunneling and
iptables is required. Before the implementation, to prepare the iptables
policy is required in order to ensure the proper firwall . The following
is the command to do so.

#### Remove the simplefirewall module

<img src="./media/image41.png" style="width:7.00833in;height:4.42569in"
alt="Text Description automatically generated" />

#### Ensure iptables is active and no pervious rules

<img src="./media/image42.png" style="width:7.00833in;height:4.42569in"
alt="Text Description automatically generated" />

#### Block Machine B from accessing its port 80 (web server) and 22 (SSH server)

<img src="./media/image55.png" style="width:7.00833in;height:6.63472in"
alt="Text Description automatically generated" />

### Implemetation

To implement the reserve tunnel, we need to do the following to setup
the tunnel in between machine A and machine B. the following is the
command to do so.

#### For reserve tunnel for SSH service from machine B to machine A

<img src="./media/image59.png" style="width:7.00833in;height:6.46458in"
alt="Text Description automatically generated" />

#### Reserve tunnel setup for HTTP service from machine B to machine A

<img src="./media/image60.png" style="width:7.00833in;height:6.63472in"
alt="Text Description automatically generated" />

### Verification

- Task 4a - SSH test

<img src="./media/image61.png" style="width:7.00833in;height:6.46458in"
alt="Text Description automatically generated" />

<img src="./media/image62.png" style="width:7.00833in;height:6.46458in"
alt="Text Description automatically generated" />

Screenshot verification for tunnel is active(Machine B)

- Task 4b – visiting HTTP service at machine A

wget screenshot

<img src="./media/image63.png" style="width:7.00833in;height:6.46458in"
alt="wget screenshot" />


Firefox screenshot

<img src="./media/image64.png" style="width:7.00833in;height:5.60694in"
alt="Firefox screenshot" />

Screenshot verification for tunnel is active

<img src="./media/image65.png" style="width:7.00833in;height:4.42569in"
alt="Screenshot verification for tunnel is active" />

# Reference

1.  Du, W. (n.d.). *Linux firewall exploration lab*. SEED Project.
    <https://seedsecuritylabs.org/Labs_16.04/Networking/Firewall/>

2.  The kernel development community. (n.d.). *Networking — The Linux
    kernel documentation*.
    <https://linux-kernel-labs.github.io/refs/heads/master/labs/networking.html>
