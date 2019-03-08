# netfilter-spooftcp
A lightweight kernel module/iptables extension for sending spoofed TCP packets  
This is a kernel-space, partial implementation of this [paper](https://www.cs.ucr.edu/~krish/imc17.pdf)

Build
=====
Prerequisites: 
* kernel headers  
* xtables headers

Kernel Module
-------------
```
$ make
# insmod xt_SPOOFTCP.ko
```
iptables Extension
------------------
Copy `libxt_SPOOFTCP.so` to iptables library folder, say `/lib/xtables`.  
Run `iptables -j SPOOFTCP --help` and see if it prints the help message of this module.

Usage
=====
```
ip6tables -t mangle -A POSTROUTING -d 2001:db8::/64 -p tcp --dport 80 --syn -j SPOOFTCP --tcp-flags SYN,ACK
```
This will sent a spoofed SYN,ACK packet **prior to** the matched (original) SYN packet.  
There are mechanisms to prevent the spoofed packets from being tracked by nf_conntrack or being matched by another SPOOFTCP rule.

Known issue
===========
Incompatible with SNAT because the spoofed packets bypass nf_conntrack.  
Use `--masq` parameter as a workaround, but it won't work in case of port changes
