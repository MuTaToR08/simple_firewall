## Simple firewall

this project is simpel firewall for try filter package with use netfilter(iptables) hooks with Windows control as Windows Default firewall.

Requriments:
  *) kernel version > 4.13.0
  *) zenity

next steps:
1) sudo apt install zenity
2) make
3) sudo insmod simple_module.ko
4) sudo ./sfw_daemon
