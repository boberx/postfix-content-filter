# postfix-content-filter
# Description
It is an simple content filter for Postfix MTA, implementing mail message interfacing with external content filters (SpamAssassin and ClamAV) to provide protection against spam, viruses and other malware
  
(very old project, tested with Debian 6/7 on amd64 and postfix 2.7/2.11)  

# How to use

master.cf  
  
```
mailparser		unix	-	n	n	-	20	pipe flags=Rhuq user=nobody argv=/usr/sbin/postfix-content-filter -q ${queue_id} -a ${client_address} -s $(sasl_username) -f ${sender} ${recipient}
```
