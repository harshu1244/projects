At first i opened windows firewall and clicked on inbound rules.
Set new rule ->port->tcp 23->block the connections-> and named it block telnet.And ran test telnet localhost 23 and deleted the block telnet rule
Screenshot attached:-
block telnet.png ->  Shows the block telnet set rules
Inbound rulesjpg.jpg -> Shows the rule is applied in the inbound rules
test.jpg -> Show the result of test (which is failed because we have blocked the connections)


Linux terminal commands:-

//Here i have enabled the ufw  
(root㉿maxop)-[/home/max]
└─# ufw enable                       
Firewall is active and enabled on system startup

//here saw the status of the wfw which was active                                                                                
┌──(root㉿maxop)-[/home/max]
└─# ufw status verbose               
Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip

//here i denied the 23/tcp connection                                                                                
┌──(root㉿maxop)-[/home/max]
└─#  ufw deny 23/tcp 
Rule added
Rule added (v6)
 //here i allowed the 22/tcp connection                                                                                
┌──(root㉿maxop)-[/home/max]
└─# ufw allow 22/tcp
Rule added
Rule added (v6)

// here i ran test to verify the set rules                                                                                
┌──(root㉿maxop)-[/home/max]
└─# telnet localhost 23
Trying ::1...
Connection failed: Connection refused
Trying 127.0.0.1...
telnet: Unable to connect to remote host: Connection refused
                                                                                
┌──(root㉿maxop)-[/home/max]
└─# ssh localhost
ssh: connect to host localhost port 22: Connection Succeed

//here i ran reset command to reset the utw

─(root㉿maxop)-[/home/max]
└─# ufw reset       
Resetting all rules to installed defaults. Proceed with operation (y|n)? y
Backing up 'user.rules' to '/etc/ufw/user.rules.20250627_164829'
Backing up 'before.rules' to '/etc/ufw/before.rules.20250627_164829'
Backing up 'after.rules' to '/etc/ufw/after.rules.20250627_164829'
Backing up 'user6.rules' to '/etc/ufw/user6.rules.20250627_164829'
Backing up 'before6.rules' to '/etc/ufw/before6.rules.20250627_164829'
Backing up 'after6.rules' to '/etc/ufw/after6.rules.20250627_164829'

