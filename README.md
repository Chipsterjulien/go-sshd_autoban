Sshd_autoban
============

I wrote this script for fun and learn golang. This script look ssh log
("journalctl", syslog-ng or rsyslog). It connect with a local socket.
This script can ban agressors with iptables, shorewall or hosts.deny
(actually) and it efficient with fast and slow brute force attack.


Depends
=======

go


Install
=======

To install it, make sure you have golang 1.3 or greater installed. Then run
this command from the command prompt:

1. go build sshd_autoban.go and move binary file to /usr/bin

2. Create /etc/sshd_autoban directory

3. Copy sshd_autoban_example.json to /etc/sshd_autoban/sshd_autoban.json

4. You should edit it !

5. If you use systemd, copy sshd_autoban.service to /usr/lib/systemd/system/

6. Create /var/log/sshd_autoban directory

7. Fixing some right :
		chmod 644 "/etc/sshd_autoban/sshd_autoban.json"
		chmod 644 "/var/log/sshd_autoban"
		chmod 755 "/usr/bin/sshd_autoban"
		
Warning
=======

You should use a non-root user to run this program
