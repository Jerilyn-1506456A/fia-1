#!/bin/bash
printf "Checking if grub.cfg belongs to root: "
if stat -L -c "owner=%U group=%G" /boot/grub2/grub.cfg | grep "owner=root group=root" >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if grub.cfg file is set to read and write for root only: "
if stat -L -c "%a" /boot/grub2/grub.cfg | grep "00" >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if boot loader password is set: \n"
grep "set superusers" /boot/grub2/grub.cfg
grep "password" /boot/grub2/grub.cfg

printf "Checking if core dumps are restricted: \n"
grep "hard" /etc/security/limits.conf

printf "fs.suid_dumpable == 0? "
if sysctl fs.suid_dumpable >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if virtual memory is randomized: "
if sysctl kernel.randomize_va_space >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[32mFAIL\e[0m\n"
fi

printf "Checking if rsyslog package is installed: "
if rpm -q rsyslog | grep "rsyslog" >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if rsyslog is enabled: "
if systemctl is-enabled rsyslog | grep "enabled" >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if appropriate logging is set: "
if (cat /etc/rsyslog.conf | grep "auth,user.* /var/log/messages" >/dev/null) && (cat /etc/rsyslog.conf | grep "kern.* /var/log/kern.log" >/dev/null) && (cat /etc/rsyslog.conf | grep "daemon.* /var/log/daemon.log" >/dev/null) && (cat /etc/rsyslog.conf | grep "syslog.* /var/log/daemon.log" >/dev/null) && (cat /etc/rsyslog.conf | grep "lpr,news,uucp,local0,local1,local2,local3,local4,local5,local6.* /var/log/unused.log") ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if /var/log/messages is root root: "
if ls -l /var/log/messages | grep "root root" >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if /var/log/messages is 600: "
if stat -c "%a %n"  /var/log/messages | grep "600" >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if /var/log/messages is 640: "
if stat -c "%a %n"  /var/log/messages | grep "640" >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if /var/log/secure is root root: "
if ls -l /var/log/secure | grep "root root" >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if /var/log/secure is 600: "
if stat -c "%a %n"  /var/log/secure | grep "600" >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if /var/log/secure is 640: "
if stat -c "%a %n"  /var/log/secure | grep "640" >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if /var/log/maillog is root root: "
if ls -l /var/log/maillog | grep "root root" >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if /var/log/maillog is 600: "
if stat -c "%a %n"  /var/log/maillog | grep "600" >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if /var/log/maillog is 0640: "
if stat -c "%a %n"  /var/log/maillog | grep "640" >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if /var/log/cron is root root: "
if ls -l /var/log/cron | grep "root root" >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if /var/log/cron is 600: "
if stat -c "%a %n"  /var/log/cron | grep "600" >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if /var/log/cron is 640: "
if stat -c "%a %n"  /var/log/cron | grep "640" >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if /var/log/spooler is root root: "
if ls -l /var/log/spooler | grep "root root" >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if /var/log/spooler is 600: "
if stat -c "%a %n"  /var/log/spooler | grep "600" >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if /var/log/spooler is 640: "
if stat -c "%a %n"  /var/log/spooler | grep "640" >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if /var/log/boot.log is root root: "
if ls -l /var/log/boot.log | grep "root root" >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if /var/log/boot.log is 600: "
if stat -c "%a %n"  /var/log/boot.log | grep "600" >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if /var/log/boot.log is 640: "
if stat -c "%a %n"  /var/log/boot.log | grep "640" >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi


printf "Checking if rsyslog sends logs to remote log host: "
if grep "^*.*[^|][^|]*@" /etc/rsyslog.conf *.* >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if rsyslog is listening for remote messages: "
printf "ModLoad imtcp.so: "
if grep '$ModLoad imtcp.so' /etc/rsyslog.conf >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "InputTCPServerRun 514: "
if grep '$InputTCPServerRun' /etc/rsyslog.conf >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Maximum size of the audit log files (MB): \n"
grep max_log_file /etc/audit/auditd.conf

printf "Checking if audit logs are retained: "
if grep max_log_file_action /etc/audit/auditd.conf | grep "keep_logs" > /dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if space_left_action = email: "
if grep space_left_action /etc/audit/auditd.conf | grep "email" >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking the action_mail_acct = root: "
if grep action_mail_acct /etc/audit/auditd.conf | grep "root" >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if admin_space_left_action = halt: "
if grep admin_space_left_action /etc/audit/auditd.conf | grep "halt" >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if auditd is enabled: "
if systemctl is-enabled auditd | grep "enabled" >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if /boot/grub2/grub.cfg is configured to log: "
if grep "[[:space:]]linux" /boot/grub2/grub.cfg | grep "audit=1" >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if system date/time are captured when modified: "
if (egrep 'adjtimex|settimeofday|clock_settime' /etc/audit/audit.rules | grep "a always, exit -F arch=b64 -S adjtimex -S settimeofday -k time-change" >/dev/null) && (egrep 'adjtimex|settimeofday|clock_settime' /etc/audit/audit.rules | grep "a always, exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change" >/dev/null) && (egrep 'adjtimex|settimeofday|clock_settime' /etc/audit/audit.rules | grep "a always, exit -F arch=b64 -S clock_settime -k time-change" >/dev/null) && (egrep 'adjtimex|settimeofday|clock_settime' /etc/audit/audit.rules | grep "a always, exit -F arch=b32 -S clock_settime -k time-change" >/dev/null) ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if modifying user/group information are recorded: "
if (egrep '\/etc\/group|\/etc\/passwd|\/etc\/gshadow|\/etc\/shadow|\/etc\/security\/opasswd' /etc/audit/audit.rules | grep "w /etc/group -p wa -k identity" >/dev/null) && (egrep '\/etc\/group|\/etc\/passwd|\/etc\/gshadow|\/etc\/shadow|\/etc\/security\/opasswd' /etc/audit/audit.rules | grep "w /etc/passwd -p wa -k identity" >/dev/null) && (egrep '\/etc\/group|\/etc\/passwd|\/etc\/gshadow|\/etc\/shadow|\/etc\/security\/opasswd' /etc/audit/audit.rules | grep "w /etc/gshadow -p wa -k identity" >/dev/null) && (egrep '\/etc\/group|\/etc\/passwd|\/etc\/gshadow|\/etc\/shadow|\/etc\/security\/opasswd' /etc/audit/audit.rules | grep "w /etc/shadow -p wa -k identity" >/dev/null) && (egrep '\/etc\/group|\/etc\/passwd|\/etc\/gshadow|\/etc\/shadow|\/etc\/security\/opasswd' /etc/audit/audit.rules | grep "w /etc/security/opasswd -p wa -k identity" >/dev/null) ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if modification of the system's environment are recorded: "
if (egrep 'sethostname | setdomainname |\/etc\/issue|\/etc\/hosts|\/etc\/sysconfig\/network' /etc/audit/audit.rules | grep "a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale" >/dev/null) && (egrep 'sethostname | setdomainname |\/etc\/issue|\/etc\/hosts|\/etc\/sysconfig\/network' /etc/audit/audit.rules | grep "a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale" >/dev/null) && (egrep 'sethostname | setdomainname |\/etc\/issue|\/etc\/hosts|\/etc\/sysconfig\/network' /etc/audit/audit.rules | grep "w /etc/issue -p wa -k system-locale" >/dev/null) && (egrep 'sethostname | setdomainname |\/etc\/issue|\/etc\/hosts|\/etc\/sysconfig\/network' /etc/audit/audit.rules | grep "w /etc/issue.net -p wa -k system-locale" >/dev/null) && (egrep 'sethostname | setdomainname |\/etc\/issue|\/etc\/hosts|\/etc\/sysconfig\/network' /etc/audit/audit.rules | grep "w /etc/hosts -p wa -k system-locale" >/dev/null) && (egrep 'sethostname | setdomainname |\/etc\/issue|\/etc\/hosts|\/etc\/sysconfig\/network' /etc/audit/audit.rules | grep "w /etc/sysconfig/network -p wa -k system-locale" >/dev/null) ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if modification of system's mandatory access controls are recorded: "
if grep \/etc\/selinux /etc/audit/audit.rules | grep "w /etc/selinux/ -p wa -k MAC-policy" >/dev/null; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if login and logout events are recorded: "
if (grep logins /etc/audit/audit.rules | grep "w /var/log/faillog -p wa -k logins" >/dev/null) && (grep logins /etc/audit/audit.rules | grep "w /var/log/lastlog -p wa -k logins" >/dev/null) && (grep logins /etc/audit/audit.rules | grep "w /var/log/tallylog -p wa -k logins" >/dev/null); then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if session initiation information is collected: "
if (egrep 'wtmp|btmp|utmp' /etc/audit/audit.rules | grep "w /var/run/utmp -p wa -k session" >/dev/null) && (egrep 'wtmp|btmp|utmp' /etc/audit/audit.rules | grep "w /var/log/wtmp -p wa -k session" >/dev/null) && (egrep 'wtmp|btmp|utmp' /etc/audit/audit.rules | grep "w /var/log/btmp -p wa -k session" >/dev/null) ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if permission modifications are being recorded: "
if (grep perm_mod /etc/audit/audit.rules | grep "a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod" >/dev/null) && (grep perm_mod /etc/audit/audit.rules | grep "a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod" >/dev/null) && (grep perm_mod /etc/audit/audit.rules | grep "a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" >/dev/null) && (grep perm_mod /etc/audit/audit.rules | grep "a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" >/dev/null) && (grep perm_mod /etc/audit/audit.rules | grep "a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >/dev/null) && (grep perm_mod /etc/audit/audit.rules | grep "a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >/dev/null) ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if there are unsuccessful attempts: "
if (grep access /etc/audit/audit.rules | grep "a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >/dev/null) && (grep access /etc/audit/audit.rules | grep "a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >/dev/null) && (grep access /etc/audit/audit.rules | grep "a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >/dev/null) && (grep access /etc/audit/audit.rules | grep "a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >/dev/null) ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

#6.2.1.14
printf "Checking if privileged commands are in audit: "
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print "-a always,exit-F path=" $1 " -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged" }' > /tmp/1.log

checkpriviledge=`cat /tmp/1.log`
cat /etc/audit/audit.rules | grep -- "$checkpriviledge" > /tmp/2.log

checkpriviledgenotinfile=`grep -F -x -v -f /tmp/2.log /tmp/1.log`

if [ -n "$checkpriviledgenotinfile" ]
then
	printf "\e[31mFAIL\e[0m\n"
else
	printf "\e[32mPASS\e[0m\n"
fi

rm /tmp/1.log
rm /tmp/2.log

printf "Checking if filesystem mounts are recorded: "
if (grep mounts /etc/audit/audit.rules | grep "a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >/dev/null) && (grep mounts /etc/audit/audit.rules | grep "a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >/dev/null) ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if file deletion events by user are recorded: "
if (grep delete /etc/audit/audit.rules | grep "a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >/dev/null) && (grep delete /etc/audit/audit.rules | grep "a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >/dev/null) ; then
	printf "\e[32mPASS\e[0m\n"	
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if changes to /etc/sudoers are recorded: "
if grep scope /etc/audit/audit.rules | grep "w /etc/sudoers -p wa -k scope" >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if administrator activity is recorded: "
if grep actions /etc/audit/audit.rules | grep "w /var/log/sudo.log -p wa -k actions" >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if kernel module loading and unloading is recorded: "
if (grep modules /etc/audit/audit.rules |grep "w /sbin/insmod -p x -k modules" >/dev/null) && (grep modules /etc/audit/audit.rules |grep "w /sbin/rmmod -p x -k modules" >/dev/null) && (grep modules /etc/audit/audit.rules |grep "w /sbin/modprobe -p x -k modules" >/dev/null) && (grep modules /etc/audit/audit.rules |grep "w /sbin/insmod -p x -k modules" >/dev/null) && (grep modules /etc/audit/audit.rules |grep "a always,exit -F arch=b64 -S init_module -S delete_module -k modules" >/dev/null) ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if the audit configuration is immutable: "
if grep "^-e 2" /etc/audit/audit.rules >/dev/null; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if the appropriate system logs are rotated: "
if (grep 'var' /etc/logrotate.d/syslog |grep "/var/log/messages" >/dev/null) && (grep 'var' /etc/logrotate.d/syslog |grep "/var/log/secure" >/dev/null) && (grep 'var' /etc/logrotate.d/syslog |grep "/var/log/maillog" >/dev/null) && (grep 'var' /etc/logrotate.d/syslog |grep "/var/log/spooler" >/dev/null) && (grep 'var' /etc/logrotate.d/syslog |grep "/var/log/boot.log" >/dev/null) && (grep 'var' /etc/logrotate.d/syslog |grep "/var/log/cron" >/dev/null) ; then
	printf "\e[32mPASS\e[0m\n" 
else
	printf "\e[31mFAIL\e[0m\n"
fi
