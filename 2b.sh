#!/bin/bash
printf "Checking if grub.cfg belongs to root: "
if stat -L -c "owner=%U group=%G" /boot/grub2/grub.cfg | grep "owner=root group=root" >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if grub.cfg file is set to read and write for root only: "
if stat -L -c "%a" /boot/grub2/grub.cfg | grep "%00" >/dev/null ; then
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

printf "Checking if rsyslog sends logs to remote log host: "
if grep "^*.*[^|][^|]*@" /etc/rsyslog.conf *.* >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if rsyslog is listening for remote messages: \n"
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

printf "Checking if system date/time are captured when modified: \n"
egrep 'adjtimex|settimeofday|clock_settime' /etc/audit/audit.rules

printf "Checking if modifying user/group information are recorded: \n"
egrep '\/etc\/group|\/etc\/passwd|\/etc\/gshadow|\/etc\/shadow|\/etc\/security\/opasswd' /etc/audit/audit.rules

printf "Checking if modification of the system's environment are recorded: /n"
egrep 'sethostname | setdomainname |\/etc\/issue|\/etc\/hosts|\/etc\/sysconfig\/network' /etc/audit/audit.rules

printf "Checking if modification of system's mandatory access controls are recorded: \n"
grep \/etc\/selinux /etc/audit/audit.rules

printf "Checking if login and logout events are recorded: \n"
grep logins /etc/audit/audit.rules

printf "Checking if session initiation information is collected: \n"
egrep 'wtmp|btmp|utmp' /etc/audit/audit.rules

printf "Checking if permission modifications are being recorded: \n"
grep perm_mod /etc/audit/audit.rules

printf "Checking if there are unsuccessful attempts: \n"
grep access /etc/audit/audit.rules

printf "Checking if filesystem mounts are recorded: \n"
grep mounts /etc/audit/audit.rules

printf "Checking if file deletion events by user are recorded: \n"
grep delete /etc/audit/audit.rules

printf "Checking if changes to /etc/sudoers are recorded: \n"
grep scope /etc/audit/audit.rules

printf "Checking if administrator activity is recorded: \n"
grep actions /etc/audit/audit.rules

printf "Checking if kernel module loading and unloading is recorded: \n"
grep modules /etc/audit/audit.rules

printf "Checking if the audit configuration is immutable: \n"
grep "^-e 2" /etc/audit/audit.rules

printf "Checking if the appropriate system logs are rotated: \n"
grep 'var' /etc/logrotate.d/syslog


