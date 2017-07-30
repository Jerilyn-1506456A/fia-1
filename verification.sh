#!/bin/bash

reset

#Formatting:
#\e[1m  - Bold
#\e[0m  - Default
#\e[31m - Red colour
#\e[32m - Green colour
#
#Putting output to /dev/null:
# /dev/null is a black hole. Whatever goes in there is discarded, lost, spaghettified
# >/dev/null  - put all command output into /dev/null
# &>/dev/null - put all types of output to /dev/null (including errors)
# 2>/dev/null - put all errors into /dev/null

#Check if UID = 0 (root)
if [ "$EUID" -ne 0 ] ; then
	printf "\e[31mPlease run as root! (sudo doesn't work)\n"
	printf "Press any key to exit\e[0m\n"
	#Takes in one keypress then continues the script
	read -n 1 -s
	exit
fi

#Check if the file "/etc/redhat-release" exists
if [ -e /etc/redhat-release ] ; then
	printf "\e[1mRunning Scan for "
	printf "$(cat /etc/redhat-release)"
	printf "\e[0m\n"
else
	printf "\e[31m\e[1mYou are not on a Red Hat System!\n"
	printf "Press any key to exit\e[0m\n"
	read -n 1 -s
	#Send kill signal 9 (terminate process) to Parent Process ID (in this case, terminal)
	kill -9 $PPID
fi

function ctrl_C() {
	printf "\nCTRL+C Pressed. Program halted.\n"
	printf "Press any key to close terminal..."
	read -n 1 -s
	kill -9 $PPID	
}

function ctrl_Z() {
	kill -9 $PPID
}

#Trap SIGINT (Ctrl+C), run function ctrl_C instead
trap ctrl_C INT
trap ctrl_Z 2 20

printf "Go grab a coffee. This is going to take a while to complete.\n"
printf "\e[31mCtrl+C and Ctrl+Z will immediately close the current terminal window.\e[0m\n"
printf "\e[1mChecks on Partitions and Files\e[0m\n"

printf "Checking if /tmp is on a separate partition: "
#[[:space:]] = any amount of space
if [[ $(grep "[[:space:]]/tmp[[:space:]]" /etc/fstab) ]] ; then
	printf "\e[32mPASS\e[0m\n"

	printf "Checking if /tmp has nodev: "
	#Output to /dev/null [>/dev/null] (supresses output so output is cleaner)
	if [[ $(grep "[[:space:]]/tmp[[:space:]]" /etc/fstab | grep "nodev") ]] ; then
		printf "\e[32mPASS\e[0m\n"
	else
		printf "\e[31mFAIL\e[0m\n"
	fi

	printf "Checking if /tmp has nosuid: "
	if [[ $(grep "[[:space:]]/tmp[[:space:]]" /etc/fstab | grep "nosuid") ]] ; then
		printf "\e[32mPASS\e[0m\n"
	else
		printf "\e[31mFAIL\e[0m\n"
	fi

	printf "Checking if /tmp has noexec: "
	if [[ $(grep "[[:space:]]/tmp[[:space:]]" /etc/fstab | grep "noexec") ]] ; then
		printf "\e[32mPASS\e[0m\n"
	else
		printf "\e[31mFAIL\e[0m\n"
	fi
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if /var is on a separate partition: "
if [[ $(grep "[[:space:]]/var[[:space:]]" /etc/fstab) ]] ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

#grep -e is to tell grep that the string contains regular expressions
printf "Checking if /var/tmp is bound to /tmp: "
if [[ $(grep -e "^/tmp[[:space:]]" /etc/fstab | grep "/var/tmp") ]] ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if /var/log is on a separate partition: "
if [[ $(grep "[[:space:]]/var/log[[:space:]]" /etc/fstab) ]] ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if /var/log/audit is on a separate partition: "
if [[ $(grep "[[:space:]]/var/log/audit[[:space:]]" /etc/fstab) ]] ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if /home is on a separate partition: "
if [[ $(grep "[[:space:]]/home[[:space:]]" /etc/fstab) ]] ; then
	printf "\e[32mPASS\e[0m\n"

	printf "Checking if /home has nodev: "
	if [[ $(grep "[[:space:]]/home[[:space:]]" /etc/fstab | grep "nodev") ]]; then
		printf "\e[32mPASS\e[0m\n"
	else
		printf "\e[31mFAIL\e[0m\n"
	fi

else
	printf "\e[31mFAIL\e[0m\n"
fi

#find under '/', ! (not) -permission that is 1000 (sticky bit), but has -permission 0002 (others - write), file type - file. As long as there is a single output (head -n 1), return true.
printf "Checking if sticky bits are enabled: "
if [ -n "$(find / \! -perm /1000 -perm /0002 -type f | head -n 1)" ] ; then
	printf "\e[31mFAIL\e[0m\n"
else
	printf "\e[32mPASS\e[0m\n"
fi

#modprobe -n (dry run - do not execute) -v (verbose) {}. '{}' is a simplified for loop for command line.
printf "\e[1mChecks on System Configurations\e[0m\n"
printf "Checking if legacy file systems are supported on the system: "
if [[ $(modprobe -n -v {cramfs,freexvfs,jffs2,hfs,hfsplus,squashfs,udf}) ]]; then
	printf "\e[31mFAIL\e[0m\n"
else
	printf "\e[32mPASS\e[0m\n"
fi

#subscription-manager version will show if the machine is registered or not
printf "Checking if system is registered to Redhat: "
if [[ $(subscription-manager version | grep "not registered") ]] ; then
	printf "\e[31mFAIL\e[0m\n"
else
	printf "\e[32mPASS\e[0m\n"
fi

#rpm -q: query, -V: verify package, -a: all packages
printf "\e[1mChecks on Packages and Services\e[0m\n"
printf "Checking if any packages are problematic: "
if [[ $(rpm -qVa | awk '$2 != "c" { print $0}' &>/dev/null | head -n 1) ]] ; then
	printf "\e[31mFAIL\e[0m\n"
else
	printf "\e[32mPASS\e[0m\n"
fi

#rpm -q: query package, package name - will show if package is installed
printf "Checking if Telnet is not installed: "
if [[ $(rpm -q telnet-server | grep "not installed") ]] ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mTelnet is installed. Replace with SSH\e[0m\n"
fi

printf "Checking if RSH is not installed: "
if [[ $(rpm -q rsh-server | grep "not installed" >/dev/null && rpm -q rsh | grep "not installed") ]] ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mRSH is installed. Replace with SSH\e[0m\n"
fi

printf "Checking if NIS is not installed: "
if [[ $(rpm -q ypserv | grep "not installed" >/dev/null && rpm -q ypbind | grep "not installed") ]] ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mNIS is installed. Replace with other protocols such as LDAP\e[0m\n"
fi

printf "Checking if TFTP is not installed: "
if [[ $(rpm -q tftp | grep "not installed" >/dev/null && rpm -q tftp-server | grep "not installed") ]] ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mTFTP is installed. Consider replacing with SFTP\e[0m\n"
fi

printf "Checking if xinetd is not installed: "
if [[ $(rpm -q xinetd | grep "not installed") ]] ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mxinetd is installed. Remove if not needed\e[0m\n"
fi

printf "Checking if chargen-dgram is disabled: "
if [[ $(chkconfig --list chargen-dgram 2>/dev/null | grep "chargen-dgram[[:space:]]off") ]] ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if chargen-stream is disabled: "
if [[ $(chkconfig --list chargen-stream 2>/dev/null | grep "chargen-stream[[:space:]]off") ]] ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if daytime-dgram is disabled: "
if [[ $(chkconfig --list daytime-dgram 2>/dev/null | grep "daytime-dgram[[:space:]]off") ]] ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if daytime-stream is disabled: "
if [[ $(chkconfig --list daytime-stream 2>/dev/null | grep "daytime-stream[[:space:]]off") ]] ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if echo-dgram is disabled: "
if [[ $(chkconfig --list echo-dgram 2>/dev/null | grep "echo-dgram[[:space:]]off") ]] ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if echo-stream is disabled: "
if [[ $(chkconfig --list echo-stream 2>/dev/null | grep "echo-stream[[:space:]]off") ]] ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if tcpmux-server is disabled: "
if [[ $(chkconfig --list tcpmux-serer 2>/dev/null | grep "tcpmux-server[[:space:]]off") ]]  ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if umask is of the recommended value: "
if [[ $(grep ^umask /etc/sysconfig/init | grep "027") ]]; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if GUI is the default boot target: "
if [[ $(ls -l /etc/systemd/system/default.target | grep "graphical.target") ]] ; then
	printf "\e[32mGUI is the default boot target. Check if CLI is preferred and X11 can be removed\e[0m\n"
else
	printf "\e[31mGUI is not the default boot target - please check and decide if X11 can be removed\e[0m\n"
fi

printf "Checking if Avahi Daemon is disabled: "
if [[ $(systemctl is-active avahi-daemon | grep "active") ]] || [[ $(systemctl is-enabled avahi-daemon | grep "enabled") ]] ; then
	printf "\e[31mFAIL\e[0m\n"
else
	printf "\e[32mPASS\e[0m\n"
fi

printf "Checking if CUPS has been disabled: "
if [[ $(systemctl is-active cups | grep "active") ]] || [[ $(systemctl is-enabled cups | grep "enabled") ]] ; then
	printf "\e[31mCUPS enabled. Remove if not needed\e[0m\n"
else
	printf "\e[32mCUPS has been disabled\e[0m\n"
fi

printf "Checking if DHCPD is removed: "
if [[ $(yum list dhcpd &>/dev/null | grep "Installed Packages") ]] ; then
	printf "\e[31mDHCPD is installed. Remove if not needed\e[0m\n"
else
	printf "\e[32mDHCPD is not installed\e[0m\n"
fi

printf "Checking NTP configurations: "
if [[ $(yum list ntp &>/dev/null | grep "Installed Packages") ]] ; then
	if [[ $(grep "^restrict default" /etc/ntp.conf) ]] && [[ $(grep "^restrict -6 default" /etc/ntp.conf) ]] && [[ $(grep "^server" /etc/ntp.conf) ]] && [[ $(grep "ntp:ntp" /etc/sysconfig/ntpd) ]] ; then
		printf "\e[32mPASS\e[0m\n"
	else
		printf "\e[31mFAIL\e[0m\n"
	fi
else
	printf "NTP is not installed. Skipping checks..."
fi

printf "Checking if LDAP is removed: "
if [[ $(yum list { openldap-clients, openldap-servers } &>/dev/null | grep "Installed Packages") ]] ; then
	printf "\e[31mLDAP is installed. Remove if not needed\e[0m\n"
else
	printf "\e[32mLDAP is not installed\e[0m\n"
fi

printf "Checking if NFS and RPC are disabled: "
if [[ $(systemctl is-enabled nfs-lock | grep "enabled") ]] && [[ $(systemctl is-enabled nfs-secure | grep "enabled") ]] && [[ $(systemctl is-enabled rpcbind | grep "enabled") ]] && [[ $(systemctl is-enabled nfs-idmap | grep "enabled") ]] && [[ $(systemctl is-enabled nfs-secure-server | grep "enabled") ]] ; then
	printf "\e[31mNFS and RPC are enabled. Disable if not needed\e[0m\n"
else
	printf "\e[32mNFS and RPC are disabled\e[0m\n"
fi

printf "Checking if DNS is disabled: "
if [[ $(systemctl is-enabled named &>/dev/null | grep "enabled") ]] ; then
	printf "\e[31mDNS is enabled. Disable if not needed\e[0m\n"
else
	printf "\e[32mDNS is disabled\e[0m\n"
fi

printf "Checking if FTP is removed: "
if [[ $(yum list ftp &>/dev/null | grep "Available packages") ]] ; then
	printf "\e[32mFTP is not installed\e[0m\n"
else
	printf "\e[31mFTP is installed. Consider switching to VSFTPD\e[0m\n"
fi

printf "Checking if HTTP service is removed: "
if [[ $(yum list httpd &>/dev/null | grep "Available packages") ]] ; then
	printf "\e[32mHTTPD is not installed\e[0m\n"
else
	printf "\e[31mHTTPD is installed\e[0m\n"
fi

printf "Checking if HTTP Proxy Server is removed: "
if [[ $(yum list squid &>/dev/null | grep "Available packages") ]] ; then
	printf "\e[32mHTTP Proxy Server is not installed\e[0m\n"
else
	printf "\e[31mHTTPD Proxy Server installed\e[0m\n"
fi

printf "Checking if SNMP Service is removed: "
if [[ $(yum list net-snmp &>/dev/null | grep "Available packages") ]] ; then
	printf "\e[32mSNMP Service is not installed\e[0m\n"
else
	printf "\e[31mSNMP Service is installed\e[0m\n"
fi

printf "Checking if Mail Transfer Agent is Local-Only: "
if [ "$(netstat -an | grep LIST | grep ':25[[:space:]]' | wc -l)" -lt 3 ] ; then
	if [ "$(netstat -an | grep LIST | grep ':25[[:space:]]' | wc -l)" -eq 2 ] ; then
		if [[ $(netstat -an | grep LIST | grep ':25[[:space:]]' | grep "127.0.0.1:25") ]] && [[ $(netstat -an | grep LIST | grep ':25[[:space:]]' | grep "::1:25") ]] ; then
			printf "\e[32mMTA is Local-Only\e[0m\n"
		else
			printf "\e[31mMTA is not Local-Only\e[0m\n"
		fi
	elif [[ $(netstat -an | grep LIST | grep ':25[[:space:]]' | grep "127.0.0.1") ]] ; then
		printf "\e[32mMTA is Local-Only\e[0m\n"
	else
		printf "\e[31mMTA is not Local-Only\e[0m\n"
	fi
else
	printf "\e[31mMTA is not Local-Only\e[0m\n"
fi

printf "\e[32mScan completed!\n"
printf "Press any key to exit\e[0m\n"
read -n 1 -s
kill -9 $PPID
