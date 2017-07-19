#!/bin/bash

reset

if [ "$EUID" -ne 0 ] ; then
	printf "\e[31mPlease run as root!\n"
	printf "Press any key to exit\e[0m\n"
	read -n 1 -s
	exit
fi

function ctrl_C() {
	kill -9 $PPID	
}

function ctrl_Z() {
	kill -9 $PPID
}

trap ctrl_C INT
trap ctrl_Z INT

printf "\e[1mRunning Scan for Red Hat Enterprise Linux 7.3 System Configurations\n"
printf "Go grab a coffee. This is going to take a while to complete.\n"
printf "\e[31mCtrl+C and Ctrl+Z will immediately close the current terminal window.\e[0m\n"
printf "\e[1mChecks on Partitions and Files\e[0m\n"
printf "Checking if /tmp is on a separate partition: "
if grep "[[:space:]]/tmp[[:space:]]" /etc/fstab ; then
	printf "\e[32mPASS\e[0m\n"
	printf "Checking if /tmp has nodev: "
	if grep "[[:space:]]/tmp[[:space:]]" /etc/fstab | grep "nodev" ; then
		printf "\e[32mPASS\e[0m\n"
	else
		printf "\e[31mFAIL\e[0m\n"
	fi
	printf "Checking if /tmp has nosuid: "
	if grep "[[:space:]]/tmp[[:space:]]" /etc/fstab | grep "nosuid" ; then
		printf "\e[32mPASS\e[0m\n"
	else
		printf "\e[31mFAIL\e[0m\n"
	fi

	printf "Checking if /tmp has noexec: "
	if grep "[[:space:]]/tmp[[:space:]]" /etc/fstab | grep "noexec" ; then
		printf "\e[32mPASS\e[0m\n"
	else
		printf "\e[31mFAIL\e[0m\n"
	fi
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if /var is on a separate partition: "
if grep "[[:space:]]/var[[:space:]]" /etc/fstab ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if /var/tmp is bound to /tmp: "
if grep -e "^/tmp[[:space:]]" /etc/fstab | grep /var/tmp ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if /var/log is on a separate partition: "
if grep "[[:space:]]/var/log[[:space:]]" /etc/fstab ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if /var/log/audit is on a separate partition: "
if grep "[[:space:]]/var/log/audit[[:space:]]" /etc/fstab ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if /home is on a separate partition: "
if grep "[[:space:]]/home[[:space:]]" /etc/fstab ; then
	printf "\e[32mPASS\e[0m\n"
	printf "Checking if /home has nodev: "
	if grep "[[:space:]]/home[[:space:]]" /etc/fstab | grep "nodev" ; then
		printf "\e[32mPASS\e[0m\n"
	else
		printf "\e[31mFAIL\e[0m\n"
	fi
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if sticky bits are enabled: "
if [ -n "$(find / \! -perm /1000 -perm /0002 -type f | head -n 1)" ] ; then
	printf "\e[31mFAIL\e[0m\n"
else
	printf "\e[32mPASS\e[0m\n"
fi

printf "\e[1mChecks on System Configurations\e[0m\n"
printf "Checking if legacy file systems are supported on the system: "
if modprobe -n -v {cramfs,freexvfs,jffs2,hfs,hfsplus,squashfs,udf} > /dev/null ; then
	printf "\e[31mFAIL\e[0m\n"
else
	printf "\e[32mPASS\e[0m\n"
fi

printf "Checking if system is registered to Redhat: "
if subscription-manager version | grep "not registered" >/dev/null ; then
	printf "\e[31mFAIL\e[0m\n"
else
	printf "\e[32mPASS\e[0m\n"
fi

printf "\e[1mChecks on Packages and Services\e[0m\n"
printf "Checking if any packages are problematic: "
if rpm -qVa | awk '$2 != "c" { print $0}' &>/dev/null | head -n 1 ; then
	printf "\e[31mFAIL\e[0m\n"
else
	printf "\e[32mPASS\e[0m\n"
fi

printf "Checking if Telnet is not installed: "
if rpm -q telnet-server | grep "not installed" >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mTelnet is installed. Replace with SSH\e[0m\n"
fi

printf "Checking if RSH is not installed: "
if rpm -q rsh-server | grep "not installed" >/dev/null && rpm -q rsh | grep "not installed" >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mRSH is installed. Replace with SSH\e[0m\n"
fi

printf "Checking if NIS is not installed: "
if rpm -q ypserv | grep "not installed" >/dev/null && rpm -q ypbind | grep "not installed" >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mNIS is installed. Replace with other protocols such as LDAP\e[0m\n"
fi

printf "Checking if TFTP is not installed: "
if rpm -q tftp | grep "not installed" >/dev/null && rpm -q tftp-server | grep "not installed" >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mTFTP is installed. Consider replacing with SFTP\e[0m\n"
fi

printf "Checking if xinetd is not installed: "
if rpm -q xinetd | grep "not installed" >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mxinetd is installed. Remove if not needed\e[0m\n"
fi

printf "Checking if chargen-dgram is disabled: "
if chkconfig --list chargen-dgram 2>/dev/null | grep "chargen-dgram[[:space:]]off" ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if chargen-stream is disabled: "
if chkconfig --list chargen-stream 2>/dev/null | grep "chargen-stream[[:space:]]off" ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if daytime-dgram is disabled: "
if chkconfig --list daytime-dgram 2>/dev/null | grep "daytime-dgram[[:space:]]off" ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if daytime-stream is disabled: "
if chkconfig --list daytime-stream 2>/dev/null | grep "daytime-stream[[:space:]]off" ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if echo-dgram is disabled: "
if chkconfig --list echo-dgram 2>/dev/null | grep "echo-dgram[[:space:]]off" ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if echo-stream is disabled: "
if chkconfig --list echo-stream 2>/dev/null | grep "echo-stream[[:space:]]off" ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if tcpmux-server is disabled: "
if chkconfig --list tcpmux-serer 2>/dev/null | grep "tcpmux-server[[:space:]]off" ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if umask is of the recommended value: "
if grep ^umask /etc/sysconfig/init | grep "027" >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if GUI is the default boot target: "
if ls -l /etc/systemd/system/default.target | grep "graphical.target" >/dev/null ; then
	printf "\e[32mGUI is the default boot target. Check if CLI is preferred and X11 can be removed\e[0m\n"
else
	printf "\e[31mGUI is not the default boot target - please check and decide if X11 can be removed\e[0m\n"
fi

printf "Checking if Avahi Daemon is disabled: "
if systemctl status avahi-daemon | grep "active (running)" >/dev/null || systemctl status avahi-daemon | grep "enabled" >/dev/null ; then
	printf "\e[31mFAIL\e[0m\n"
else
	printf "\e[32mPASS\e[0m\n"
fi

printf "Checking if CUPS has been disabled: "
if systemctl status cups | grep "active (running)" >/dev/null || systemctl status cups | grep "enabled" >/dev/null ; then
	printf "\e[31mCUPS enabled. Remove if not needed\e[0m\n"
else
	printf "\e[32mCUPS has been disabled\e[0m\n"
fi

printf "Checking if DHCPD is removed: "
if yum list dhcpd &>/dev/null | grep "Installed Packages" ; then
	printf "\e[31mDHCPD is installed. Remove if not needed\e[0m\n"
else
	printf "\e[32mDHCPD is not installed\e[0m\n"
fi

printf "Checking NTP configurations: "
if grep "^restrict default" /etc/ntp.conf >/dev/null && grep "^restrict -6 default" /etc/ntp.conf >/dev/null && grep "^server" /etc/ntp.conf >/dev/null && grep "ntp:ntp" /etc/sysconfig/ntpd >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if LDAP is removed: "
if yum list { openldap-clients, openldap-servers } &>/dev/null | grep "Installed Packages" ; then
	printf "\e[31mLDAP is installed. Remove if not needed\e[0m\n"
else
	printf "\e[32mLDAP is not installed\e[0m\n"
fi

printf "Checking if NFS and RPC are disabled: "
if systemctl is-enabled nfs-lock | grep "enabled" >/dev/null && systemctl is-enabled nfs-secure | grep "enabled" >/dev/null && systemctl is-enabled rpcbind | grep "enabled" >/dev/null && systemctl is-enabled nfs-idmap | grep "enabled" >/dev/null && systemctl is-enabled nfs-secure-server | grep "enabled" ; then
	printf "\e[31mNFS and RPC are enabled. Disable if not needed\e[0m\n"
else
	printf "\e[32mNFS and RPC are disabled\e[0m\n"
fi

printf "Checking if DNS is disabled: "
if systemctl is-enabled named &>/dev/null | grep "enabled" >/dev/null ; then
	printf "\e[31mDNS is enabled. Disable if not needed\e[0m\n"
else
	printf "\e[32mDNS is disabled\e[0m\n"
fi

printf "Checking if FTP is removed: "
if yum list ftp &>/dev/null | grep "Available packages" ; then
	printf "\e[32mFTP is not installed\e[0m\n"
else
	printf "\e[31mFTP is installed. Consider switching to VSFTPD\e[0m\n"
fi

printf "Checking if HTTP service is removed: "
if yum list httpd &>/dev/null | grep "Available packages" ; then
	printf "\e[32mHTTPD is not installed\e[0m\n"
else
	printf "\e[31mHTTPD is installed\e[0m\n"
fi

printf "Checking if HTTP Proxy Server is removed: "
if yum list squid &>/dev/null | grep "Available packages" ; then
	printf "\e[32mHTTP Proxy Server is not installed\e[0m\n"
else
	printf "\e[31mHTTPD Proxy Server installed\e[0m\n"
fi

printf "Checking if SNMP Service is removed: "
if yum list net-snmp &>/dev/null | grep "Available packages" ; then
	printf "\e[32mSNMP Service is not installed\e[0m\n"
else
	printf "\e[31mSNMP Service is installed\e[0m\n"
fi

printf "Checking if Mail Transfer Agent is Local-Only: "
if [ "$(netstat -an | grep LIST | grep ':25[[:space:]]' | wc -l)" -lt 3 ] ; then
	if [ "$(netstat -an | grep LIST | grep ':25[[:space:]]' | wc -l)" -eq 2 ] ; then
		if netstat -an | grep LIST | grep ':25[[:space:]]' | grep "127.0.0.1:25" >/dev/null && netstat -an | grep LIST | grep ':25[[:space:]]' | grep "::1:25" >/dev/null; then
			printf "\e[32mMTA is Local-Only\e[0m\n"
		else
			printf "\e[31mMTA is not Local-Only\e[0m\n"
		fi
	elif netstat -an | grep LIST | grep ':25[[:space:]]' | grep "127.0.0.1" >/dev/null ; then
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
