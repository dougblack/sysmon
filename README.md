## Sysmon

Setup

1. `make` build as kernel module
2. `sudo ./build.sh` insert module
3. `id` get current user id
4. `echo [user_id] > /proc/sysmon_uid` tell module which user to monitor
5. `echo 1 > /proc/sysmon_toggle` turn the monitor on

Read syscall logs

1. `cat /proc/sysmon_log` print out the log to dmesg
2. `sudo dmesg -c` read and destroy current log output

