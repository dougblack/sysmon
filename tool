#! /bin/bash

# Doug Black
# Gabino Dabdoub

# Approach 1. This method is mentioned in 
# the kprobes help guide.
if [ ! -f /sys/kernel/debug/kprobes/list ]; then
   echo "Mounting /sys/kernel/debug/kprobes"
   mount -t debugfs none /sys/kernel/debug
fi

# Get number of kprobes active. If over 30, initialized.
lines=`cat /sys/kernel/debug/kprobes/list | wc -l`
if [ $lines -ge 30 ]; then
   echo "Monitoring is initialized."
else
   echo "Monitoring is not initialized."
fi

# Turn all kprobes on.
if [ $1 ] && [ $1 = "on" ]; then
   echo 1 > /sys/kernel/debug/kprobes/enabled
   echo "Turned monitoring on."
# Turn all kprobes off
elif [ $1 ] && [ $1 = "off" ]; then
   echo 0 > /sys/kernel/debug/kprobes/enabled
   echo "Turned monitoring off."

# Approach 2.
elif [ $1 ] && [ $1 = "log" ]; then
   dmesg > out.txt
   first=`cat out.txt | tac | grep -m1 'Its id is' | awk '{ print $NF }'`
   echo $first
   if ! [[ "$first" =~ ^[0-9]+$ ]]; then
      echo "Not monitoring"
      exit 0
   fi
   echo "Starting busy work to generate syscalls"
   ls
   mkdir a
   rm -rf a
   ls
   mkdir a
   rm -rf a
   ls
   mkdir a
   rm -rf a
   echo "Sleeping for 7 seconds"
   sleep 7 
   echo "Done sleeping"
   dmesg > out.txt
   second=`cat out.txt | tac | grep -m1 'Its id is' | awk '{ print $NF }'`
   if [ $second -gt $first ]; then
      echo "Currently monitoring!"
   else
      echo "Not currently monitoring."
   fi
# Approach 3.
elif [ $1 ] && [ $1 = "clog" ]; then
   cat /proc/sysmon_log
   first=`dmesg | tail -3`
   ls
   cat /proc/sysmon_log
   second=`dmesg | tail -3`
   if [[ "$second" == "$first" ]]
   then
      echo "Not currently monitoring."
   else
      echo "Currently monitoring."
   fi
fi
