#! /bin/bash
if [ ! -f /sys/kernel/debug/kprobes/list ]; then
   echo "Mounting /sys/kernel/debug/kprobes"
   mount -t debugfs none /sys/kernel/debug
fi

lines=`cat /sys/kernel/debug/kprobes/list | wc -l`
if [ $lines -ge 30 ]; then
   echo "Monitoring is initialized."
else
   echo "Monitoring is not initialized."
fi

if [ $1 ] && [ $1 = "on" ]; then
   echo 1 > /sys/kernel/debug/kprobes/enabled
   echo "Turned monitoring on."
elif [ $1 ] && [ $1 = "off" ]; then
   echo 0 > /sys/kernel/debug/kprobes/enabled
   echo "Turned monitoring off."
fi
