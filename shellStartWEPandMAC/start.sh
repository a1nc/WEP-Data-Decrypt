#!/bin/bash

sudo ifconfig wlx00184dbbcc91 up
echo "WEP and MAC"
echo "---------------------------"
echo "sh: sudo ifconfig"

sudo ifconfig |tee rec_ifconfig

DevFlag="wlx"
Buffer=$(cat rec_ifconfig)
for str in $Buffer
do
if [[ $str = *$DevFlag* ]]
then
echo $str
DevName=$str
fi
done
echo "Device Name: " $DevName
echo "sh: sudo ifconfig "$DevName" dwon"
sudo ifconfig $DevName down
echo "sh: sudo iwconfig "$DevName" mode monitor"
sudo iwconfig $DevName mode monitor
echo "sh: sudo airmon-ng start "$DevName

ArrayError=(var0 var1 var2 var3 var4 var5 var6 var7 var8 var9)
ArrayLength=0
sudo airmon-ng start $DevName |tee rec_airmon
Buffer=$(cat rec_airmon)
for str in $Buffer
do
echo $str
if [ "$str" -gt 100 ] > txt 
then
ArrayError[ArrayLength]="$str"
echo "$str"
ArrayLength=`expr $ArrayLength + 1`
fi
done

for loop in 0 1 2 3 4 5 6 7 8 9
do
if [ "$loop" -lt $ArrayLength ]
then
FlagKill=1
echo "su: sudo kill -s 9 "${ArrayError[$loop]}
sudo kill -s 9 ${ArrayError[$loop]}
fi
done

if [ "$FlagKill" -eq 1 ]
then
echo "sh: sudo airmon-ng start "$DevName
sudo airmon-ng start $DevName
fi
echo "sh: sudo airbase-ng mon0 -e " "TEST" " -c 5 -s -w 1112223334"
sudo airbase-ng mon0 -e "TEST" -c 5 -s -w 1112223334 > rec_airbase &
echo "---------------------------"
echo "Capture Packet"
sudo ./run
