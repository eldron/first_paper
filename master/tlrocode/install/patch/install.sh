#! /bin/bash
# description: remove sma modules when shutdown/reboot
#

rm -f /etc/rc.d/rc0.d/K01sma
rm -f /etc/rc.d/rc6.d/K01sma
rm -f /etc/rc.d/rc3.d/S99sma
rm -f /etc/rc.d/rc5.d/S99sma

cp -f sma /etc/rc.d/init.d
chmod 777 /etc/rc.d/init.d/sma
ln -s /etc/rc.d/init.d/sma /etc/rc.d/rc0.d/K01sma 
ln -s /etc/rc.d/init.d/sma /etc/rc.d/rc6.d/K01sma
ln -s /etc/rc.d/init.d/sma /etc/rc.d/rc3.d/S99sma 
ln -s /etc/rc.d/init.d/sma /etc/rc.d/rc5.d/S99sma 

