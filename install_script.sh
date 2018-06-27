#!/bin/bash
apt install -y gcc libpcre3-dev zlib1g-dev libpcap-dev openssl libssl-dev libnghttp2-dev libdumbnet-dev bison flex libdnet
apt-get install -y libcrypt-ssleay-perl liblwp-useragent-determined-perl
apt-get install -y mysql-server libmysqlclient-dev mysql-client autoconf libtool
pip3 install PyMySQL
pip3 install paramiko

groupadd snort
useradd snort -r -s /sbin/nologin -c SNORT_IDS -g snort
mkdir ~/snort_src && cd ~/snort_src
wget https://www.snort.org/downloads/snort/daq-2.0.6.tar.gz
tar -xvzf daq-2.0.6.tar.gz
cd daq-2.0.6
./configure && make && sudo make install
cd ~/snort_src
wget https://www.snort.org/downloads/snort/snort-2.9.11.1.tar.gz
tar -xvzf snort-2.9.11.1.tar.gz
cd snort-2.9.11.1
./configure --enable-sourcefire && make && sudo make install
ldconfig
ln -s /usr/local/bin/snort /usr/sbin/snort

mkdir /etc/snort/snortShield
touch /etc/snort/snortShield/rules2.xml
touch /etc/snort/snortShield/rules.xml
touch /etc/snort/snortShield/test_rule.xml

mkdir /etc/snort
mkdir /etc/snort/rules
mkdir /etc/snort/rules/iplists
mkdir /etc/snort/preproc_rules
mkdir /usr/local/lib/snort_dynamicrules
mkdir /etc/snort/so_rules
mkdir /var/log/snort
mkdir /var/log/snort/archived_logs
chmod -R 5775 /etc/snort
chmod -R 5775 /var/log/snort
chmod -R 5775 /var/log/snort/archived_logs
chmod -R 5775 /etc/snort/so_rules
chmod -R 5775 /usr/local/lib/snort_dynamicrules
chown -R snort:snort /etc/snort
chown -R snort:snort /var/log/snort
chown -R snort:snort /usr/local/lib/snort_dynamicrules
touch /etc/snort/rules/iplists/black_list.rules
touch /etc/snort/rules/iplists/white_list.rules
touch /etc/snort/rules/local.rules
touch /etc/snort/sid-msg.map
cp ~/snort_src/snort-2.9.11.1/etc/*.conf* /etc/snort
cp ~/snort_src/snort-2.9.11.1/etc/*.map /etc/snort
cp ~/snort_src/snort-2.9.11.1/etc/*.dtd /etc/snort
cd ~/snort_src/snort-2.9.11.1/src/dynamic-preprocessors/build/usr/local/lib/snort_dynamicpreprocessor/
cp * /usr/local/lib/snort_dynamicpreprocessor/
sed -i 's/include \$RULE\_PATH/#include \$RULE\_PATH/' /etc/snort/snort.conf


cd ~/snort_src
wget https://github.com/shirkdog/pulledpork/archive/master.tar.gz -O pulledpork-master.tar.gz
tar xzvf pulledpork-master.tar.gz
cd pulledpork-master/
cp pulledpork.pl /usr/local/bin
chmod +x /usr/local/bin/pulledpork.pl
cp etc/*.conf /etc/snort


cd ~/snort_src
wget https://github.com/firnsy/barnyard2/archive/master.tar.gz -O barnyard2-Master.tar.gz
tar zxvf barnyard2-Master.tar.gz
cd barnyard2-master
autoreconf -fvi -I ./m4
ln -s /usr/include/dumbnet.h /usr/include/dnet.h
ldconfig

if [ $(uname -m) == 'x86_64' ]; then
  ./configure --with-mysql --with-mysql-libraries=/usr/lib/x86_64-linux-gnu
else
  ./configure --with-mysql --with-mysql-libraries=/usr/lib/i386-linux-gnu
fi

make
make install
cp ~/snort_src/barnyard2-master/etc/barnyard2.conf /etc/snort/
mkdir /var/log/barnyard2
chown snort.snort /var/log/barnyard2
touch /var/log/snort/barnyard2.waldo
chown snort.snort /var/log/snort/barnyard2.waldo
chmod o-r /etc/snort/barnyard2.conf

add-apt-repository ppa:ondrej/php
apt-get update
apt-get install -y apache2 libapache2-mod-php5.6 php5.6-mysql php5.6-cli php5.6 php5.6-common php5.6-gd php5.6-cli php-pear php5.6-xml
pear install -f --alldeps Image_Graph
cd ~/snort_src
wget https://sourceforge.net/projects/adodb/files/adodb-php5-only/adodb-520-for-php5/adodb-5.20.8.tar.gz
tar -xvzf adodb-5.20.8.tar.gz
mv adodb5 /var/adodb
chmod -R 755 /var/adodb
cd ~/snort_src
wget http://sourceforge.net/projects/secureideas/files/BASE/base-1.4.5/base-1.4.5.tar.gz
tar xzvf base-1.4.5.tar.gz
mv base-1.4.5 /var/www/html/base/
cd /var/www/html/base
cp base_conf.php.dist base_conf.php
chown -R www-data:www-data /var/www/html/base
chmod o-r /var/www/html/base/base_conf.php
service apache2 restart
apt-get install iptables-persistent
service netfilter-persistent start
echo 1 > /proc/sys/net/ipv4/ip_forward