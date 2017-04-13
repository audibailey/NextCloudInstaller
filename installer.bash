#!/bin/bash
#
# Desgyz NextCloud Install Script
#
# Custom built NextCloud Install Script designed for installing NextCloud on a Vultr VPS easier.
#
# May work on Ubuntu 16.04 64bit on other VPS providors or machines.
#
# Copyright 2017, Desgyz (Audi Bailey) <audibailey7@gmail.com> (No redistributing please)

# -------------------------------------------
# Beginning the script
# -------------------------------------------

echo "-------------------------------------------"
echo "Running Preliminary Tests/Setup and Installing Whiptail (User Interface)"
echo "-------------------------------------------"
sleep 2

# -------------------------------------------
# Root Check
# -------------------------------------------

echo "-------------------------------------------"
echo "Checking that you are root"
echo "-------------------------------------------"

if [[ $EUID -ne 0 ]]; then
  echo "Aborting because you are not root" ; exit 1
fi

# -------------------------------------------
# Housekeeping
# -------------------------------------------

echo "-------------------------------------------"
echo "Setting Home Directory"
echo "-------------------------------------------"

if [[ $HOME == "" ]]; then
    export HOME=/root
fi

# -------------------------------------------
# Abort if directory certain file directories exists
# -------------------------------------------

echo "-------------------------------------------"
echo "Checking if /etc/caddy exists"
echo "-------------------------------------------"

if [[ -d "/etc/caddy" ]] ;
then
  whiptail --title "Desgyz NextCloud Installer" --msgbox " \n Aborting because directory /etc/caddy already exist \n " 8 70
  exit 1
fi

echo "-------------------------------------------"
echo "Checking if /etc/ssl/caddy exists"
echo "-------------------------------------------"

if [[ -d "/etc/ssl/caddy" ]] ;
then
  whiptail --title "Desgyz NextCloud Installer" --msgbox " \n Aborting because directory /etc/ssl/caddy already exist \n " 8 70
  exit 1
fi

# -------------------------------------------
# Abort if not Ubuntu 16.04 64bit
# -------------------------------------------

echo "-------------------------------------------"
echo "Checking if you are using the correct version of Ubuntu"
echo "-------------------------------------------"

DIST="$(lsb_release -si)"
VER="$(lsb_release -sr)"
ARCH="$(uname -m)"

if [[ ${DIST} != "ubuntu" && ${VER} != "16.04" && {ARCH} != "x86_64" ]] ; 
then
  whiptail --title "Desgyz NextCloud Installer" --msgbox " \n Aborting because you are using the wrong OS, use Ubuntu 16.04 64bit \n " 8 70
  exit 1
fi

# -------------------------------------------
# Installing Whiptail
# -------------------------------------------

echo "-------------------------------------------"
echo "Installing Whiptail with the blue background"
echo "-------------------------------------------"

apt-get update
apt-get install whiptail -y
ln -sf /etc/newt/palette.original  /etc/alternatives/newt-palette

# -------------------------------------------
# Running the Script
# -------------------------------------------

whiptail --title "Desgyz NextCloud Installer" --msgbox "This script installs NextCloud on a Ubuntu 16.04 (Xenial) 64bit \n
----------------------------------------------------------------- \n
This installer is meant to run on a freshly installed machine 
only. If you run it on a production server things can and 
probably will go terribly wrong and you will lose valuable 
data! \n
-----------------------------------------------------------------" 16 74


# -------------------------------------------
# Additional required packages
# -------------------------------------------

whiptail --title "Desgyz NextCloud Installer" --msgbox " \n It will now install the required packages to begin \n " 8 64

echo "-------------------------------------------"
echo "Installing requried packages for NextCloud"
echo "-------------------------------------------"

debconf-apt-progress -- apt-get update
debconf-apt-progress -- apt dist-upgrade -y
debconf-apt-progress -- apt-get install software-properties-common curl wget unzip tar libcups2 libgl1-mesa-glx libsm6 libpixman-1-0 libxcb-shm0 libxcb-render0 libxrender1 libcairo2-dev -y 

whiptail --title "Desgyz NextCloud Installer" --msgbox " \n This script will now install NextCloud \n " 8 44

# -------------------------------------------
# HOLY FUNCTIONS
# -------------------------------------------

function install_nextcloud {
    # -------------------------------------------
    # NextCloud Install/Config
    # -------------------------------------------    
    
NEXTCLOUD_VERSION=$(whiptail --title "Desgyz NextCloud Installer" --inputbox "What version of NextCloud would you like to install?? " 8 93 3>&1 1>&2 2>&3)
DOMAIN_NAME=$(whiptail --title "Desgyz NextCloud Installer" --inputbox "What is your domain name? " 8 93 3>&1 1>&2 2>&3)
    echo "-------------------------------------------"
    echo "Creating NextCloud Directory"
    echo "-------------------------------------------"
    
mkdir -p /var/www/$DOMAIN_NAME/
chown -R www-data:www-data /var/www/$DOMAIN_NAME/
cd /var/www/$DOMAIN_NAME/

    echo "-------------------------------------------"
    echo "Downloading NextCloud"
    echo "-------------------------------------------"
    
wget https://download.nextcloud.com/server/releases/nextcloud-$NEXTCLOUD_VERSION.tar.bz2
tar -vxjf nextcloud-$NEXTCLOUD_VERSION.tar.bz2
rm nextcloud-$NEXTCLOUD_VERSION.tar.bz2
chown -R www-data:www-data /var/www/$DOMAIN_NAME/

    echo "-------------------------------------------"
    echo "Creating NextCloud Data Directory"
    echo "-------------------------------------------"
    
    DATA_DIR=$(whiptail --title "Desgyz NextCloud Installer" --inputbox "Where would you like to store the NextCloud Data Directory? " 8 93 3>&1 1>&2 2>&3)
    
mkdir -p $DATA_DIR
chown -R www-data:www-data $DATA_DIR
    
    echo "-------------------------------------------"
    echo "Your NextCloud Data Directory is $DATA_DIR, you will need this for the Web Setup."
    echo "-------------------------------------------"
}

function install_caddy {

    # -------------------------------------------
    # Caddy Install/Config
    # -------------------------------------------    
    
    echo "-------------------------------------------"
    echo "Installing Caddy"
    echo "-------------------------------------------"
    
curl -fsSL https://getcaddy.com | bash
setcap cap_net_bind_service=+ep /usr/local/bin/caddy
    echo "-------------------------------------------"
    echo "Configuring Caddy Folders"
    echo "-------------------------------------------"
    
mkdir /etc/caddy
touch /etc/caddy/Caddyfile
chown -R root:www-data /etc/caddy
mkdir /etc/ssl/caddy
chown -R www-data:root /etc/ssl/caddy
chmod 0770 /etc/ssl/caddy
}

function install_mysql {

    # -------------------------------------------
    # MySQL Install/Config
    # -------------------------------------------
    
    MYSQL_PASSWORD=$(whiptail --title "Desgyz NextCloud Installer" --passwordbox "Enter MySQL Password: " 8 93 3>&1 1>&2 2>&3)
    
    echo "-------------------------------------------"
    echo "Setting MySQL DebConfs"
    echo "-------------------------------------------"
    
    echo "mysql-server-5.7 mysql-server/root_password password $MYSQL_PASSWORD" | sudo debconf-set-selections
    echo "mysql-server-5.7 mysql-server/root_password_again password $MYSQL_PASSWORD" | sudo debconf-set-selections
    
    echo "-------------------------------------------"
    echo "Installing MySQL Server and Expect"
    echo "-------------------------------------------"
    
    apt-get update
    apt-get install mysql-server expect -y

    echo "-------------------------------------------"
    echo "Running Expect for the automated MySQL setup"
    echo "-------------------------------------------"
    
    SECURE_MYSQL=$(expect -c "
    set timeout 10
    spawn mysql_secure_installation
    expect \"Enter current password for root:\"
    send \"$MYSQL_PASSWORD\r\"
    expect \"Would you like to setup VALIDATE PASSWORD plugin?\"
    send \"n\r\" 
    expect \"Change the password for root ?\"
    send \"n\r\"
    expect \"Remove anonymous users?\"
    send \"y\r\"
    expect \"Disallow root login remotely?\"
    send \"y\r\"
    expect \"Remove test database and access to it?\"
    send \"y\r\"
    expect \"Reload privilege tables now?\"
    send \"y\r\"
    expect eof
    ")
    
    echo "-------------------------------------------"
    echo "Creating the NextCloud Database"
    echo "-------------------------------------------"
    
mysql -u root --password=$MYSQL_PASSWORD -e "CREATE DATABASE nextcloud; GRANT ALL PRIVILEGES ON nextcloud.* TO 'nextcloud'@'localhost' IDENTIFIED BY 'nextcloudPassword'; FLUSH PRIVILEGES;"
    echo "-------------------------------------------"
    echo "Restarting MySQL"
    echo "-------------------------------------------"
    
service mysql restart
}

function install_php5.6 {

    # -------------------------------------------
    # PHP5.6 Install/Config
    # -------------------------------------------

    echo "-------------------------------------------"    
    echo "Adding PHP5.6 repository and installing PHP5.6"
    echo "-------------------------------------------"
add-apt-repository ppa:ondrej/php -y
apt-get update
    apt-get install php5.6-fpm php5.6-json php5.6-curl php5.6-ldap php5.6-imap php5.6-gd php5.6-mysql php5.6-xml php5.6-zip php5.6-intl php5.6-mcrypt php5.6-imagick php5.6-mbstring php5.6-cli -y 
    echo "-------------------------------------------"
    echo "Editing the php.ini"
    echo "-------------------------------------------"
    
sed -i "s/memory_limit = .*/memory_limit = 512M/" /etc/php/5.6/fpm/php.ini
sed -i "s/;date.timezone.*/date.timezone = UTC/" /etc/php/5.6/fpm/php.ini
sed -i "s/;cgi.fix_pathinfo=1/cgi.fix_pathinfo=1/" /etc/php/5.6/fpm/php.ini 
sed -i "s/upload_max_filesize = .*/upload_max_filesize = 500M/" /etc/php/5.6/fpm/php.ini
sed -i "s/post_max_size = .*/post_max_size = 500M/" /etc/php/5.6/fpm/php.ini
}

function install_php {

    # -------------------------------------------
    # PHP7 Install/Config
    # -------------------------------------------

    echo "-------------------------------------------"
    echo "Installing PHP7"
    echo "-------------------------------------------"
    
    apt-get update
    apt-get install php-fpm php-json php-curl php-ldap php-imap php-gd php-mysql php-xml php-zip php-intl php-mcrypt php-imagick php-mbstring php-cli -y
    echo "-------------------------------------------"
    echo "Editing the php.ini"
    echo "-------------------------------------------"
    
sed -i "s/memory_limit = .*/memory_limit = 512M/" /etc/php/7.0/fpm/php.ini
sed -i "s/;date.timezone.*/date.timezone = UTC/" /etc/php/7.0/fpm/php.ini
sed -i "s/;cgi.fix_pathinfo=1/cgi.fix_pathinfo=1/" /etc/php/7.0/fpm/php.ini 
sed -i "s/upload_max_filesize = .*/upload_max_filesize = 500M/" /etc/php/7.0/fpm/php.ini
sed -i "s/post_max_size = .*/post_max_size = 500M/" /etc/php/7.0/fpm/php.ini
}

function config_caddyphp5.6 {
    
    # -------------------------------------------
    # Caddyfile and Caddy Service Installation (PHP5.6)
    # -------------------------------------------
    
DOMAIN_NAME=$(whiptail --title "Desgyz NextCloud Installer" --inputbox "What is your domain name? " 8 93 3>&1 1>&2 2>&3)
TLS_EMAIL=$(whiptail --title "Desgyz NextCloud Installer" --inputbox "What is your email address for the SSL cert? " 8 93 3>&1 1>&2 2>&3)
    
    echo "-------------------------------------------"
    echo "Configuring the CaddyFile"
    echo "-------------------------------------------"
    
cat >/etc/caddy/Caddyfile <<EOT
    $DOMAIN_NAME {
        root /var/www/$DOMAIN_NAME/nextcloud
        log /var/tmp/access.log
        errors /var/tmp/error.log
        tls $TLS_EMAIL
        gzip
        fastcgi / /var/run/php/php5.6-fpm.sock {
                env PATH /bin
                ext .php
                split .php
        }
        rewrite {
                r ^/index.php/.*$
                to /index.php?{query}
        }
        # client support (e.g. os x calendar / contacts)
        redir /.well-known/carddav /remote.php/carddav 301
        redir /.well-known/caldav /remote.php/caldav 301
        # remove trailing / as it causes errors with php-fpm
        rewrite {
                r ^/remote.php/(webdav|caldav|carddav|dav)(\/?)$
                to /remote.php/{1}
        }
        rewrite {
                r ^/remote.php/(webdav|caldav|carddav|dav)/(.+?)(\/?)$
                to /remote.php/{1}/{2}
        }
        # .htaccess / data / config / ... shouldn't be accessible from outside
        status 403 {
                /.htacces
                /data
                /config
                /db_structure
                /.xml
                /README
        }
        header / Strict-Transport-Security "max-age=31536000;"
   }
EOT

    echo "-------------------------------------------"
    echo "Creating the Caddy Service"
    echo "-------------------------------------------"
    
    cat >/etc/systemd/system/caddy.service <<EOL
    [Unit]
    Description=Caddy HTTP/2 web server
    Documentation=https://caddyserver.com/docs
    After=network-online.target
    Wants=network-online.target systemd-networkd-wait-online.service
   
    [Service]
    Restart=on-failure
   
    User=www-data
    Group=www-data
   
    Environment=HOME=/etc/ssl/caddy
   
    ExecStart=/usr/local/bin/caddy -log stdout -agree=true -conf=/etc/caddy/Caddyfile -root=/var/tmp
    ExecReload=/bin/kill -USR1 $MAINPID
   
    LimitNOFILE=4096
    LimitNPROC=64
   
    PrivateTmp=true
    PrivateDevices=true
    ProtectHome=true
    ProtectSystem=full
    ReadWriteDirectories=/etc/ssl/caddy
   
    CapabilityBoundingSet=CAP_NET_BIND_SERVICE
    AmbientCapabilities=CAP_NET_BIND_SERVICE
    NoNewPrivileges=true
   
    [Install]
    WantedBy=multi-user.target 
   
EOL

    echo "-------------------------------------------"
    echo "Enable the Caddy service on start up"
    echo "-------------------------------------------"
    
    systemctl enable caddy
    
}

function config_caddyphp {

    # -------------------------------------------
    # Caddyfile and Caddy Service Installation (PHP7)
    # -------------------------------------------

DOMAIN_NAME=$(whiptail --title "Desgyz NextCloud Installer" --inputbox "What is your domain name? " 8 93 3>&1 1>&2 2>&3)
TLS_EMAIL=$(whiptail --title "Desgyz NextCloud Installer" --inputbox "What is your email address for the SSL cert? " 8 93 3>&1 1>&2 2>&3)
    
    echo "-------------------------------------------"
    echo "Configuring the CaddyFile"
    echo "-------------------------------------------"
    
cat >/etc/caddy/Caddyfile <<EOT
$DOMAIN_NAME {
root /var/www/$DOMAIN_NAME/nextcloud
log /var/tmp/access.log
errors /var/tmp/error.log
tls $TLS_EMAIL
gzip
fastcgi / /var/run/php/php7.0-fpm.sock {
env PATH /bin
ext .php
split .php
}
rewrite {
r ^/index.php/.*$
to /index.php?{query}
}

# client support (e.g. os x calendar / contacts)
redir /.well-known/carddav /remote.php/carddav 301
redir /.well-known/caldav /remote.php/caldav 301

# remove trailing / as it causes errors with php-fpm
rewrite {
r ^/remote.php/(webdav|caldav|carddav|dav)(\/?)$
to /remote.php/{1}
}

rewrite {
r ^/remote.php/(webdav|caldav|carddav|dav)/(.+?)(\/?)$
to /remote.php/{1}/{2}
}

# .htaccess / data / config / ... shouldn't be accessible from outside
status 403 {
/.htacces
/data
/config
/db_structure
/.xml
/README
}

header / Strict-Transport-Security "max-age=31536000;"

}
EOT
    echo "-------------------------------------------"
    echo "Creating the Caddy Service"
    echo "-------------------------------------------"
    
   cat >/etc/systemd/system/caddy.service <<EOL
[Unit]
Description=Caddy HTTP/2 web server
Documentation=https://caddyserver.com/docs
After=network-online.target
Wants=network-online.target systemd-networkd-wait-online.service

[Service]
Restart=on-failure

User=www-data
Group=www-data

Environment=HOME=/etc/ssl/caddy

ExecStart=/usr/local/bin/caddy -log stdout -agree=true -conf=/etc/caddy/Caddyfile -root=/var/tmp
ExecReload=/bin/kill -USR1 $MAINPID

LimitNOFILE=4096
LimitNPROC=64

PrivateTmp=true
PrivateDevices=true
ProtectHome=true
ProtectSystem=full
ReadWriteDirectories=/etc/ssl/caddy

CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOL

    echo "-------------------------------------------"
    echo "Enable the Caddy service on start up"
    echo "-------------------------------------------"

systemctl enable caddy
}

function install_code { #FIX
CERT_PATH=/etc/ssl/caddy/.caddy/acme/acme-v01.api.letsencrypt.org/sites/$DOMAIN_NAME
    FILEPATH=/usr/share/loolwsd

apt-get install apt-transport-https ca-certificates curl software-properties-common -y
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add -
add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
apt-get update
apt-get install docker-ce -y
docker run -t -d -p 127.0.0.1:9980:9980 --name collabora -e "domain=$DOMAIN_NAME" --restart always --cap-add MKNOD collabora/code
docker cp collabora:/opt/collaboraoffice5.1/ /opt/
docker cp collabora:/usr/bin/loolforkit /usr/bin/
docker cp collabora:/usr/bin/loolmap /usr/bin/
docker cp collabora:/usr/bin/loolmount /usr/bin/
docker cp collabora:/usr/bin/looltool /usr/bin/
docker cp collabora:/usr/bin/loolwsd /usr/bin/
docker cp collabora:/usr/bin/loolwsd-systemplate-setup /usr/bin/
docker cp collabora:/etc/loolwsd/ /etc/
docker cp collabora:/usr/share/loolwsd/ /usr/share/
docker cp collabora:/usr/lib/libPocoCrypto.so.45 /usr/lib/
docker cp collabora:/usr/lib/libPocoFoundation.so.45 /usr/lib/
docker cp collabora:/usr/lib/libPocoJSON.so.45 /usr/lib/
docker cp collabora:/usr/lib/libPocoNet.so.45 /usr/lib/
docker cp collabora:/usr/lib/libPocoNetSSL.so.45 /usr/lib/
docker cp collabora:/usr/lib/libPocoUtil.so.45 /usr/lib/
docker cp collabora:/usr/lib/libPocoXML.so.45 /usr/lib/
docker stop collabora
docker rm collabora
rm /etc/loolwsd/*.pem
USERNAME=$(whiptail --title "Desgyz NextCloud Installer" --inputbox "Type the CODE Admin Username : " 8 93 3>&1 1>&2 2>&3)
PASSWORD=$(whiptail --title "Desgyz NextCloud Installer" --passwordbox "Type the CODE Admin Password: " 8 93 3>&1 1>&2 2>&3)

sed -i "s/<cert_file_path desc="Path to the cert file" relative="false">\/etc\/loolwsd\/cert.pem<\/cert_file_path>/<cert_file_path desc="Path to the cert file" relative="false">\/etc\/ssl\/caddy\/.caddy\/acme\/acme-v01.api.letsencrypt.org\/sites\/$DOMAIN_NAME.crt<\/cert_file_path>" /etc/loolwsd/loolwsd.xml
sed -i "s/<key_file_path desc="Path to the key file" relative="false">\/etc\/loolwsd\/key.pem<\/key_file_path>/<key_file_path desc="Path to the key file" relative="false">\/etc\/ssl\/caddy\/.caddy\/acme\/acme-v01.api.letsencrypt.org\/sites\/$DOMAIN_NAME.key<\/key_file_path>" /etc/loolwsd/loolwsd.xml
sed -i "s/<ca_file_path desc="Path to the ca file" relative="false">\/etc\/loolwsd\/ca-chain.cert.pem</ca_file_path>/<ca_file_path desc="Path to the ca file" relative="false">\/etc\/ssl\/caddy\/.caddy\/acme\/acme-v01.api.letsencrypt.org\/sites\/$DOMAIN_NAME.crt</ca_file_path>" /etc/loolwsd/loolwsd.xml
sed -i "s@><\/file_server_root_path>@>$FILEPATH<\/file_server_root_path>@g" /etc/loolwsd/loolwsd.xml
sed -i "s@><\/username>@>$USERNAME<\/username>@g" /etc/loolwsd/loolwsd.xml
sed -i "s@><\/password>@>$PASSWORD<\/password>@g" /etc/loolwsd/loolwsd.xml

useradd lool
setcap cap_fowner,cap_mknod,cap_sys_chroot=ep /usr/bin/loolforkit
setcap cap_sys_admin=ep /usr/bin/loolmount
mkdir -p /var/cache/loolwsd/
mkdir -p /opt/lool/child-roots/
chown -R lool:lool /var/cache/loolwsd/
chown -R lool:lool /opt/lool/child-roots/

/usr/bin/loolwsd-systemplate-setup /opt/lool/systemplate /opt/collaboraoffice5.1/
chown -R lool:lool /opt/lool/systemplate
cat >/etc/systemd/system/loolwsd.service <<EOL
[Unit]
Description=loolwsd as a service

[Service]
User=lool
ExecStart=/usr/bin/loolwsd --o:sys_template_path=/opt/lool/systemplate --o:lo_template_path=/opt/collaboraoffice5.1 --o:child_root_path=/opt/lool/child-roots --o:file_server_root_path=/usr/share/loolwsd
ExecReload=/bin/kill -HUP $MAINPID
KillMode=process
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOL
    #echo "I haven't finished programming the install CODE script, it seems to be quite difficult. Give me some time please."
    #echo "Congratulation for getting this far, here take a free exit. I'm all out of cookies :("
    #sleep 3
    #exit 1
}

function install_secpatches6.5 {

    # -------------------------------------------
    # Configure Security Patches (PHP5.6)
    # -------------------------------------------

    # -------------------------------------------
    # SSH Stuff
    # -------------------------------------------

    SSH_KEY=$(whiptail --title "Desgyz NextCloud Installer" --inputbox "What is your SSH Key? " 8 93 3>&1 1>&2 2>&3)
    
    echo "-------------------------------------------"
    echo "Adding SSH Key"
    echo "-------------------------------------------"
    
    mkdir -p /root/.ssh
    chmod 600 /root/.ssh
    echo $SSH_KEY > /root/.ssh/authorized_keys
    chmod 700 /root/.ssh/authorized_keys

    SSH_PORT=$(whiptail --title "Desgyz NextCloud Installer" --inputbox "What port would you like SSH to be on? " 8 93 3>&1 1>&2 2>&3)
    echo "-------------------------------------------"
    echo "Changing SSH Configs"
    echo "-------------------------------------------"
    
sed -i "s/Port 22/Port $SSH_PORT/" /etc/ssh/sshd_config
sed -i "s/#PasswordAuthentication yes/PasswordAuthentication no/" /etc/ssh/sshd_config
# -------------------------------------------
    # Firewall Stuff
    # -------------------------------------------
    
    echo "-------------------------------------------"
    echo "Editing Firewall"
    echo "-------------------------------------------"
    
ufw default allow outgoing
ufw default deny incoming
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow $SSH_PORT/tcp
ufw enable
ufw status

# -------------------------------------------
    # FS Stuff
    # -------------------------------------------
    echo "-------------------------------------------"
    echo "Editing fstab"
    echo "-------------------------------------------"
    
echo "
tmpfs     /run/shm     tmpfs     defaults,noexec,nosuid     0     0" >> /etc/fstab
# -------------------------------------------
    # SysCtl Stuff
    # -------------------------------------------

    echo "-------------------------------------------"
    echo "Editing SYSCTL"
    echo "-------------------------------------------"
    
sed -i 's/#net.ipv4.conf.default.rp_filter=1/net.ipv4.conf.all.rp_filter = 1/' /etc/sysctl.conf
sed -i 's/#net.ipv4.conf.all.rp_filter=1/net.ipv4.conf.default.rp_filter = 1/' /etc/sysctl.conf
echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf
sed -i 's/#net.ipv4.conf.all.accept_source_route = 0/net.ipv4.conf.all.accept_source_route = 0/' /etc/sysctl.conf
sed -i 's/#net.ipv6.conf.all.accept_source_route = 0/net.ipv6.conf.all.accept_source_route = 0/' /etc/sysctl.conf
echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
sed -i 's/#net.ipv4.conf.all.send_redirects = 0/net.ipv4.conf.all.send_redirects = 0/' /etc/sysctl.conf
echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf
sed -i 's/#net.ipv4.tcp_syncookies=1/net.ipv4.tcp_syncookies = 1/' /etc/sysctl.conf
echo "net.ipv4.tcp_max_syn_backlog = 2048" >> /etc/sysctl.conf
echo "net.ipv4.tcp_synack_retries = 2" >> /etc/sysctl.conf
echo "net.ipv4.tcp_syn_retries = 5" >> /etc/sysctl.conf
sed -i 's/#net.ipv4.conf.all.log_martians = 1/net.ipv4.conf.all.log_martians = 1/' /etc/sysctl.conf
echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.conf
sed -i 's/#net.ipv4.conf.all.accept_redirects = 0/net.ipv4.conf.all.accept_redirects = 0/' /etc/sysctl.conf
sed -i 's/#net.ipv6.conf.all.accept_redirects = 0/net.ipv6.conf.all.accept_redirects = 0/' /etc/sysctl.conf
echo "net.ipv4.conf.default.accept_redirects = 0 " >> /etc/sysctl.conf
echo "net.ipv6.conf.default.accept_redirects = 0 " >> /etc/sysctl.conf
echo "net.ipv4.icmp_echo_ignore_all = 1" >> /etc/sysctl.conf
sysctl -p

# -------------------------------------------
    # Host file Stuff
    # -------------------------------------------
echo "-------------------------------------------"
    echo "Editing Hosts"
    echo "-------------------------------------------"
    
rm -R /etc/host.conf
echo "
order bind,hosts
multi on
nospoof on" >> /etc/host.conf
# -------------------------------------------
    # PHP Stuff
    # -------------------------------------------
    
PHP_SESSION_ID=$(whiptail --title "Desgyz NextCloud Installer" --inputbox "What is the PHP Session ID? " 8 93 3>&1 1>&2 2>&3)

    echo "-------------------------------------------"
    echo "Patching PHP"
    echo "-------------------------------------------"

echo "register_globals = Off" >> /etc/php/5.6/fpm/php.ini
sed -i 's/html_errors = On/html_errors = Off/' /etc/php/5.6/fpm/php.ini
echo "magic_quotes_gpc = Off" >> /etc/php/5.6/fpm/php.ini
sed -i 's/mail.add_x_header = On/mail.add_x_header = Off' /etc/php/5.6/fpm/php.ini
sed -i "s/session.name = PHPSESSID/session.name = $PHP_SESSION_ID/" /etc/php/5.6/fpm/php.ini
sed -i 's/disable_functions = pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,/disable_functions = pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,exec,system,shell_exec,passthru/' /etc/php/5.6/fpm/php.ini

# -------------------------------------------
    # Fail2Ban Stuff
    # -------------------------------------------
    
ALERT_EMAIL=$(whiptail --title "Desgyz NextCloud Installer" --inputbox "What is your email for alerts? " 8 93 3>&1 1>&2 2>&3)
    echo "-------------------------------------------"
    echo "Installing Fail2Ban"
    echo "-------------------------------------------"
    
apt install fail2ban
    
    echo "-------------------------------------------"
    echo "Setting up Fail2Ban"
    echo "-------------------------------------------"
    
echo "
[sshd]

enabled  = true
port     = $SSH_PORT
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 3" >> /etc/fail2ban/jail.conf
sed -i "s/destemail = root@localhost/destemail = $ALERT_EMAIL/" /etc/fail2ban/jail.conf
sed -i 's/action = %(action_)s/action = %(action_mwl)s/' /etc/fail2ban/jail.conf
}

function install_secpatches {

    # -------------------------------------------
    # Configure Security Patches (PHP7)
    # -------------------------------------------

    # -------------------------------------------
    # SSH Stuff
    # -------------------------------------------

    SSH_KEY=$(whiptail --title "Desgyz NextCloud Installer" --inputbox "What is your SSH Key? " 8 93 3>&1 1>&2 2>&3)

    echo "-------------------------------------------"
    echo "Adding SSH Key"
    echo "-------------------------------------------"

    mkdir -p /root/.ssh
    chmod 600 /root/.ssh
    echo $SSH_KEY > /root/.ssh/authorized_keys
    chmod 700 /root/.ssh/authorized_keys

    SSH_PORT=$(whiptail --title "Desgyz NextCloud Installer" --inputbox "What port would you like SSH to be on? " 8 93 3>&1 1>&2 2>&3)
    
    echo "-------------------------------------------"
    echo "Changing SSH Configs"
    echo "-------------------------------------------"
sed -i "s/Port 22/Port $SSH_PORT/" /etc/ssh/sshd_config
sed -i "s/#PasswordAuthentication yes/PasswordAuthentication no/" /etc/ssh/sshd_config
# -------------------------------------------
    # Firewall Stuff
    # -------------------------------------------
    
    echo "-------------------------------------------"
    echo "Editing Firewall"
    echo "-------------------------------------------"

ufw default allow outgoing
ufw default deny incoming
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow $SSH_PORT/tcp
ufw enable
ufw status

# -------------------------------------------
    # FS Stuff
    # -------------------------------------------
    
    echo "-------------------------------------------"
    echo "Editing fstab"
    echo "-------------------------------------------"
echo "
tmpfs     /run/shm     tmpfs     defaults,noexec,nosuid     0     0" >> /etc/fstab
# -------------------------------------------
    # SysCtl Stuff
    # -------------------------------------------

    echo "-------------------------------------------"
    echo "Editing SYSCTL"
    echo "-------------------------------------------"

sed -i 's/#net.ipv4.conf.default.rp_filter=1/net.ipv4.conf.all.rp_filter = 1/' /etc/sysctl.conf
sed -i 's/#net.ipv4.conf.all.rp_filter=1/net.ipv4.conf.default.rp_filter = 1/' /etc/sysctl.conf
echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf
sed -i 's/#net.ipv4.conf.all.accept_source_route = 0/net.ipv4.conf.all.accept_source_route = 0/' /etc/sysctl.conf
sed -i 's/#net.ipv6.conf.all.accept_source_route = 0/net.ipv6.conf.all.accept_source_route = 0/' /etc/sysctl.conf
echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
sed -i 's/#net.ipv4.conf.all.send_redirects = 0/net.ipv4.conf.all.send_redirects = 0/' /etc/sysctl.conf
echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf
sed -i 's/#net.ipv4.tcp_syncookies=1/net.ipv4.tcp_syncookies = 1/' /etc/sysctl.conf
echo "net.ipv4.tcp_max_syn_backlog = 2048" >> /etc/sysctl.conf
echo "net.ipv4.tcp_synack_retries = 2" >> /etc/sysctl.conf
echo "net.ipv4.tcp_syn_retries = 5" >> /etc/sysctl.conf
sed -i 's/#net.ipv4.conf.all.log_martians = 1/net.ipv4.conf.all.log_martians = 1/' /etc/sysctl.conf
echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.conf
sed -i 's/#net.ipv4.conf.all.accept_redirects = 0/net.ipv4.conf.all.accept_redirects = 0/' /etc/sysctl.conf
sed -i 's/#net.ipv6.conf.all.accept_redirects = 0/net.ipv6.conf.all.accept_redirects = 0/' /etc/sysctl.conf
echo "net.ipv4.conf.default.accept_redirects = 0 " >> /etc/sysctl.conf
echo "net.ipv6.conf.default.accept_redirects = 0 " >> /etc/sysctl.conf
echo "net.ipv4.icmp_echo_ignore_all = 1" >> /etc/sysctl.conf
sysctl -p

# -------------------------------------------
    # Host file Stuff
    # -------------------------------------------

echo "-------------------------------------------"
    echo "Editing Hosts"
    echo "-------------------------------------------"
rm -R /etc/host.conf
echo "
order bind,hosts
multi on
nospoof on" >> /etc/host.conf
# -------------------------------------------
    # PHP Stuff
    # -------------------------------------------
PHP_SESSION_ID=$(whiptail --title "Desgyz NextCloud Installer" --inputbox "What is the PHP Session ID? " 8 93 3>&1 1>&2 2>&3)
    
    echo "-------------------------------------------"
    echo "Patching PHP"
    echo "-------------------------------------------"

echo "register_globals = Off" >> /etc/php/7.0/fpm/php.ini
sed -i 's/html_errors = On/html_errors = Off/' /etc/php/7.0/fpm/php.ini
echo "magic_quotes_gpc = Off" >> /etc/php/7.0/fpm/php.ini
sed -i 's/mail.add_x_header = On/mail.add_x_header = Off' /etc/php/7.0/fpm/php.ini
sed -i "s/session.name = PHPSESSID/session.name = $PHP_SESSION_ID/" /etc/php/7.0/fpm/php.ini
sed -i 's/disable_functions = pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,/disable_functions = pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,exec,system,shell_exec,passthru/' /etc/php/5.6/fpm/php.ini

# -------------------------------------------
    # Fail2Ban Stuff
    # -------------------------------------------
ALERT_EMAIL=$(whiptail --title "Desgyz NextCloud Installer" --inputbox "What is your email for alerts? " 8 93 3>&1 1>&2 2>&3)
    
    echo "-------------------------------------------"
    echo "Installing Fail2Ban"
    echo "-------------------------------------------"
apt install fail2ban
    
    echo "-------------------------------------------"
    echo "Setting up Fail2Ban"
    echo "-------------------------------------------"
    
echo "
[sshd]

enabled  = true
port     = $SSH_PORT
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 3" >> /etc/fail2ban/jail.conf
sed -i "s/destemail = root@localhost/destemail = $ALERT_EMAIL/" /etc/fail2ban/jail.conf
sed -i 's/action = %(action_)s/action = %(action_mwl)s/' /etc/fail2ban/jail.conf
}

# -------------------------------------------
# Installation Selections
# -------------------------------------------

whiptail --ok-button "Install" --title "Desgyz NextCloud Installer" --radiolist \
"Choose what you want to install:" 20 78 9 \
"1" "NextCloud+MySQL+PHP5.6+CODE+SECPATCHES" off \
"2" "NextCloud+MySQL+PHP5.6+SECPATCHES" off \
"3" "NextCloud+MySQL+PHP5.6+CODE" off \
"4" "NextCloud+MySQL+PHP5.6" off \
"5" "NextCloud+MySQL+PHP7+CODE+SECPATCHES" off \
"6" "NextCloud+MySQL+PHP7+SECPATCHES" off \
"7" "NextCloud+MySQL+PHP7+CODE" off \
"8" "NextCloud+MySQL+PHP7" off 2>results 

echo "$(cat results)"

if grep -Fxq "1" results
then

    echo "PHP5CODESEC"

    # -------------------------------------------
    # Initiate the functions
    # -------------------------------------------
    
    whiptail --title "Desgyz NextCloud Installer" --msgbox " \n This function does not work! You may or may not of broken things! \n " 8 44\
    exit 1
    #install_nextcloud
    #install_mysql
    #install_caddy
    #install_php5.6 
    #install_code
    #config_caddyphp5.6
    #install_secpatches5.6
    
    # -------------------------------------------
    # Finish the Installation with a restart
    # -------------------------------------------

    whiptail --title "Desgyz NextCloud Installer" --msgbox " \n This script will now reboot and automatically start NextCloud \n " 8 44
    reboot
fi

if grep -Fxq "2" results
then

    # -------------------------------------------
    # Initiate the functions
    # -------------------------------------------

    install_nextcloud
    install_mysql
    install_caddy
    install_php5.6 
    config_caddyphp5.6
    install_secpatches5.6
    
    # -------------------------------------------
    # Finish the Installation with a restart
    # -------------------------------------------

    whiptail --title "Desgyz NextCloud Installer" --msgbox " \n This script will now reboot and automatically start NextCloud \n " 8 44
    reboot
fi

if grep -Fxq "3" results
then

    # -------------------------------------------
    # Initiate the functions
    # -------------------------------------------
    
    #whiptail --title "Desgyz NextCloud Installer" --msgbox " \n This function does not work! You may or may not of broken things! \n " 8 44
    #exit 1
    install_nextcloud
    install_mysql
    install_caddy
    install_php5.6 
    install_code
    config_caddyphp5.6
    
    # -------------------------------------------
    # Finish the Installation with a restart
    # -------------------------------------------

    whiptail --title "Desgyz NextCloud Installer" --msgbox " \n This script will now reboot and automatically start NextCloud \n " 8 44
    reboot
fi
   
if grep -Fxq "4" results
then

    # -------------------------------------------
    # Initiate the functions
    # -------------------------------------------

    install_nextcloud
    install_mysql
    install_caddy
    install_php5.6 
    config_caddyphp5.6
    
    # -------------------------------------------
    # Finish the Installation with a restart
    # -------------------------------------------

    whiptail --title "Desgyz NextCloud Installer" --msgbox " \n This script will now reboot and automatically start NextCloud \n " 8 44
    reboot
    
if grep -Fxq "5" results
then

    echo "PHPCODESEC"

    # -------------------------------------------
    # Initiate the functions
    # -------------------------------------------

    whiptail --title "Desgyz NextCloud Installer" --msgbox " \n This function does not work! You may or may not of broken things! \n " 8 44\
    exit 1
    #install_nextcloud
    #install_mysql
    #install_caddy
    #install_php 
    #install_code
    #config_caddyphp
    #install_secpatches
fi

if grep -Fxq "6" results
then 
    # -------------------------------------------
    # Initiate the functions
    # -------------------------------------------
    
    install_nextcloud
    install_mysql
    install_caddy
    install_php
    config_caddyphp
    install_secpatches
    
    # -------------------------------------------
    # Finish the Installation with a restart
    # -------------------------------------------

    whiptail --title "Desgyz NextCloud Installer" --msgbox " \n This script will now reboot and automatically start NextCloud \n " 8 44
    reboot
fi

if grep -Fxq "7" results
then 

    echo "PHPCODE"

    # -------------------------------------------
    # Initiate the functions
    # -------------------------------------------

    whiptail --title "Desgyz NextCloud Installer" --msgbox " \n This function does not work! You may or may not of broken things! \n " 8 44
    #install_nextcloud
    #install_mysql
    #install_caddy
    #install_php 
    #install_code
    #config_caddyphp
    
    # -------------------------------------------
    # Finish the Installation with a restart
    # -------------------------------------------

    whiptail --title "Desgyz NextCloud Installer" --msgbox " \n This script will now reboot and automatically start NextCloud \n " 8 44
    reboot
fi

if grep -Fxq "8" results
then
    # -------------------------------------------
    # Initiate the functions
    # -------------------------------------------
    
    install_nextcloud
    install_mysql
    install_caddy
    install_php
    config_caddyphp
    install_secpatches
    
    # -------------------------------------------
    # Finish the Installation with a restart
    # -------------------------------------------

    whiptail --title "Desgyz NextCloud Installer" --msgbox " \n This script will now reboot and automatically start NextCloud \n " 8 44
    reboot
fi
