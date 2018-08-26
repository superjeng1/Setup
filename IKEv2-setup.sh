#!/bin/bash -e
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
export PATH

allVaribles="timezone email VPNHOST VPNUSERNAME cloudflareSecrets cloudflareSecretsPath VPNIPPOOL VPNPASSWORD VPNPASSWORD2 auth_email auth_key zone_identifier record_name"

timezone="Asia/Taipei"    # << Change This

email=" "                 # << Change This

VPNHOST=" "               # << Change This

VPNUSERNAME=" "           # << Change This

cloudflareSecrets="~/.secrets/certbot/cloudflare.ini" # << Maybe Change This
cloudflareSecretsPath="~/.secrets/certbot/"           # << Maybe Change This

VPNIPPOOL="10.10.10.0/24" # << Maybe Change This
VPNPASSWORD=" "           # << Change This
VPNPASSWORD2=" "          # << Change This and match "VPNPASSWORD"

auth_email="foo@example.org"   # << Change This
# The email used to login 'https://dash.cloudflare.com'

auth_key="fooAPIKey"           # << Change This
# Top right corner, "My profile" > "Global API Key"

zone_identifier="fooZoneId"    # << Change This
# Can be found in the "Overview" tab of your domain

record_name=${VPNHOST}         # << Linked with VPNHOST
# Which record you want to be synced

iosProfileName="IKEv2 VPN Configuration (${VPNHOST})"
iosVPNName="${VPNHOST}"

function exit_badly {
  echo $1
  exit 1
}

echo
echo "=== Script Start ==="
echo

[[ $(id -u) -eq 0 ]] || exit_badly "Please re-run as root (e.g. sudo ./path/to/this/script)"

echo
echo "--- Checking for varibles ---"
echo
for varibleName in $allVaribles
do
  if [[ "${!varibleName}" = " " ]]; then
    exit_badly "Varible '$varibleName' does not exists. Please enter it by editing this script!!"
  fi
done
if [[ $auth_email = "foo@example.org" ]]; then
  exit_badly "Varible 'auth_email' is still a default value. Please enter it by editing this script!!"
fi
if [[ $auth_key = "fooAPIKey" ]]; then
  exit_badly "Varible 'auth_key' is still a default value. Please enter it by editing this script!!"
fi
if [[ $zone_identifier = "fooZoneId" ]]; then
  exit_badly "Varible 'zone_identifier' is still a default value. Please enter it by editing this script!!"
fi

if [[ "$VPNPASSWORD" != "$VPNPASSWORD2" ]]; then
  exit_badly "Passwords didn't match -- please edit VPNPASSWORD and VPNPASSWORD2 in this script so they match."
fi

echo
echo "All Varibles are Setup correctly."
echo

# Pick up and continue with BBR installation
if [[ $(lsmod |grep 'bbr') ]]; then
  if [[ ! $(lsmod |grep 'bbr_powered') ]]; then
    echo
    echo "--- Continuing on BBR installation ---"
    echo
    wget -qO 'BBR_POWERED.sh' 'https://moeclub.org/attachment/LinuxShell/BBR_POWERED.sh'
    bash BBR_POWERED.sh
    rm ~/raninstallbbr
    read -s -p "All setup is completed, press [Return] to reboot, or Ctrl-C to exit..."
    reboot
    exit 0
  else
    exit_badly "BBR installation is already finished before!!"
  fi
fi

echo
echo "--- Updating and installing software ---"
echo

export DEBIAN_FRONTEND=noninteractive

# AppArmor
if ! [ -x "$(command -v aa-status)" ]; then
  echo "AppArmor Setup"
  echo
  echo "Please RE-Run this script without setting up AppArmor after rebooting to continue with the rest of the setup."
  read -n 1 -s -r -p "Press any key to continue, or Ctrl-C to abort..."
  apt-get -o Acquire::ForceIPv4=true update
  apt-get install -y apparmor apparmor-utils
  mkdir -p /etc/default/grub.d
  echo 'GRUB_CMDLINE_LINUX_DEFAULT="$GRUB_CMDLINE_LINUX_DEFAULT apparmor=1 security=apparmor"' | tee /etc/default/grub.d/apparmor.cfg
  update-grub
  reboot
fi

#export LANGUAGE=en_US.UTF-8
#export LANG=en_US.UTF-8
#export LC_ALL=en_US.UTF-8
#locale-gen --purge en_US.UTF-8
#echo -e 'LANG="en_US.UTF-8"\nLANGUAGE="en_US.UTF-8"\nLC_ALL="en_US.UTF-8"' > /etc/default/locale

echo "deb http://ftp.debian.org/debian stretch-backports main
deb-src http://ftp.debian.org/debian stretch-backports main
deb http://security.debian.org/debian-security jessie/updates main
deb-src http://security.debian.org/debian-security jessie/updates main
" >> /etc/apt/sources.list
apt-get -o Acquire::ForceIPv4=true update && apt-get upgrade -y

echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
#echo strongswan-starter strongswan/runlevel_changes note | debconf-set-selections # Did not work.
#echo strongswan-starter strongswan/runlevel_changes seen true | debconf-set-selections # Did not work.

apt-get install -yq strongswan libstrongswan-standard-plugins strongswan-libcharon libcharon-extra-plugins moreutils iptables-persistent dnsutils uuid-runtime ca-certificates apparmor apparmor-utils libssl1.0.0 python3-pip golang-go make curl
apt-get install certbot -t stretch-backports -y
pip3 install certbot-dns-cloudflare

echo
echo "--- Configuring timezone ---"
echo
date
ln -fs /usr/share/zoneinfo/${timezone} /etc/localtime
dpkg-reconfigure -f noninteractive tzdata


echo
echo "--- Configuring timedatectl ---"
echo
timedatectl set-ntp true
cat <<'EOF' >> /etc/systemd/timesyncd.conf
NTP=time1.google.com time2.google.com time3.google.com time4.google.com
FallbackNTP=time1.google.com time2.google.com time3.google.com time4.google.com
EOF


echo
echo "--- Configuring CloudFlare DDNS ---"
echo

touch /var/log/cfupdater.log
cat <<EOF > /usr/bin/cfupdater-v4
#!/bin/bash

# Forked by benkulbertis/cloudflare-update-record.sh
# CHANGE THESE
auth_email="${auth_email}"            # The email used to login 'https://dash.cloudflare.com'
auth_key="${auth_key}"   # Top right corner, "My profile" > "Global API Key"
zone_identifier="${zone_identifier}" # Can be found in the "Overview" tab of your domain
record_name="${record_name}"                     # Which record you want to be synced
EOF

cat <<'EOF' >> /usr/bin/cfupdater-v4
# DO NOT CHANGE LINES BELOW
ip=$(curl -s https://ipv4.icanhazip.com/)

# SCRIPT START
echo -n `date +"[%m/%d %H:%M:%S] "` >> /var/log/cfupdater.log
echo "[Cloudflare DDNS] Check Initiated" >> /var/log/cfupdater.log
echo -n `date +"[%m/%d %H:%M:%S] "` >> /var/log/cfupdater.log

# Seek for the record
record=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$zone_identifier/dns_records?name=$record_name" -H "X-Auth-Email: $auth_email" -H "X-Auth-Key: $auth_key" -H "Content-Type: application/json")

# Can't do anything without the record
if [[ $record == *"\"count\":0"* ]]; then
  >&2 echo -e "[Cloudflare DDNS] Record does not exist, perhaps create one first?"
  exit 1
fi

# Set existing IP address from the fetched record
old_ip=$(echo "$record" | grep -Po '(?<="content":")[^"]*' | head -1)

# Compare if they're the same
if [ $ip == $old_ip ]; then
  echo "[Cloudflare DDNS] IP has not changed." >> /var/log/cfupdater.log
  exit 0
fi

# Set the record identifier from result
record_identifier=$(echo "$record" | grep -Po '(?<="id":")[^"]*' | head -1)

# The execution of update
update=$(curl -s -X PUT "https://api.cloudflare.com/client/v4/zones/$zone_identifier/dns_records/$record_identifier" -H "X-Auth-Email: $auth_email" -H "X-Auth-Key: $auth_key" -H "Content-Type: application/json" --data "{\"id\":\"$zone_identifier\",\"type\":\"A\",\"proxied\":false,\"name\":\"$record_name\",\"content\":\"$ip\"}")

# The moment of truth
case "$update" in
*"\"success\":false"*)
  >&2 echo -e "[Cloudflare DDNS] Update failed for $record_identifier. DUMPING RESULTS:\n$update" >> /var/log/cfupdater.log
  exit 1;;
*)
  echo "[Cloudflare DDNS] IPv4 context '$ip' has been synced to Cloudflare." >> /var/log/cfupdater.log;;
esac
EOF

chmod 700 /usr/bin/cfupdater-v4

cat <<'EOF' > /etc/systemd/system/cfupdate.service
[Unit]
Description=Cloudflare DDNS service
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/bin/cfupdater-v4

[Install]
WantedBy=multi-user.target
EOF

chmod 644 /etc/systemd/system/cfupdate.service

cat <<'EOF' > /etc/systemd/system/cfupdate.timer
[Unit]
Description=Run cfupdate.service every ten seconds

[Timer]
OnCalendar=*:*:0/10
AccuracySec=1ms

[Install]
WantedBy=timers.target
EOF
chmod 644 /etc/systemd/system/cfupdate.timer

mkdir ~/systemd-timesyncd-wait/
cd ~/systemd-timesyncd-wait/
wget https://github.com/assisi/systemd-timesyncd-wait/raw/master/Makefile
wget https://github.com/assisi/systemd-timesyncd-wait/raw/master/systemd-timesyncd-wait.go
wget https://github.com/assisi/systemd-timesyncd-wait/raw/master/systemd-timesyncd-wait.service
wget https://github.com/assisi/systemd-timesyncd-wait/raw/master/systemd-timesyncd-wait.socket
wget https://github.com/assisi/systemd-timesyncd-wait/raw/master/systemd-timesyncd-wrap.go
wget https://github.com/assisi/systemd-timesyncd-wait/raw/master/systemd-timesyncd.service.d-wait.conf
make
make install
cd ~/

cat <<'EOF' >> /lib/systemd/system/timers.target
Requires=systemd-timesyncd-wait.service
EOF

#systemctl daemon-reload
systemctl enable cfupdate.timer
systemctl start cfupdate.timer
systemctl status cfupdate.timer

echo "Waiting for 11 sec..."
sleep 11

echo
echo "--- Configuration: VPN settings ---"
echo

echo "** Note: hostname must resolve to this machine already, to enable Let's Encrypt certificate setup **"

VPNHOST_R="$(echo $VPNHOST | awk -F . '{print $4"."$3"."$2"."$1}')"
VPNHOSTIP=$(dig -4 +short "$VPNHOST")
[[ -n "$VPNHOSTIP" ]] || exit_badly "Cannot resolve VPN hostname, aborting"

ETH0ORSIMILAR=$(ip route get 1.1.1.1 | awk -- '{printf $5}')
IP=$(ifdata -pa $ETH0ORSIMILAR)

echo
echo "Network interface: ${ETH0ORSIMILAR}"
echo "External IP: ${IP}"

if [[ "$IP" != "$VPNHOSTIP" ]]; then
  echo "Warning: $VPNHOST resolves to $VPNHOSTIP, not $IP"
  echo "Either you are behind NAT, or something is wrong (e.g. hostname points to wrong IP, CloudFlare proxying shenanigans, ...)"
  read -s -p "Press [Return] to continue, or Ctrl-C to abort" DUMMYVAR
fi

echo
echo
echo "--- Configuring firewall ---"
echo

IF=$(ip route get 1.1.1.1 | awk -- '{printf $5}')

iptables -P INPUT   ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT  ACCEPT

iptables -t nat -F
iptables -t mangle -F
iptables -F
iptables -X

# DDOS Protection
### 1: Drop invalid packets ###
iptables -t mangle -A PREROUTING -m conntrack --ctstate INVALID -j DROP

### 2: Drop TCP packets that are new and are not SYN ###
iptables -t mangle -A PREROUTING -p tcp ! --syn -m conntrack --ctstate NEW -j DROP

### 3: Drop SYN packets with suspicious MSS value ###
iptables -t mangle -A PREROUTING -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -j DROP

### 4: Block packets with bogus TCP flags ###
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,ACK FIN -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,URG URG -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,FIN FIN -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,PSH PSH -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL ALL -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL NONE -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP

### 6: Drop ICMP (you usually don't need this protocol) ###
iptables -t mangle -A PREROUTING -p icmp -j DROP

### 7: Drop fragments in all chains ###
#iptables -t mangle -A PREROUTING -f -j DROP

### 8: Limit connections per source IP ###
iptables -A INPUT -p tcp -m connlimit --connlimit-above 111 -j REJECT --reject-with tcp-reset

### 9: Limit RST packets ###
iptables -A INPUT -p tcp --tcp-flags RST RST -m limit --limit 5/s --limit-burst 5 -j ACCEPT
iptables -A INPUT -p tcp --tcp-flags RST RST -j DROP

### 10: Limit new TCP connections per second per source IP ###
iptables -A INPUT -p tcp -m conntrack --ctstate NEW -m limit --limit 60/s --limit-burst 20 -j ACCEPT
iptables -A INPUT -p tcp -m conntrack --ctstate NEW -j DROP

### 5: Block spoofed packets ###
iptables -t mangle -A PREROUTING -s $VPNIPPOOL -j ACCEPT
iptables -t mangle -A PREROUTING -s 224.0.0.0/3 -j DROP
iptables -t mangle -A PREROUTING -s 169.254.0.0/16 -j DROP
iptables -t mangle -A PREROUTING -s 172.16.0.0/12 -j DROP
iptables -t mangle -A PREROUTING -s 192.0.2.0/24 -j DROP
iptables -t mangle -A PREROUTING -s 192.168.0.0/16 -j DROP
iptables -t mangle -A PREROUTING -s 10.0.0.0/8 -j DROP
iptables -t mangle -A PREROUTING -s 0.0.0.0/8 -j DROP
iptables -t mangle -A PREROUTING -s 240.0.0.0/5 -j DROP
iptables -t mangle -A PREROUTING -s 127.0.0.0/8 ! -i lo -j DROP

# Security
### SSH brute-force protection ###
iptables -A INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -m recent --set
iptables -A INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 10 -j DROP

### Protection against port scanning ###
iptables -N port-scanning
iptables -A port-scanning -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s --limit-burst 2 -j RETURN
iptables -A port-scanning -j DROP


# INPUT
# accept everything
#iptables -A INPUT -j ACCEPT
# accept anything already accepted
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
#iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED --j ACCEPT
# accept anything on the loopback interface
iptables -A INPUT -i lo -j ACCEPT

# drop invalid packets
iptables -A INPUT -m state --state INVALID -j DROP

# rate-limit repeated new requests from same IP to any ports
iptables -I INPUT -i $IF -m state --state NEW -m recent --set
iptables -I INPUT -i $IF -m state --state NEW -m recent --update --seconds 60 --hitcount 255 -j DROP

# accept (non-standard) SSH
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# accept SSR
#iptables -A INPUT -p tcp --dport 60443 -j ACCEPT

# VPN

# accept IPSec/NAT-T for VPN (ESP not needed with forceencaps, as ESP goes inside UDP)
iptables -A INPUT -p udp --dport  500 -j ACCEPT
iptables -A INPUT -p udp --dport 4500 -j ACCEPT

# forward VPN traffic anywhere
iptables -A FORWARD --match policy --pol ipsec --dir in  --proto esp -s $VPNIPPOOL -j ACCEPT
iptables -A FORWARD --match policy --pol ipsec --dir out --proto esp -d $VPNIPPOOL -j ACCEPT

# reduce MTU/MSS values for dumb VPN clients
iptables -t mangle -A FORWARD --match policy --pol ipsec --dir in -s $VPNIPPOOL -o $IF -p tcp -m tcp --tcp-flags SYN,RST SYN -m tcpmss --mss 1361:1536 -j TCPMSS --set-mss 1360

# masquerade VPN traffic over eth0 etc.
iptables -t nat -A POSTROUTING -s $VPNIPPOOL -o $IF -m policy --pol ipsec --dir out -j ACCEPT  # exempt IPsec traffic from masquerading
#iptables -t nat -A POSTROUTING -s $VPNIPPOOL -o $ETH0ORSIMILAR -j SNAT --to-source $VPNHOSTIP
iptables -t nat -A POSTROUTING -o $IF -j MASQUERADE

# fall through to drop any other input and forward traffic

iptables -A INPUT -j DROP
iptables -A FORWARD -j DROP

dpkg-reconfigure -f noninteractive iptables-persistent

echo
echo "--- Configuring RSA certificates ---"
echo

mkdir -p ${cloudflareSecretsPath}
cat <<EOF > ${cloudflareSecrets}
# Cloudflare API credentials used by Certbot
# Readme: https://certbot-dns-cloudflare.readthedocs.io/en/latest/
dns_cloudflare_email = ${auth_email}
dns_cloudflare_api_key = ${auth_key}
EOF
chmod 600 ${cloudflareSecrets}

mkdir -p /etc/letsencrypt

echo 'rsa-key-size = 4096
pre-hook = /sbin/iptables -I INPUT -p tcp --dport 80 -j ACCEPT
post-hook = /sbin/iptables -D INPUT -p tcp --dport 80 -j ACCEPT
renew-hook = /usr/sbin/ipsec reload && /usr/sbin/ipsec secrets
' > /etc/letsencrypt/cli.ini

# certbot certonly --non-interactive --agree-tos --standalone --preferred-challenges http --email ${email} -d $VPNHOST
certbot certonly --non-interactive --agree-tos -m ${email} --dns-cloudflare --dns-cloudflare-credentials ${cloudflareSecrets} --dns-cloudflare-propagation-seconds 60 -d $VPNHOST

ln -f -s /etc/letsencrypt/live/$VPNHOST/cert.pem    /etc/ipsec.d/certs/cert.pem
ln -f -s /etc/letsencrypt/live/$VPNHOST/privkey.pem /etc/ipsec.d/private/privkey.pem
ln -f -s /etc/letsencrypt/live/$VPNHOST/chain.pem   /etc/ipsec.d/cacerts/chain.pem

grep -Fq 'Setup by setup.sh' /etc/apparmor.d/local/usr.lib.ipsec.charon || echo "
# Setup by setup.sh
/etc/letsencrypt/archive/${VPNHOST}/* r,
" >> /etc/apparmor.d/local/usr.lib.ipsec.charon

aa-status --enabled && invoke-rc.d apparmor reload

echo
echo "--- Configuring VPN ---"
echo

# ip_forward is for VPN
# ip_no_pmtu_disc is for UDP fragmentation
# others are for security

grep -Fq 'Setup by setup.sh' /etc/sysctl.conf || echo '
# Setup by setup.sh
net.ipv4.ip_forward = 1
net.ipv4.ip_no_pmtu_disc = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
' >> /etc/sysctl.conf

sysctl -p

# these ike and esp settings are tested on Mac 10.12, iOS 10 and Windows 10
# iOS/Mac with appropriate configuration profiles use AES_GCM_16_256/PRF_HMAC_SHA2_256/ECP_521 
# Windows 10 uses AES_CBC_256/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/ECP_384 

echo "config setup
  strictcrlpolicy=yes
  uniqueids=never

conn roadwarrior
  auto=add
  compress=no
  type=tunnel
  keyexchange=ikev2
  fragmentation=yes
  forceencaps=yes
  ike=aes256gcm16-sha256-ecp521,aes256-sha256-ecp384!
  esp=aes256gcm16-sha256,aes256gcm16-ecp384!
  dpdaction=clear
  dpddelay=180s
  rekey=no
  left=%any
  leftid=@${VPNHOST}
  leftcert=cert.pem
  leftsendcert=always
  leftsubnet=0.0.0.0/0
  right=%any
  rightid=%any
  rightauth=eap-mschapv2
  eap_identity=%any
  rightdns=1.1.1.1,1.0.0.1
  rightsourceip=${VPNIPPOOL}
  rightsendcert=never
" > /etc/ipsec.conf

echo "${VPNHOST} : RSA \"privkey.pem\"
${VPNUSERNAME} : EAP \""${VPNPASSWORD}"\"
" > /etc/ipsec.secrets

ipsec restart


echo
echo "--- Creating configuration files ---"
echo

cd /root/

cat << EOF > vpn-ios-or-mac.mobileconfig
<?xml version='1.0' encoding='UTF-8'?>
<!DOCTYPE plist PUBLIC '-//Apple//DTD PLIST 1.0//EN' 'http://www.apple.com/DTDs/PropertyList-1.0.dtd'>
<plist version='1.0'>
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>IKEv2</key>
      <dict>
        <key>AuthenticationMethod</key>
        <string>None</string>
        <key>ChildSecurityAssociationParameters</key>
        <dict>
          <key>EncryptionAlgorithm</key>
          <string>AES-256-GCM</string>
          <key>IntegrityAlgorithm</key>
          <string>SHA2-256</string>
          <key>DiffieHellmanGroup</key>
          <integer>21</integer>
          <key>LifeTimeInMinutes</key>
          <integer>1440</integer>
        </dict>
        <key>DeadPeerDetectionRate</key>
        <string>Medium</string>
        <key>DisableMOBIKE</key>
        <integer>0</integer>
        <key>DisableRedirect</key>
        <integer>0</integer>
        <key>EnableCertificateRevocationCheck</key>
        <integer>0</integer>
        <key>EnablePFS</key>
        <true/>
        <key>ExtendedAuthEnabled</key>
        <true/>
        <key>IKESecurityAssociationParameters</key>
        <dict>
          <key>EncryptionAlgorithm</key>
          <string>AES-256-GCM</string>
          <key>IntegrityAlgorithm</key>
          <string>SHA2-256</string>
          <key>DiffieHellmanGroup</key>
          <integer>21</integer>
          <key>LifeTimeInMinutes</key>
          <integer>1440</integer>
        </dict>
        <key>LocalIdentifier</key>
        <string>${VPNHOST}</string>
        <key>OnDemandEnabled</key>
        <integer>1</integer>
        <key>OnDemandRules</key>
        <array>
          <dict>
            <key>Action</key>
            <string>Connect</string>
          </dict>
        </array>
        <key>RemoteAddress</key>
        <string>${VPNHOST}</string>
        <key>RemoteIdentifier</key>
        <string>${VPNHOST}</string>
        <key>UseConfigurationAttributeInternalIPSubnet</key>
        <integer>0</integer>
      </dict>
      <key>IPv4</key>
      <dict>
        <key>OverridePrimary</key>
        <integer>1</integer>
      </dict>
      <key>PayloadDescription</key>
      <string>Configures VPN settings</string>
      <key>PayloadDisplayName</key>
      <string>VPN</string>
      <key>PayloadIdentifier</key>
      <string>com.apple.vpn.managed.$(uuidgen)</string>
      <key>PayloadType</key>
      <string>com.apple.vpn.managed</string>
      <key>PayloadUUID</key>
      <string>$(uuidgen)</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
      <key>Proxies</key>
      <dict>
        <key>HTTPEnable</key>
        <integer>0</integer>
        <key>HTTPSEnable</key>
        <integer>0</integer>
      </dict>
      <key>UserDefinedName</key>
      <string>${iosVPNName}</string>
      <key>VPNType</key>
      <string>IKEv2</string>
    </dict>
  </array>
  <key>PayloadDisplayName</key>
  <string>${iosProfileName}</string>
  <key>PayloadIdentifier</key>
  <string>${VPNHOST_R}.$(uuidgen)</string>
  <key>PayloadRemovalDisallowed</key>
  <false/>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadUUID</key>
  <string>$(uuidgen)</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
</dict>
</plist>
EOF

cat << EOF > vpn-ubuntu-client.sh
#!/bin/bash -e
if [[ \$(id -u) -ne 0 ]]; then echo "Please run as root (e.g. sudo ./path/to/this/script)"; exit 1; fi

read -p "VPN username (same as entered on server): " VPNUSERNAME
while true; do
read -s -p "VPN password (same as entered on server): " VPNPASSWORD
echo
read -s -p "Confirm VPN password: " VPNPASSWORD2
echo
[ "\$VPNPASSWORD" = "\$VPNPASSWORD2" ] && break
echo "Passwords didn't match -- please try again"
done

apt-get install -y strongswan libstrongswan-standard-plugins libcharon-extra-plugins
apt-get install -y libcharon-standard-plugins || true  # 17.04+ only

ln -f -s /etc/ssl/certs/DST_Root_CA_X3.pem /etc/ipsec.d/cacerts/

grep -Fq 'Setup by setup.sh' /etc/ipsec.conf || echo "
# Setup by setup.sh
conn ikev2vpn
        ikelifetime=60m
        keylife=20m
        rekeymargin=3m
        keyingtries=1
        keyexchange=ikev2
        ike=aes256gcm16-sha256-ecp521!
        esp=aes256gcm16-sha256!
        leftsourceip=%config
        leftauth=eap-mschapv2
        eap_identity=\${VPNUSERNAME}
        right=${VPNHOST}
        rightauth=pubkey
        rightid=@${VPNHOST}
        rightsubnet=0.0.0.0/0
        auto=add  # or auto=start to bring up automatically
" >> /etc/ipsec.conf

grep -Fq 'Setup by setup.sh' /etc/ipsec.secrets || echo "
# Setup by setup.sh
\${VPNUSERNAME} : EAP \"\${VPNPASSWORD}\"
" >> /etc/ipsec.secrets

ipsec restart
sleep 5  # is there a better way?

echo "Bringing up VPN ..."
ipsec up ikev2vpn
ipsec statusall

echo
echo -n "Testing IP address ... "
VPNIP=\$(dig -4 +short ${VPNHOST})
ACTUALIP=\$(curl -s ifconfig.co)
if [[ "\$VPNIP" == "\$ACTUALIP" ]]; then echo "PASSED (IP: \${VPNIP})"; else echo "FAILED (IP: \${ACTUALIP}, VPN IP: \${VPNIP})"; fi

echo
echo "To disconnect: ipsec down ikev2vpn"
echo "To resconnect: ipsec up ikev2vpn"
echo "To connect automatically: change auto=add to auto=start in /etc/ipsec.conf"
EOF

cat << EOF > vpn-instructions.txt
== iOS and macOS ==

A configuration profile is attached as vpn-ios-or-mac.mobileconfig — simply open this to install. You will be asked for your device PIN or password, and your VPN username and password, not necessarily in that order.


== Windows ==

You will need Windows 10 Pro or above. Please run the following commands in PowerShell:

Add-VpnConnection -Name "${VPNHOST}" \`
  -ServerAddress "${VPNHOST}" \`
  -TunnelType IKEv2 \`
  -EncryptionLevel Maximum \`
  -AuthenticationMethod EAP \`
  -RememberCredential

Set-VpnConnectionIPsecConfiguration -ConnectionName "${VPNHOST}" \`
  -AuthenticationTransformConstants GCMAES256 \`
  -CipherTransformConstants GCMAES256 \`
  -EncryptionMethod AES256 \`
  -IntegrityCheckMethod SHA256 \`
  -DHGroup ECP384 \`
  -PfsGroup ECP384 \`
  -Force


== Android ==

Download the strongSwan app from the Play Store: https://play.google.com/store/apps/details?id=org.strongswan.android

Server: ${VPNHOST}
VPN Type: IKEv2 EAP (Username/Password)
Username and password: as configured on the server
CA certificate: Select automatically


== Ubuntu ==

A bash script to set up strongSwan as a VPN client is attached as vpn-ubuntu-client.sh. You will need to chmod +x and then run the script as root.

EOF

cd /etc/letsencrypt/archive/$VPNHOST/
openssl smime \
-sign \
-signer cert1.pem \
-inkey privkey1.pem \
-certfile chain1.pem \
-nodetach \
-outform der \
-in /root/vpn-ios-or-mac.mobileconfig \
-out /root/vpn-ios-or-mac-signed.mobileconfig

echo
echo "--- How to connect ---"
echo
echo "Connection instructions can be found in your home directory"

read -s -p "Setup is almost finished. Press [Return] to Install BBR now and Reboot. Ctrl-C to finish setup without installing BBR..." DUMMYVAR
echo
read -n 1 -s -r -p "Please RE-RUN this script after reboot. It will automaticly finish the installation. Press any key to continue..."
touch ~/raninstallbbr
wget -qO 'BBR.sh' 'https://moeclub.org/attachment/LinuxShell/BBR.sh'
bash BBR.sh -f

#echo
#echo "Shadowsocks installation started"
#echo
#cd /root/
#wget https://raw.githubusercontent.com/teddysun/shadowsocks_install/master/shadowsocks-all.sh
#chmod +x shadowsocks-all.sh
#./shadowsocks-all.sh 2>&1 | tee shadowsocks-all.log


# necessary for IKEv2?
# Windows: https://support.microsoft.com/en-us/kb/926179
# HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PolicyAgent += AssumeUDPEncapsulationContextOnSendRule, DWORD = 2
