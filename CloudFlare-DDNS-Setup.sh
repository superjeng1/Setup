 #!/bin/bash -e
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
export PATH

RED='\033[0;31m'
NC='\033[0m' # No Color
GREEN='\033[0;32m'
printf "[${GREEN}輸入${NC}] 請輸入登入 CloudFlare 的電子郵箱："
read auth_email

printf "[${GREEN}輸入${NC}] 請前往 CloudFlare 尋找 API Key，方法如下
       登入後請點選右上角的頭像，點選帳號郵箱
       下方有個 Global API Key，對他旁邊的 View 按一下
       跳出密碼視窗，輸入密碼登入。登入完畢後金鑰會出現
       把它複製起來，並貼上到這裡："
read auth_key

printf "[${GREEN}輸入${NC}] 請前往 CloudFlare 尋找 Zone ID，方法如下
       登入後左上位置的選單可以看到自己的網域名，
       選擇想DDNS的網域名，點下去後
       頁面中應該可以看到 Zone ID 點 Copy
       然後貼到這裡："
read zone_identifier

printf "[${GREEN}輸入${NC}] 請輸入想 DDNS 的域名全名（如：foo.example.com）："
read record_name

printf "[${GREEN}選擇${NC}] 請問更新頻率？（CloudFlare 的 API 要求限制為 1200次/秒，若共用 ip，請選較低的頻率）
${RED}1.${NC} 3 秒
${RED}2.${NC} 5 秒
${RED}3.${NC} 10 秒
${RED}4.${NC} 15 秒
${RED}5.${NC} 20 秒
${RED}6.${NC} 30 秒
${RED}7.${NC} 1 分
${RED}8.${NC} 2 分
${RED}9.${NC} 5 分
選擇 [預設：7]："
read secondselect
if [ -z "$secondselect" ]; then
secondselect="7"
fi

case "$secondselect" in
"1")
  seconds=*:0/3
  ;;
"2")
  seconds=*:0/5
  ;;
"3")
  seconds=*:0/10
  ;;
"4")
  seconds=*:0/15
  ;;
"5")
  seconds=*:0/20
  ;;
"6")
  seconds=*:0/30
  ;;
"7")
  seconds=1
  ;;
"8")
  seconds=2
  ;;
"9")
  seconds=5
  ;;
*)
  printf "[${RED}錯誤${NC}] 選擇錯誤！"
  exit 1
  ;;
esac

printf "[${GREEN}提示${NC}] 這樣就是我需要的全部資料了，請等待完成"
printf "[${GREEN}配置${NC}] 開始安裝依賴"
apt-get update &> /dev/null
apt-get install -y ca-certificates golang-go make grep wget curl &> /dev/null
printf "[${GREEN}完成${NC}] 安裝依賴完成"
printf "[${GREEN}配置${NC}] 開始設定時區"
ln -fs /usr/share/zoneinfo/${timezone} /etc/localtime &> /dev/null
dpkg-reconfigure -f noninteractive tzdata &> /dev/null
printf "[${GREEN}完成${NC}] 時區設定完成"

printf "[${GREEN}配置${NC}] 開始設定NTP"
timedatectl set-ntp true &> /dev/null
cat <<'EOF' >> /etc/systemd/timesyncd.conf
NTP=time1.google.com time2.google.com time3.google.com time4.google.com
FallbackNTP=time1.google.com time2.google.com time3.google.com time4.google.com
EOF
printf "[${GREEN}完成${NC}] NTP設定完成"

printf "[${GREEN}配置${NC}] 開始生成 CloudFlare DDNS 腳本"
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
printf "[${GREEN}完成${NC}] CloudFlare DDNS 腳本生成完成"
printf "[${GREEN}配置${NC}] 開始配置 Systemd"
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

cat <<EOF > /etc/systemd/system/cfupdate.timer
[Unit]
Description=Run cfupdate.service when the timer ticks
[Timer]
OnCalendar=*:${seconds}
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
systemctl enable cfupdate.timer
printf "[${GREEN}完成${NC}] Systemd 配置完成"
printf "[${GREEN}啟動${NC}] 正在啟動 Systemd 計時器"
#systemctl daemon-reload
systemctl start cfupdate.timer
#systemctl status cfupdate.timer
printf "[${GREEN}提示${NC}] 設置完成，計時器執行紀錄紀錄於 /var/log/cfupdater.log"
printf "[${GREEN}完成${NC}] 腳本完成"
exit 0
