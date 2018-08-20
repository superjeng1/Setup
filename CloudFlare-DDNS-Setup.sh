#!/bin/bash -e
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
export PATH

RED='\033[0;31m'
NC='\033[0m' # No Color
GREEN='\033[0;32m'
bold=$(tput bold)
normal=$(tput sgr0)

function exit_badly {
  printf "$1"
  exit 1
}

function chk_root {
  if [[ "${EUID}" -ne 0 ]]; then
    exit_badly "Please re-run as root (e.g. sudo ./path/to/this/script)"
  fi
}

function interactive {
  printf "[${GREEN}${bold}輸入${NC}${normal}] 請輸入登入 CloudFlare 的電子郵箱："
  read auth_email

  printf "[${GREEN}${bold}輸入${NC}${normal}] 請前往 CloudFlare 尋找 API Key，方法如下\n"
  printf "       登入後請點選右上角的頭像，點選帳號郵箱\n"
  printf "       下方有個 Global API Key，對他旁邊的 View 按一下\n"
  printf "       跳出密碼視窗，輸入密碼登入。登入完畢後金鑰會出現\n"
  printf "       把它複製起來，並貼上到這裡："
  read auth_key

  printf "[${GREEN}${bold}輸入${NC}${normal}] 請前往 CloudFlare 尋找 Zone ID，方法如下\n"
  printf "       登入後左上位置的選單選HOME，\n"
  printf "       選擇想DDNS的網域名，點下去後\n"
  printf "       頁面中應該可以看到 Zone ID 點 Copy\n"
  printf "       然後貼到這裡："
  read zone_identifier

  printf "[${RED}${bold}提示${NC}${normal}] 請${RED}${bold}務必${NC}${normal}先前往 CloudFlare 添加想 DDNS 的域名的紀錄，但可隨便指向任意 IP\n"
  printf "[${GREEN}${bold}輸入${NC}${normal}] 請輸入想 DDNS 的域名全名（如：foo.example.com）："
  read record_name

  printf "[${GREEN}${bold}選擇${NC}${normal}] 請問更新頻率？（CloudFlare 的 API 要求限制為 1200次/秒，若共用 IP，請選較低的頻率）\n"
  printf "${RED}${bold}1.${NC}${normal} 3 秒\n"
  printf "${RED}${bold}2.${NC}${normal} 5 秒\n"
  printf "${RED}${bold}3.${NC}${normal} 10 秒\n"
  printf "${RED}${bold}4.${NC}${normal} 15 秒\n"
  printf "${RED}${bold}5.${NC}${normal} 20 秒\n"
  printf "${RED}${bold}6.${NC}${normal} 30 秒\n"
  printf "${RED}${bold}7.${NC}${normal} 1 分\n"
  printf "${RED}${bold}8.${NC}${normal} 2 分\n"
  printf "${RED}${bold}9.${NC}${normal} 5 分\n"
  printf "選擇 [預設：7]："
  read secondselect
  if [ -z "$secondselect" ]; then
    secondselect="7"
  fi
  getSeconds
  printf "[${GREEN}${bold}提示${NC}${normal}] 這樣就是我需要的全部資料了，請等待完成\n"
}

function getSeconds {
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
    seconds=0/1
    ;;
  "8")
    seconds=0/2
    ;;
  "9")
    seconds=0/5
    ;;
  *)
    exit_badly "[${RED}${bold}錯誤${NC}${normal}] 選擇錯誤！\n"
    ;;
  esac
}

function install_dependencies {
  printf "[${GREEN}${bold}配置${NC}${normal}] 開始安裝依賴（需要20秒到1分鐘，取決於網速和電腦速度，若之前全裝過則一瞬間完成）\n"
  apt-get update &> /dev/null
  apt-get install -y ca-certificates golang-go make grep curl &> /dev/null
  printf "[${GREEN}${bold}完成${NC}${normal}] 安裝依賴完成\n"
}

function set_timezone {
  printf "[${GREEN}${bold}配置${NC}${normal}] 開始設定時區\n"
  ln -fs /usr/share/zoneinfo/${timezone} /etc/localtime &> /dev/null
  dpkg-reconfigure -f noninteractive tzdata &> /dev/null
  printf "[${GREEN}${bold}完成${NC}${normal}] 時區設定完成\n"
}

function setup_ntp {
  printf "[${GREEN}${bold}配置${NC}${normal}] 開始設定NTP\n"
  timedatectl set-ntp true &> /dev/null
  cat <<'EOF' >> /etc/systemd/timesyncd.conf
NTP=time1.google.com time2.google.com time3.google.com time4.google.com
FallbackNTP=time1.google.com time2.google.com time3.google.com time4.google.com
EOF
  printf "[${GREEN}${bold}完成${NC}${normal}] NTP設定完成\n"
}

function generate_cfupdater_script {
printf "[${GREEN}${bold}配置${NC}${normal}] 開始生成 CloudFlare DDNS 腳本\n"
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
printf "[${GREEN}${bold}完成${NC}${normal}] CloudFlare DDNS 腳本生成完成\n"
}
function setup_systemd {
printf "[${GREEN}${bold}配置${NC}${normal}] 開始配置 Systemd\n"
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
curl -LJO https://github.com/assisi/systemd-timesyncd-wait/raw/master/Makefile &> /dev/null
curl -LJO https://github.com/assisi/systemd-timesyncd-wait/raw/master/systemd-timesyncd-wait.go &> /dev/null
curl -LJO https://github.com/assisi/systemd-timesyncd-wait/raw/master/systemd-timesyncd-wait.service &> /dev/null
curl -LJO https://github.com/assisi/systemd-timesyncd-wait/raw/master/systemd-timesyncd-wait.socket &> /dev/null
curl -LJO https://github.com/assisi/systemd-timesyncd-wait/raw/master/systemd-timesyncd-wrap.go &> /dev/null
curl -LJO https://github.com/assisi/systemd-timesyncd-wait/raw/master/systemd-timesyncd.service.d-wait.conf &> /dev/null
make &> /dev/null
make install &> /dev/null
cd ~/

cat <<'EOF' >> /lib/systemd/system/timers.target
Requires=systemd-timesyncd-wait.service
EOF
systemctl enable cfupdate.timer &> /dev/null
printf "[${GREEN}${bold}完成${NC}${normal}] Systemd 配置完成\n"
printf "[${GREEN}${bold}提示${NC}${normal}] 設置完成，計時器執行紀錄紀錄於 /var/log/cfupdater.log\n"
}
function start_systemd_timer {
printf "[${GREEN}${bold}啟動${NC}${normal}] 正在啟動 Systemd 計時器\n"
#systemctl daemon-reload
systemctl start cfupdate.timer
#systemctl status cfupdate.timer
printf "[${GREEN}${bold}啟動${NC}${normal}] 已啟動 Systemd 計時器\n"
}

printf "[${GREEN}${bold}開始${NC}${normal}] 腳本開始\n"
chk_root
interactive
install_dependencies
set_timezone
setup_ntp
generate_cfupdater_script
setup_systemd
start_systemd_timer
printf "[${GREEN}${bold}完成${NC}${normal}] 腳本完成\n"
exit 0
