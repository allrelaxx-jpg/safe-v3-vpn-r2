команда для установки через PuTTY:

curl -fsSL https://raw.githubusercontent.com/allrelaxx-jpg/safe-v3-vpn-r2/main/safe-v3-vpn-r2.sh -o /root/safe-v3-vpn-r2.sh && chmod +x /root/safe-v3-vpn-r2.sh && bash /root/safe-v3-vpn-r2.sh







Быстрые команды для внутренней проверки состояния:
iptables -nvL DOCKER-USER --line-numbers
iptables -nvL INPUT --line-numbers
systemctl status firewall-selfheal.timer --no-pager
tail -n 100 /var/log/firewall-selfheal/selfheal.log
