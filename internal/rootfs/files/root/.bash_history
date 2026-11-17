apt update
apt upgrade -y
systemctl restart nginx
mysql -h db01.internal -u shop -p
cd /var/www/html
vim config.php
exit
