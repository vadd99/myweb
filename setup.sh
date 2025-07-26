#!/bin/bash

# ========================
# AUTO INSTALL SCRIPT (Final Version)
# ========================

# 1. Update dan install dependensi
apt update && apt install -y python3 python3-pip nginx git curl software-properties-common

# 2. Install Gunicorn
pip3 install gunicorn

# 3. Clone project dari GitHub (branch master)
git clone -b master https://vadd99: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@github.com/vadd99/myweb.git /var/www/myweb

# 4. Set kepemilikan direktori
chown -R root:www-data /var/www/myweb

# 5. Buat file wsgi.py
cat <<EOF > /var/www/myweb/wsgi.py
from vadd import app

if __name__ == "__main__":
    app.run()
EOF

# 6. Buat systemd service untuk Gunicorn
cat <<EOF > /etc/systemd/system/myweb.service
[Unit]
Description=Gunicorn instance to serve Vadd VPN Store
After=network.target

[Service]
User=root
Group=www-data
WorkingDirectory=/var/www/myweb
Environment="PATH=/usr/local/bin"
ExecStart=/usr/local/bin/gunicorn --workers 3 --bind unix:/var/www/myweb/myweb.sock -m 007 wsgi:app
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# 7. Buat konfigurasi Nginx
cat <<EOF > /etc/nginx/sites-available/myweb
server {
    listen 80;
    server_name v.vadd.my.id;

    location / {
        proxy_pass http://unix:/var/www/myweb/myweb.sock;
        include proxy_params;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF

# 8. Aktifkan konfigurasi Nginx
ln -s /etc/nginx/sites-available/myweb /etc/nginx/sites-enabled/

# 9. Konfigurasi Firewall (SEBELUM service dijalankan)
ufw allow OpenSSH
ufw allow 'Nginx Full'
ufw --force enable

# 10. Reload systemd dan aktifkan service
systemctl daemon-reload
systemctl enable myweb
systemctl restart myweb

# 11. Restart nginx
systemctl restart nginx

# 12. Install Certbot dan setup SSL
apt install -y certbot python3-certbot-nginx

certbot --nginx --non-interactive --agree-tos --redirect --email v.vadd99@gmail.com -d v.vadd.my.id

# DONE
echo "==============================="
echo "INSTALLASI SELESAI!"
echo "Website aktif di: https://v.vadd.my.id"
echo "Firewall UFW aktif & port aman"
echo "==============================="