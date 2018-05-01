# webserver.confs

This is how we have installed and configured Nging using Let’s Encrypt to get an A+ 100% score on SSL Labs
and which HTTP headers we have added to our default website deployment to score an A+ on securityheaders.com

Deploying on a Debian 9 Stretch serve

sudo apt -y install nginx
sudo apt -y install python-certbot-nginx -t stretch-backports

certbot --nginx --rsa-key-size 4096 --no-redirect --staple-ocsp -d on-the-move.ml

In s/etc/nginx/sites-available/default we delete everything (including the certbot entries) and replace it with:

server {

		server_name on-the-move.ml;
		root /var/www/html;

		index index.html index.php;
		location / {
			try_files $uri $uri/ =404;
		}

		listen [::]:443 ssl ipv6only=on;
    listen 443 ssl;

		ssl_certificate /etc/letsencrypt/live/on-the-move.ml/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/on-the-move.ml/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;

    add_header Strict-Transport-Security "max-age=63072000; includeSubdomains; preload";
    ssl_trusted_certificate /etc/letsencrypt/live/on-the-move.ml/chain.pem;
    ssl_stapling on;
    ssl_stapling_verify on;

    #Security headers
    server_tokens off;
    add_header Referrer-Policy "no-referrer";
    add_header X-Frame-Options SAMEORIGIN;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://assets.zendesk.com img-src 'self' https://assets.zendesk.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://assets.zendesk.com; font-src 'self' https://themes.googleusercontent.com; frame-src https://assets.zendesk.com; object-src 'none'";
}

Next you need to edit /etc/letsencrypt/options-ssl-nginx.conf by replace all the content with:

ssl_session_cache shared:le_nginx_SSL:1m;
ssl_session_timeout 1440m;

ssl_protocols TLSv1.2;
ssl_ecdh_curve secp384r1:X25519:prime256v1;
ssl_prefer_server_ciphers on;

ssl_ciphers 'ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384::ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384';

And then you need to restart Nginx with sudo systemctl restart nginx
