#!/bin/bash
mkdir -p /root/.ssh && ssh-keyscan github.com >> ~/.ssh/known_hosts
mkdir -p /data/nginx/cache
mv /nginx_config /etc/nginx/sites-available/default
B64KEY=$(echo -n "$INPUT_RPROXYUSER:$INPUT_RPROXYKEY" | base64 -w0)
AUTHLINE=$(echo -n "Basic $B64KEY")
sed -i "s/REPLACE/$AUTHLINE/g" /etc/nginx/sites-available/default
service nginx restart
vanagon_action