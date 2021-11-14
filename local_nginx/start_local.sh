#!/bin/zsh
B64KEY=$(echo -n "artifactory:$RPROXY_KEY" | base64)
AUTHLINE=$(echo -n "Basic $B64KEY")
cp ./nginx.conf ./nginx_secure.conf
mkdir cache
gsed -i "s/REPLACE/$AUTHLINE/g" ./nginx_secure.conf
CONFPATH="/Users/jeremy.mill/Documents/test-go-vanagon-action/local_nginx/nginx_secure.conf"
CACHEPATH="/Users/jeremy.mill/Documents/test-go-vanagon-action/local_nginx/cache/"
docker pull nginx:latest
docker run -p 8080:80 \
		-v $CONFPATH:/etc/nginx/conf.d/default.conf \
        -v $CACHEPATH:/data/nginx/cache \
	    --name localproxy -t nginx