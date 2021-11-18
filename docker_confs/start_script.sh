#!/bin/bash
# setup github SSH keys
mkdir -p ~/.ssh && ssh-keyscan github.com >> ~/.ssh/known_hosts
# handle user SSH keys
if [ "$INPUT_SSHKEY" ];
then
    if [ "$INPUT_SSHKEYNAME" ];
    then
        filename="/.ssh/$INPUT_SSHKEYNAME"
        echo $INPUT_SSHKEY | base64 -d > ~/"$filename"
        chmod 600 ~/"$filename"
    else
        echo "ERROR: SSHKEY set with no SSHKEYNAME"
        exit 1
    fi
fi
# setup nginx
mkdir -p /data/nginx/cache
mv /nginx_config /etc/nginx/sites-available/default
B64KEY=$(echo -n "$INPUT_RPROXYUSER:$INPUT_RPROXYKEY" | base64 -w0)
AUTHLINE=$(echo -n "Basic $B64KEY")
sed -i "s/REPLACE/$AUTHLINE/g" /etc/nginx/sites-available/default
service nginx restart
# start the app
vanagon_action