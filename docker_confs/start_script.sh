#!/bin/bash
# setup github SSH keys
mkdir -p ~/.ssh
# write known hosts
echo "# github.com:22 SSH-2.0-babeld-a73e1397" >> ~/.ssh/known_hosts
echo "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl" >> ~/.ssh/known_hosts
echo "# github.com:22 SSH-2.0-babeld-a73e1397" >> ~/.ssh/known_hosts
echo "github.com ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmdnm9tUDbO9IDSwBK6TbQa+PXYPCPy6rbTrTtw7PHkccKrpp0yVhp5HdEIcKr6pLlVDBfOLX9QUsyCOV0wzfjIJNlGEYsdlLJizHhbn2mUjvSAHQqZETYP81eFzLQNnPHt4EVVUh7VfDESU84KezmD5QlWpXLmvU31/yMf+Se8xhHTvKSCZIFImWwoG6mbUoWf9nzpIoaSjB+weqqUUmpaaasXVal72J+UX2B+2RPW3RcT0eOzQgqlJL3RKrTJvdsjE3JEAvGq3lGHSZXy28G3skua2SmVi/w4yCE6gbODqnTWlg7+wC604ydGXA8VJiS5ap43JXiUFFAaQ==" >> ~/.ssh/known_hosts
echo "# github.com:22 SSH-2.0-babeld-a73e1397" >> ~/.ssh/known_hosts
echo "github.com ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2YB/++Tpockg=" >> ~/.ssh/known_hosts
chmod 600 ~/.ssh/known_hosts
# handle user SSH keys
if [ "$INPUT_SSHKEY" ];
then
    if [ "$INPUT_SSHKEYNAME" ];
    then
        filename="/.ssh/$INPUT_SSHKEYNAME"
        echo $INPUT_SSHKEY | base64 -d > ~/"$filename"
        chmod 600 ~/"$filename"
        export FullKnownHosts=`realpath -z ~/.ssh/known_hosts`
        export FullKeyPath=`realpath -z ~/.ssh/$INPUT_SSHKEYNAME`
        # git ssh command
        export GIT_SSH_COMMAND='ssh -i $FullKeyPath -o UserKnownHostsFile=$FullKnownHosts' 
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
