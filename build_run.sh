#!/bin/bash

# NOTE: 
#   of course this script is really bad (creating files for state management? Really?),
#   but no other ideas came up!

# Remove already running containers

docker stop $(docker ps -aq)
docker rm $(docker ps -aq)
sudo docker network prune -f

# Close all the opened terminals

if test -f opened_bashpids.txt; then

    cat opened_bashpids.txt | while read line 
    do
        kill -9 "$line"
    done

    rm "opened_bashpids.txt"
fi

# Start containers again

sudo docker compose build
xhost +local:docker
sudo docker compose up -d

# Create file for saving pids

if ! test -f opened_bashpids.txt; then
  touch opened_bashpids.txt
fi

CONTAINER_NAMES=$(sudo docker ps --format "{{.Names}}")

for cn in $CONTAINER_NAMES
do
    # WTF? Well, the reason is this one:
    #   => ERROR [server_host_a 4/4] RUN ip route add 192.168.11.0/24 via 192.168.42.15
    #   > [server_host_a 4/4] RUN ip route add 192.168.11.0/24 via 192.168.42.15:
    #   RTNETLINK answers: Operation not permitted
    # So this horrible trick has been used. This requires a use of a convention: all 
    # the container internal to the VPN must have this name 'server_host_*', where * is whatever.
    if [[ "$cn" == "server_host_"* ]]; then
        sudo docker exec "$cn" sh -c 'ip route add 192.168.11.0/24 via 192.168.42.15'
    fi

    # Attach terminal's standard input, output, and error.
    # Need to install dbus-x11 for running gnome-terminal command easily.
    echo "$cn" > "holder.txt"
    gnome-terminal -- sh -c 'sudo docker attach $(head -n 1 holder.txt); echo $$ >> opened_bashpids.txt; $SHELL'
done

rm "holder.txt"