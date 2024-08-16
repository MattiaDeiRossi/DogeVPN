#!/bin/bash

# NOTE: 
#   Of course this script is really bad (creating files for state management? Really?),
#   but no other ideas came up!

# Remove already running containers

docker stop $(docker ps -q)
docker container prune -f  # Remove all stopped containers from the system.
docker image prune -f      # Removes dangling images, which are not associated with any container and don't have tags.
docker network prune -f    # Remove unused networks

# Close all the opened terminals

if test -f opened_bashpids.txt; then

    cat opened_bashpids.txt | while read line 
    do
        kill -9 "$line"
    done

    rm "opened_bashpids.txt"
fi

# Start containers again

docker compose build
xhost +local:docker
docker compose up -d

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
    # the containers internal to the VPN must have this name 'server_host_*', where * is whatever.
    if [[ "$cn" == "server_host_"* ]]; then
        docker exec "$cn" sh -c 'ip route add 192.168.11.0/24 via 192.168.42.15'
    fi

    # Attach terminal's standard input, output, and error.
    # Need to install dbus-x11 for running gnome-terminal command easily.
    echo "$cn" > "holder.txt"
    gnome-terminal -- sh -c 'sudo docker attach $(head -n 1 holder.txt); echo $$ >> opened_bashpids.txt; $SHELL'
done

rm "holder.txt"