#!/bin/bash

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

# Attach terminal's standard input, output, and error
# Need to install dbus-x11 for running gnome-terminal command easily
# Create file for saving pids

if ! test -f opened_bashpids.txt; then
  touch opened_bashpids.txt
fi

CONTAINER_NAMES=$(sudo docker ps --format "{{.Names}}")

for cn in $CONTAINER_NAMES
do
    echo "$cn" > "holder.txt"
    gnome-terminal -- sh -c 'sudo docker attach $(head -n 1 holder.txt); echo $$ >> opened_bashpids.txt; $SHELL'
done

rm "holder.txt"