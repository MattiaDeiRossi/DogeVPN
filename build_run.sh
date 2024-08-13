#!/bin/bash

# Remove already running containers

docker stop $(docker ps -aq)
docker rm $(docker ps -aq)
sudo docker network prune -f

# Start containers again

sudo docker compose build
xhost +local:docker
sudo docker compose up -d

# Attach terminal's standard input, output, and error
# Need to install dbus-x11 for running gnome-terminal command easily

CONTAINER_NAMES=$(sudo docker ps --format "{{.Names}}")

for cn in $CONTAINER_NAMES
do
    echo "$cn" > "holder.txt"
    gnome-terminal -- sh -c 'sudo docker attach $(head -n 1 holder.txt); $SHELL'
done

rm "holder.txt"