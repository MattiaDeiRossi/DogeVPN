#!/bin/bash

# NOTE: 
#   Of course this script is really bad (creating files for state management? Really?),
#   but no other ideas came up!

# Remove already running containers

docker stop $(docker ps -q)
docker container prune -f   # Remove all stopped containers from the system
docker image prune -f       # Removes dangling images, which are not associated with any container and don't have tags
docker network prune -f     # Remove unused networks
docker volume prune -f      # Removes all anonymous volumes not used by any containers

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
    # Attach terminal's standard input, output, and error.
    # Need to install dbus-x11 for running gnome-terminal command easily.
    echo "$cn" > "holder.txt"
    gnome-terminal -- sh -c 'sudo docker attach $(head -n 1 holder.txt); echo $$ >> opened_bashpids.txt; $SHELL'
done

rm "holder.txt"