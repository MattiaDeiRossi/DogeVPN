#!/bin/bash

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