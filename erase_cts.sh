#!/bin/bash

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