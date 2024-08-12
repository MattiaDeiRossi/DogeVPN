#!/bin/bash

docker stop $(docker ps -aq)
docker rm $(docker ps -aq)
sudo docker network prune -f