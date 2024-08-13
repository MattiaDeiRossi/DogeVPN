#!/bin/bash

docker stop $(docker ps -aq)
docker rm $(docker ps -aq)
sudo docker network prune -f

sudo docker compose build
xhost +local:docker
sudo docker compose up -d