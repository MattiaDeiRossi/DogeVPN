FROM ubuntu:latest
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y \
    cmake \
    build-essential \
    qtbase5-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /DogeVPN
ADD lib/ /DogeVPN/lib
ADD client/  /DogeVPN/client
ADD config.txt /DogeVPN/.

RUN cd client/DogeVPNGui/;\
    mkdir build;\
    cd build;\
    cmake ..;\
    make

ENTRYPOINT ["./client/DogeVPNGui/build/DogeVPNGui"]
