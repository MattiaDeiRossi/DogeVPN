FROM ubuntu
RUN apt -y update

RUN apt install -y \
    g++ \
    cmake \
    git \
    curl \
    python3 \
    build-essential \
    libssl-dev \
    iproute2 \
    tcpdump \
    net-tools

# copy and build
WORKDIR /server
ADD lib/ /lib
ADD server/ .
RUN rm build/ -r; mkdir build; cd build; cmake ..; make; cd ..