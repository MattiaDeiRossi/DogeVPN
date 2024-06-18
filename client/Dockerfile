FROM ubuntu
RUN apt -y update

RUN apt install -y \
    g++ \
    cmake \
    git \
    curl\
    python3\
    build-essential\
    libssl-dev

# copy and build
WORKDIR /client
ADD . .
# RUN make all