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

# installing mongocxx driver - connects c++ to mongo
RUN cd ~ \
    && curl -OL https://github.com/mongodb/mongo-cxx-driver/releases/download/r3.10.1/mongo-cxx-driver-r3.10.1.tar.gz\
    && tar -xzf mongo-cxx-driver-r3.10.1.tar.gz\
    && cd mongo-cxx-driver-r3.10.1/build \
    && cmake ..\
    -DCMAKE_BUILD_TYPE=Release\
    -DMONGOCXX_OVERRIDE_DEFAULT_INSTALL_PREFIX=OFF\
    && cmake --build .\
    && cmake --build . --target install

# copy and build
WORKDIR /server
ADD lib/ /lib
ADD server/ .
RUN mkdir build; cd build/ \
    && cmake .. \
    && make