#!/bin/bash

cd DogeVPNGui/
rm build/ -r; mkdir build; cd build/
cmake ..; make
cd ..; cd ..