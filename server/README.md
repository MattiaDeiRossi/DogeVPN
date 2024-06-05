
## To compile: 
```bash
cd DogeVPN/
mkdir build; cd build/
cmake ../server/
make
```

## To run the server:
```bash
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
$ ./main
```