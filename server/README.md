## Without docker compose
### To compile: 
```bash
mkdir build; cd build/
cmake ..
make
```

### To run the server:
```bash
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
$ ./build/main
```

## With docker compose
### build
```bash
docker compose build
```
### run
```bash
docker compose up --attach vpnserver
```