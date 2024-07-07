## Without docker compose
### To compile: 
```bash
rm build/ -r; mkdir build; cd build/
cmake ..
make; cd ..
```

### To run the server:
```bash
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
./build/vpnserver
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