## Without docker compose
### To compile: 
```bash
cd DogeVPNGui/
rm build/ -r; mkdir build; cd build/
cmake ..
make;
```
### To execute:
```bash
cd build/
./DogeVPNGui
```


## With docker compose
### To compile:
```bash
docker compose build
```

### To execute
```
xhost +local:docker
docker compose up
```
