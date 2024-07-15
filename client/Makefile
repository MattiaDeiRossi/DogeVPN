all: 
	g++ client.cpp aes.c ../lib/utils.cpp ../lib/ssl_utils.cpp ../lib/socket_utils.cpp ../lib/vpn_data_utils.cpp ../lib/encryption.cpp -lssl -lcrypto -o client
clean: 
	rm client