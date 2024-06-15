#include "mongo.hpp"
// #include "../tcp_server.cpp"

int main(int argc, char const *argv[])
{
  //  if(argc < 2)
  //     return EXIT_FAILURE;

   mongo mongo("mongodb://user:pwd@10.5.0.5:27017/vpndb");
   mongo.add_user("0", "user1", "psw");
   mongo.get_users(); // print users

   std::cout<< mongo.is_present("user1", "psw") << std::endl;



  //  char const *mode = argv[1];
	// int return_val = MODE_DETECTION_ERROR;

	// if (is_clear_mode(mode)) {

	// 	// This will be deprecated, but initial setup won't consider encryption using OpenSSL.
	// 	return_val = start_clear_doge_vpn();
	// } else if (is_enrcypted_mode(mode)) {

	// 	// The final version.
	// 	return_val = start_encrypted_doge_vpn();
	// } else {

	// 	fprintf(stderr, "Failed to detect mode.\n");
	// }

	// return return_val;
}
