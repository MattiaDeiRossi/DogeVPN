#include "mongo.hpp"

int main()
{
   mongo mongo("mongodb://user:pwd@localhost:27017/vpndb");
   mongo.add_user("0", "user1", "psw");
   mongo.get_users();

   auto hash = mongo.hash_password("psw");
   std::cout<< mongo.is_present("user1", hash) << std::endl;
}
