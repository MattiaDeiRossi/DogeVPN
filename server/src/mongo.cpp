#include <cstdint>
#include <iostream>
#include <vector>

#include <bsoncxx/builder/basic/document.hpp>
#include <bsoncxx/json.hpp>
#include <mongocxx/client.hpp>
#include <mongocxx/instance.hpp>
#include <mongocxx/stdx.hpp>
#include <mongocxx/uri.hpp>

using bsoncxx::builder::basic::kvp;
using bsoncxx::builder::basic::make_array;
using bsoncxx::builder::basic::make_document;

int main()
{
   mongocxx::instance instance{}; // This should be done only once.
   mongocxx::uri uri("mongodb://user:pwd@localhost:27017/vpndb");
   mongocxx::client client(uri);

   auto db = client["vpndb"];

   for(const auto& it : db.list_collection_names())
      std::cout<< it << std::endl;
}
