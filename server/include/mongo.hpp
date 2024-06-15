#ifndef MONGO_HPP
#define MONGO_HPP

#include <bsoncxx/builder/basic/document.hpp>
#include <bsoncxx/json.hpp>
#include <mongocxx/client.hpp>
#include <mongocxx/instance.hpp>
#include <mongocxx/stdx.hpp>
#include <mongocxx/uri.hpp>
#include <mongocxx/exception/bulk_write_exception.hpp>

#include "standards.h"
#include "socket.h"
#include "openssl.h"
#include "data_structures.h"
#include "defines.h"

using bsoncxx::builder::basic::kvp;
using bsoncxx::builder::basic::make_array;
using bsoncxx::builder::basic::make_document;

class mongo
{
private:
  mongocxx::instance instance_;
  mongocxx::uri uri_;
  mongocxx::client client_;
  mongocxx::database db_;
  mongocxx::collection collection_;
  std::string salt_;
  std::string to_hex_string(size_t hash_value);

public:
  mongo(const std::string uri);
  ~mongo();

  std::string hash_password(const std::string &password);
  std::string get_salt();

  void add_user(const std::string id, const std::string username, const std::string password);
  user_id is_present(const std::string username, const std::string password);
  void delete_user();
  void get_users();
};

#endif