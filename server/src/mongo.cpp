
#include "mongo.hpp"

mongo::mongo(const std::string uri) : instance_{}, uri_(uri), client_(uri_)
{
   db_ = client_["vpndb"];
   collection_ = db_["users"];
   salt_ = SALT;
}

mongo::~mongo()
{
}

std::string mongo::to_hex_string(size_t hash_value)
{
   std::stringstream ss;
   ss << std::hex << hash_value;
   return ss.str();
}

std::string mongo::hash_password(const std::string &password)
{
   std::hash<std::string> hash_fn;
   size_t hash_value = hash_fn(password + salt_);
   return to_hex_string(hash_value);
}

std::string mongo::get_salt()
{
   return std::string();
}

void mongo::add_user(const std::string id, const std::string username, const std::string password)
{
   try
   {
      std::string hashed_password = hash_password(password);
      auto result = collection_.insert_one(make_document(
          kvp("_id", id),
          kvp("username", username),
          kvp("password", hashed_password)));
      assert(result);
   }
   catch (const mongocxx::bulk_write_exception &e)
   {
      if (e.code().value() == 11000)
      {
         // std::cerr << "Duplicate key error: " << e.code().message() << std::endl;
         return;
      }
   }
}

user_id mongo::is_present(const std::string username, const std::string password)
{
   auto result = collection_.find_one(make_document(kvp("username", username)));
   if (result)
   {
      auto view = result->view();
      auto password_element = view["password"];
      auto hashed_password = hash_password(password);
      if (password_element && password_element.get_string().value.to_string() == hashed_password)
         return stoi(view["_id"].get_string().value.to_string());
      else
         return -1;
   }
   else
   {
      return -1;
   }
}

void mongo::get_users()
{
   auto cursor_all = collection_.find({});
   std::cout << "collection [" << collection_.name()
             << "] contains these documents:" << std::endl;
   for (auto doc : cursor_all)
   {
      std::cout << bsoncxx::to_json(doc, bsoncxx::ExtendedJsonMode::k_relaxed) << std::endl;
   }
}
