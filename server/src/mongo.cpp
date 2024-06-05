
#include "mongo.hpp"

mongo::mongo(const std::string uri) : instance_{}, uri_(uri), client_(uri_)
{
   db_ = client_["vpndb"];
   collection_ = db_["users"];
}

mongo::~mongo()
{
}

void mongo::generate_salt(size_t length)
{
   const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
   const size_t max_index = (sizeof(charset) - 1);
   std::random_device rd;
   std::mt19937 generator(rd());
   std::uniform_int_distribution<> dist(0, max_index);

   std::string salt;
   for (size_t i = 0; i < length; ++i)
   {
      salt += charset[dist(generator)];
   }

   salt_ = salt;
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
      generate_salt(16);
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

bool mongo::is_present(const std::string username, const std::string hashed_password)
{
   auto result = collection_.find_one(make_document(kvp("username", username)));
   if (result)
   {
      auto view = result->view();
      auto password_element = view["password"];
      if (password_element && password_element.get_string().value.to_string() == hashed_password)
         return true;
      else
         return false;
   }
   else
   {
      return false;
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
