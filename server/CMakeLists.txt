cmake_minimum_required(VERSION 3.8)
project(mongo)

if(CMAKE_COMPILER_IS_GNUCXX OR CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  add_compile_options(-Wall -Wextra -Wpedantic)
endif()

set(MONGOCXX_INCLUDE_DIR /usr/local/include)

# find dependencies
find_package(mongocxx REQUIRED)
find_package(bsoncxx REQUIRED)

include_directories(include)

add_library(mongo src/mongo.cpp)
add_library(encryption src/encryption.cpp)

add_executable(vpnserver src/vpn_server.cpp)

target_include_directories(mongo PUBLIC
  ${MONGOCXX_INCLUDE_DIR}/mongocxx/v_noabi
  ${MONGOCXX_INCLUDE_DIR}/bsoncxx/
  ${MONGOCXX_INCLUDE_DIR}/bsoncxx/v_noabi
  ${MONGOCXX_INCLUDE_DIR}/bsoncxx/v_noabi/bsoncxx/third_party/mnmlstc)

target_link_libraries(mongo PRIVATE 
  mongocxx 
  bsoncxx
)

# target_link_libraries(main mongo)

target_link_libraries(vpnserver 
  crypto
  ssl
  encryption
  mongo
)

# install(TARGETS 
#   vpnserver
#   DESTINATION lib/${PROJECT_NAME})
