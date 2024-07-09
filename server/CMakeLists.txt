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
include_directories(../lib)

add_library(mongo src/mongo.cpp)
add_library(encryption ../lib//encryption.cpp)
add_library(socket_utils ../lib/socket_utils.cpp)
add_library(ssl_utils ../lib/ssl_utils.cpp)
add_library(utils ../lib/utils.cpp)
add_library(client_credentials_utils src/client_credentials_utils.cpp)
add_library(udp_client_info_utils src/udp_client_info_utils.cpp)
add_library(vpn_data_utils src/vpn_data_utils.cpp)

add_executable(vpnserver src/vpn_server.cpp)

target_include_directories(mongo PUBLIC
  ${MONGOCXX_INCLUDE_DIR}/mongocxx/v_noabi
  ${MONGOCXX_INCLUDE_DIR}/bsoncxx/
  ${MONGOCXX_INCLUDE_DIR}/bsoncxx/v_noabi
  ${MONGOCXX_INCLUDE_DIR}/bsoncxx/v_noabi/bsoncxx/third_party/mnmlstc
)

target_link_libraries(mongo PRIVATE 
  mongocxx 
  bsoncxx
)

target_link_libraries(vpnserver 
  encryption
  mongo
  socket_utils
  ssl_utils
  utils
  client_credentials_utils
  udp_client_info_utils
  vpn_data_utils
  crypto
  ssl
)

# install(TARGETS 
#   vpnserver
#   DESTINATION lib/${PROJECT_NAME})
