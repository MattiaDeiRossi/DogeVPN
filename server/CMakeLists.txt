cmake_minimum_required(VERSION 3.8)
project(mongo)

if(CMAKE_COMPILER_IS_GNUCXX OR CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  add_compile_options(-Wall -Wextra -Wpedantic -Wformat=2 -Wmisleading-indentation)
endif()

include_directories(include)
include_directories(../lib)

add_library(encryption ../lib/encryption.cpp)
add_library(socket_utils ../lib/socket_utils.cpp)
add_library(ssl_utils ../lib/ssl_utils.cpp)
add_library(utils ../lib/utils.cpp)
add_library(random_utils ../lib/random_utils.cpp)
add_library(key_exchange_utils ../lib/key_exchange_utils.cpp)
add_library(vpn_data_utils ../lib/vpn_data_utils.cpp)
add_library(tun_utils ../lib/tun_utils.cpp)
add_library(logging ../lib/logging.cpp)
add_library(session_poller ../lib/session_poller.cpp)
add_library(holder src/holder.cpp)
add_library(file_utils src/file_utils.cpp)

add_executable(vpnserver src/vpn_server.cpp)

target_link_libraries(vpnserver 
  encryption
  socket_utils
  ssl_utils
  random_utils
  key_exchange_utils
  holder
  vpn_data_utils
  tun_utils
  file_utils
  utils
  logging
  session_poller
  crypto
  ssl
)
