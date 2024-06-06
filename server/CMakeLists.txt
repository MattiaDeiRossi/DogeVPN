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
add_executable(main src/main.cpp)
add_executable(openssl_main src/openssl_main.c)

target_include_directories(mongo PUBLIC
  ${MONGOCXX_INCLUDE_DIR}/mongocxx/v_noabi
  ${MONGOCXX_INCLUDE_DIR}/bsoncxx/
  ${MONGOCXX_INCLUDE_DIR}/bsoncxx/v_noabi
  ${MONGOCXX_INCLUDE_DIR}/bsoncxx/v_noabi/bsoncxx/third_party/mnmlstc)

target_link_libraries(mongo PRIVATE 
  mongocxx 
  bsoncxx
)

target_link_libraries(main mongo)

target_link_libraries(openssl_main crypto)

install(TARGETS 
  mongo
  DESTINATION lib/${PROJECT_NAME})
