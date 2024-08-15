#include "file_utils.h"

namespace file_utils {
    
    std::map<std::string, std::string> parse_key_value_lines(const char *path) {

        std::ifstream file(path);
        std::map<std::string, std::string> config_map;
        
        if (file.is_open()) {

            std::istream_iterator<std::string> fileIterator(file);
            std::istream_iterator<std::string> endIterator;
            
            while (fileIterator != endIterator) {

                std::stringstream ss(*fileIterator);
                std::string key;
                std::string value;

                while (!ss.eof()) {

                    getline(ss, key, ':');
                    getline(ss, value, ':');
                    config_map[key] = value;
                }
        
                ++fileIterator;
            }
            
            file.close();
        }

        return config_map;
    }

    std::vector<std::map<std::string, std::string>> parse_multi_key_value_lines(const char *path) {

        std::ifstream file(path);
        std::vector<std::map<std::string, std::string>> user_map;

        if (file.is_open()) {

            std::istream_iterator<std::string> fileIterator(file);
            std::istream_iterator<std::string> endIterator;
            
            while (fileIterator != endIterator) {

                std::stringstream ss(*fileIterator);
                std::string key;
                std::string value;

                std::map<std::string, std::string> config_map;

                while (!ss.eof()) {

                    for (size_t i = 0; i < 2; i++) {

                        getline(ss, key, ':');
                        getline(ss, value, ':');
                        config_map[key] = value;
                    }
                }

                user_map.push_back(config_map);
                ++fileIterator;
            }
            
            file.close();
        }

        return user_map;
    }

    std::optional<std::map<std::string, std::string>> find_in_multi_key_value_lines(const char *path, const char *key, const char *value) {

        std::vector<std::map<std::string, std::string>> vector_map = parse_multi_key_value_lines(path);

        for (auto u_map : vector_map) {

            for (auto pair : u_map) {

                if (pair.first.compare(key) == 0) {
                    if (pair.second.compare(value) == 0) {
                        return u_map;
                    }
                }
            }
        }

        return std::nullopt;
    }
}