#include "file_utils.h"

namespace file_utils {
    
    std::map<std::string, std::string> parse_key_value_lines(const char *path, char delimiter) {

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

                    getline(ss, key, delimiter);
                    getline(ss, value, delimiter);
                    config_map[key] = value;
                }
        
                ++fileIterator;
            }
            
            file.close();
        }

        return config_map;
    }
}