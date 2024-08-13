#ifndef CONFIG_H
#define CONFIG_H

namespace config {

    const unsigned char third_octet = 11;
    
    const char *name = "serverTUN";
    const char *public_cert = "certs/cert.pem";
    const char *private_key = "certs/key.pem";
    const char *address = "10.5.42.15";
    const char *port = "8080";
}


#endif