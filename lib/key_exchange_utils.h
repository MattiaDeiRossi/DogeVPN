#ifndef KEY_EXCHANGE_H
#define KEY_EXCHANGE_H

#include <openssl/ssl.h>

#include <optional>
#include <string>

#include <socket_utils.h>

/* The authentication server sends the client a message consisting of:
 *  - a session identifier (Ids)
 *  - a pseudorandom string (A)
 * The client receives the message from the server and sends a response consisting of:
 *  - username
 *  - a pseudorandom string (B)
 *  - the pseudorandom string (A), the session identifier (IdS), the user password, under the SHA256.
 * The server receives the message from the client, checks it and sends the relevant response consisting of:
 *  - the outcome of the connection attempt
 *  - the pseudorandom string (B) and the user's password are all encrypted
 * The client receives the response and uses the session if authentication has occurred, otherwise it interrupts the connection
 */
namespace key_exchange_utils
{

    const int MAX_SESSION_ID_SIZE = 8;
    const int MAX_CHALLENGE_SIZE = 16;
    const int MAX_HASH_SIZE = 32;
    const int MAX_KEY_SIZE = 32;
    const int MAX_PROTOCOL_NAME_SIZE = 32;
    const int MAX_USERNAME_SIZE = 256;

    enum altered_MS_CHAPV2_message_type
    {
        m1_server,
        m1_client,
        m2_server
    };

    struct altered_MS_CHAPV2_identifier_t
    {
        altered_MS_CHAPV2_message_type message_type;

        char protocol_name[MAX_PROTOCOL_NAME_SIZE];

        altered_MS_CHAPV2_identifier_t();
        altered_MS_CHAPV2_identifier_t(altered_MS_CHAPV2_message_type message_type);

        std::string to_s();
    };

    /**/
    struct altered_MS_CHAPV2_m1_server_sender_t
    {

        /**/
        altered_MS_CHAPV2_identifier_t message_identifier;

        unsigned char server_challenge[MAX_CHALLENGE_SIZE];

        unsigned int session_id;

        altered_MS_CHAPV2_m1_server_sender_t(unsigned int session_id);

        void send(SSL *ssl);
    };

    /**/
    struct altered_MS_CHAPV2_m1_server_receiver_t
    {

        /**/
        altered_MS_CHAPV2_identifier_t message_identifier;

        unsigned char server_challenge[MAX_CHALLENGE_SIZE];

        unsigned int session_id;

        void receive(SSL *ssl);
    };

    /**/
    struct altered_MS_CHAPV2_m1_client_sender_t
    {
        /**/
        altered_MS_CHAPV2_identifier_t message_identifier;

        char username[MAX_USERNAME_SIZE];

        unsigned char client_challenge[MAX_CHALLENGE_SIZE];
        unsigned char server_challenge[MAX_CHALLENGE_SIZE];
        unsigned char shared_secret[MAX_KEY_SIZE];

        unsigned int session_id;

        altered_MS_CHAPV2_m1_client_sender_t(
            const char *username,
            unsigned const char *server_challenge,
            unsigned const char *shared_secret,
            unsigned int session_id);

        void send(SSL *ssl);
    };

    /**/
    struct altered_MS_CHAPV2_m1_client_receiver_t
    {
        /**/
        altered_MS_CHAPV2_identifier_t message_identifier;

        char username[MAX_USERNAME_SIZE];

        unsigned char client_challenge[MAX_CHALLENGE_SIZE];
        unsigned char hashed_challenge[MAX_HASH_SIZE];

        void receive(SSL *ssl);

        bool valid_response(
            unsigned int session_id,
            unsigned const char *server_challenge,
            unsigned const char *shared_secret);
    };

    struct altered_MS_CHAPV2_m2_server_sender_t
    {

        /**/
        unsigned char client_challenge[MAX_CHALLENGE_SIZE];
        unsigned char shared_secret[MAX_KEY_SIZE];

        altered_MS_CHAPV2_identifier_t message_identifier;

        altered_MS_CHAPV2_m2_server_sender_t(unsigned const char *client_challenge, unsigned const char *shared_secret);

        void send(SSL *ssl);
    };

    struct altered_MS_CHAPV2_m2_server_receiver_t
    {
        altered_MS_CHAPV2_identifier_t message_identifier;
        unsigned char hashed_challenge[MAX_HASH_SIZE];

        void receive(SSL *ssl);

        bool valid_response(unsigned const char *client_challenge, unsigned const char *shared_secret);
    };

    int complete_synced_altered_MS_CHAPV2_server_flow(SSL *ssl, unsigned int session_id, std::string (*secret_fetcher)(std::string));

    int complete_synced_altered_MS_CHAPV2_client_flow(SSL *ssl, const unsigned char *secret, const char *username);
}

#endif
