#ifndef KEY_EXCHANGE_H
#define KEY_EXCHANGE_H

#include <openssl/ssl.h>

#include <optional>
#include <string>

#include <socket_utils.h>

/**
 * The authentication process involves several key steps between the server and the client:
 *
 * 1. Server to Client:
 *    - The authentication server sends a message containing:
 *      - A pseudorandom string (A)
 *
 * 2. Client Response:
 *    - The client receives the message and constructs a response that includes:
 *      - The username
 *      - A new pseudorandom string (B)
 *      - A hashed combination of:
 *        - The pseudorandom string (A)
 *        - The user's secret (hashed using SHA256)
 *
 * 3. Server Verification:
 *    - Upon receiving the client's message, the server checks its validity and sends a response containing:
 *      - Both the pseudorandom string (B) and the user's secret, which are hashed using SHA256
 *
 * 4. Client Action:
 *    - The client processes the server's response. If authentication is successful, it will use the session; otherwise, it will terminate the connection.
 */
namespace key_exchange_utils
{

    const int MAX_SESSION_ID_SIZE = 8;
    const int MAX_CHALLENGE_SIZE = 16;
    const int MAX_HASH_SIZE = 32;
    const int MAX_KEY_SIZE = 32;
    const int MAX_PROTOCOL_NAME_SIZE = 32;
    const int MAX_USERNAME_SIZE = 256;

    struct credential_fetcher
    {
        /**
         * This pure virtual method must be implemented by any derived class.
         * It is responsible for fetching the secret associated with a specific username.
         */
        virtual std::string secret_by_username(std::string username) = 0;
    };

    enum altered_MS_CHAPV2_message_type
    {
        m1_server,
        m1_client,
        m2_server
    };

    /**
     * @struct altered_MS_CHAPV2_identifier_t
     * @brief Represents an identifier for the altered MS-CHAPv2 protocol.
     *
     * This struct encapsulates information related to an altered MS-CHAPv2 message.
     * It includes the message type and a protocol name. The struct provides
     * constructors for initialization and a method to convert the object to a
     * string representation.
     */
    struct altered_MS_CHAPV2_identifier_t
    {
        altered_MS_CHAPV2_message_type message_type;
        char protocol_name[MAX_PROTOCOL_NAME_SIZE];

        altered_MS_CHAPV2_identifier_t();
        altered_MS_CHAPV2_identifier_t(altered_MS_CHAPV2_message_type message_type);

        /**
         * Converts the altered_MS_CHAPV2 identifier to a
         * string representation.
         */
        std::string to_s();
    };

    /**
     * @struct altered_MS_CHAPV2_m1_server_sender_t
     * @brief Represents the sender for the altered MS-CHAPv2 M1 server message.
     *
     * This struct is responsible for holding the message identifier and the server challenge
     * used in the altered MS-CHAPv2 authentication protocol. It provides a constructor for
     * initialization and a method to send the message over an SSL connection.
     */
    struct altered_MS_CHAPV2_m1_server_sender_t
    {
        altered_MS_CHAPV2_identifier_t message_identifier;
        unsigned char server_challenge[MAX_CHALLENGE_SIZE];

        altered_MS_CHAPV2_m1_server_sender_t();

        void send(SSL *ssl);
    };

    /**
     * @struct altered_MS_CHAPV2_m1_server_receiver_t
     * @brief Represents the receiver for the altered MS-CHAPv2 M1 server message.
     *
     * This struct is designed to handle the reception of the M1 server message in the altered
     * MS-CHAPv2 authentication protocol. It contains the message identifier and the server
     * challenge, as well as methods for initialization and message reception.
     */
    struct altered_MS_CHAPV2_m1_server_receiver_t
    {
        altered_MS_CHAPV2_identifier_t message_identifier;
        unsigned char server_challenge[MAX_CHALLENGE_SIZE];

        altered_MS_CHAPV2_m1_server_receiver_t();

        void receive(SSL *ssl);
    };

    /**
     * @struct altered_MS_CHAPV2_m1_client_sender_t
     * @brief Represents the sender for the altered MS-CHAPv2 M1 client message.
     *
     * This struct is responsible for preparing and sending the M1 client message in the
     * altered MS-CHAPv2 authentication protocol. It contains the message identifier,
     * user credentials, and challenges required for the authentication process.
     */
    struct altered_MS_CHAPV2_m1_client_sender_t
    {
        altered_MS_CHAPV2_identifier_t message_identifier;
        char username[MAX_USERNAME_SIZE];
        unsigned char client_challenge[MAX_CHALLENGE_SIZE];
        unsigned char server_challenge[MAX_CHALLENGE_SIZE];
        unsigned char shared_secret[MAX_KEY_SIZE];

        altered_MS_CHAPV2_m1_client_sender_t(
            const char *username,
            unsigned const char *server_challenge,
            unsigned const char *shared_secret);

        void send(SSL *ssl);
    };

    /**
     * @struct altered_MS_CHAPV2_m1_client_receiver_t
     * @brief Represents the receiver for the altered MS-CHAPv2 M1 client message.
     *
     * This struct handles the reception of the M1 client message from the client, storing relevant
     * details such as the username and challenges. It provides methods for receiving the message,
     * and validating the client's response.
     */
    struct altered_MS_CHAPV2_m1_client_receiver_t
    {
        altered_MS_CHAPV2_identifier_t message_identifier;
        char username[MAX_USERNAME_SIZE];
        unsigned char client_challenge[MAX_CHALLENGE_SIZE];
        unsigned char hashed_challenge[MAX_HASH_SIZE];

        altered_MS_CHAPV2_m1_client_receiver_t();

        void receive(SSL *ssl);

        bool valid_response(
            unsigned const char *server_challenge,
            unsigned const char *shared_secret);
    };

    /**
     * @struct altered_MS_CHAPV2_m2_server_sender_t
     * @brief Represents the sender for the altered MS-CHAPv2 M2 server message.
     *
     * This struct is responsible for preparing and sending the M2 server message in the
     * altered MS-CHAPv2 authentication protocol. It contains the client challenge,
     * shared secret, and a message identifier, allowing the server to respond
     * appropriately to the client's previous request.
     */
    struct altered_MS_CHAPV2_m2_server_sender_t
    {
        unsigned char client_challenge[MAX_CHALLENGE_SIZE];
        unsigned char shared_secret[MAX_KEY_SIZE];
        altered_MS_CHAPV2_identifier_t message_identifier;

        altered_MS_CHAPV2_m2_server_sender_t(unsigned const char *client_challenge, unsigned const char *shared_secret);

        void send(SSL *ssl);
    };

    /**
     * @struct altered_MS_CHAPV2_m2_server_receiver_t
     * @brief Represents the receiver for the altered MS-CHAPv2 M2 server message.
     *
     * This struct handles the reception of the M2 message from the server in the
     * altered MS-CHAPv2 authentication protocol. It stores the message identifier
     * and the hashed challenge, and provides methods to receive the message and
     * validate the server's response.
     */
    struct altered_MS_CHAPV2_m2_server_receiver_t
    {
        altered_MS_CHAPV2_identifier_t message_identifier;
        unsigned char hashed_challenge[MAX_HASH_SIZE];
        altered_MS_CHAPV2_m2_server_receiver_t();

        void receive(SSL *ssl);

        bool valid_response(unsigned const char *client_challenge, unsigned const char *shared_secret);
    };

    int complete_synced_altered_MS_CHAPV2_server_flow(
        SSL *ssl,
        credential_fetcher *fetcher,
        unsigned char *key_buffer);

    int complete_synced_altered_MS_CHAPV2_client_flow(
        SSL *ssl,
        const unsigned char *secret,
        const char *username,
        unsigned char *key_buffer);
}

#endif
