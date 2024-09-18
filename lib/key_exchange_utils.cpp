#include "key_exchange_utils.h"

#include <stdexcept>
#include <iostream>

#include <ssl_utils.h>
#include <random_utils.h>
#include <encryption.h>
#include <utils.h>

#define TRY_EXP_OR_RETURN(expression_to_evaluate, return_value_on_failure) \
    try                                                                    \
    {                                                                      \
        expression_to_evaluate;                                            \
    }                                                                      \
    catch (const std::exception &e)                                        \
    {                                                                      \
        std::cerr << e.what() << std::endl;                                \
        return return_value_on_failure;                                    \
    }

namespace key_exchange_utils
{

    altered_MS_CHAPV2_identifier_t::altered_MS_CHAPV2_identifier_t() {}

    altered_MS_CHAPV2_identifier_t::altered_MS_CHAPV2_identifier_t(altered_MS_CHAPV2_message_type message_type)
    {

        /**/
        const char *p_name = "altered_MS_CHAPV2";

        bzero(protocol_name, sizeof(protocol_name));
        memcpy(protocol_name, p_name, strlen(p_name));

        /**/
        this->message_type = message_type;
    }

    std::string altered_MS_CHAPV2_identifier_t::to_s()
    {

        std::string type_str;

        if (message_type)
        {
            type_str = std::string("m1_client");
        }
        if (message_type == m1_server)
        {
            type_str = std::string("m1_server");
        }
        if (message_type == m2_server)
        {
            type_str = std::string("m2_server");
        }

        std::string identifier(protocol_name);
        identifier
            .append(":")
            .append(type_str);

        return identifier;
    }

    altered_MS_CHAPV2_m1_server_sender_t::altered_MS_CHAPV2_m1_server_sender_t()
    {

        /**/
        random_utils::random random;
        random.generate_timestamp_random_16(server_challenge, false);

        /**/
        message_identifier = altered_MS_CHAPV2_identifier_t(m1_server);
    }

    void altered_MS_CHAPV2_m1_server_sender_t::send(SSL *ssl)
    {

        /**/
        std::string message_to_send = message_identifier.to_s();
        utils::push_back(message_to_send, server_challenge, sizeof(server_challenge));

        /**/
        ssl_utils::write_or_throw(ssl, message_to_send.c_str(), message_to_send.size());
    }

    altered_MS_CHAPV2_m1_server_receiver_t::altered_MS_CHAPV2_m1_server_receiver_t() {
        bzero(server_challenge, sizeof(this->server_challenge));
    }

    void altered_MS_CHAPV2_m1_server_receiver_t::receive(SSL *ssl)
    {

        /**/
        char raw_message[256];
        size_t n = ssl_utils::read_or_throw(ssl, raw_message, sizeof(raw_message));

        /**/
        altered_MS_CHAPV2_identifier_t m_identifier(m1_server);
        if (!utils::start_with(raw_message, n, m_identifier.to_s()))
        {
            throw std::invalid_argument("");
        }

        /**/
        unsigned char challenge[MAX_CHALLENGE_SIZE];
        size_t challenge_index = 0;
        size_t start_index = m_identifier.to_s().size();

        for (size_t i = start_index; i < n; i++)
        {

            char b_data = raw_message[i];

            if (challenge_index == MAX_CHALLENGE_SIZE)
            {
                /**/
                throw std::invalid_argument("");
            }

            challenge[challenge_index] = b_data;
            challenge_index += 1;
        }

        if (challenge_index != MAX_CHALLENGE_SIZE)
        {
            /**/
            throw std::invalid_argument("");
        }

        /**/
        message_identifier = m_identifier;
        memcpy(server_challenge, challenge, sizeof(server_challenge));
    }

    altered_MS_CHAPV2_m1_client_sender_t::altered_MS_CHAPV2_m1_client_sender_t(
        const char *username,
        unsigned const char *server_challenge,
        unsigned const char *shared_secret)
    {
        /**/
        message_identifier = altered_MS_CHAPV2_identifier_t(m1_client);

        /**/
        random_utils::random random;
        random.generate_timestamp_random_16(client_challenge, false);

        bzero(this->username, sizeof(this->username));
        memcpy(this->username, username, strlen(username));

        memcpy(this->server_challenge, server_challenge, sizeof(this->server_challenge));
        memcpy(this->shared_secret, shared_secret, sizeof(this->shared_secret));
    }

    void altered_MS_CHAPV2_m1_client_sender_t::send(SSL *ssl)
    {

        /**/
        std::string data_to_hash;
        utils::push_back(data_to_hash, server_challenge, sizeof(server_challenge));
        utils::push_back(data_to_hash, shared_secret, sizeof(shared_secret));
        std::string computed_hash = encryption::compute_hash(data_to_hash);

        /**/
        std::string message_to_send = message_identifier.to_s();
        utils::push_back(message_to_send, username, strlen(username));
        utils::push_back(message_to_send, ".", strlen("."));
        utils::push_back(message_to_send, client_challenge, sizeof(client_challenge));
        utils::push_back(message_to_send, computed_hash.c_str(), computed_hash.size());

        std::cout << "sending: " << message_to_send << std::endl;

        /**/
        ssl_utils::write_or_throw(ssl, message_to_send.c_str(), message_to_send.size());
    }

    altered_MS_CHAPV2_m1_client_receiver_t::altered_MS_CHAPV2_m1_client_receiver_t() {
        bzero(username, sizeof(username));
        bzero(client_challenge, sizeof(client_challenge));
        bzero(hashed_challenge, sizeof(hashed_challenge));
    }

    void altered_MS_CHAPV2_m1_client_receiver_t::receive(SSL *ssl)
    {
        /**/
        char raw_message[512];
        size_t n = ssl_utils::read_or_throw(ssl, raw_message, sizeof(raw_message));

        /**/
        altered_MS_CHAPV2_identifier_t m_identifier(m1_client);
        if (!utils::start_with(raw_message, n, m_identifier.to_s()))
        {
            throw std::invalid_argument("");
        }

        /**/
        bool reading_username = true;
        bool reading_client_challenge = false;
        bool reading_challenge_response = false;

        /**/
        char username_buff[MAX_USERNAME_SIZE];
        bzero(username_buff, sizeof(username_buff));

        /**/
        char client_challenge_buff[MAX_CHALLENGE_SIZE];
        char challenge_response_buff[MAX_HASH_SIZE];

        /**/
        size_t username_buff_index = 0;
        size_t client_challenge_buff_index = 0;
        size_t challenge_response_buff_index = 0;
        size_t start_index = m_identifier.to_s().size();

        for (size_t i = start_index; i < n; i++)
        {
            char b_data = raw_message[i];

            /**/
            if (reading_username)
            {

                if (b_data == '.')
                {

                    /**/
                    reading_username = false;
                    reading_client_challenge = true;
                    continue;
                }
                else if (username_buff_index == MAX_USERNAME_SIZE - 1)
                {

                    /**/
                    throw std::invalid_argument("");
                }
                else
                {

                    /**/
                    username_buff[username_buff_index] = b_data;
                    username_buff_index += 1;
                    continue;
                }
            }

            /**/
            if (reading_client_challenge)
            {

                client_challenge_buff[client_challenge_buff_index] = b_data;
                client_challenge_buff_index += 1;

                if (client_challenge_buff_index == MAX_CHALLENGE_SIZE)
                {

                    /**/
                    reading_client_challenge = false;
                    reading_challenge_response = true;
                }

                continue;
            }

            /**/
            if (reading_challenge_response)
            {

                challenge_response_buff[challenge_response_buff_index] = b_data;
                challenge_response_buff_index += 1;

                if (challenge_response_buff_index == MAX_HASH_SIZE)
                {

                    reading_challenge_response = false;
                    break;
                }
            }
        }

        bool is_parse_valid =
            username_buff_index > 0 &&
            client_challenge_buff_index == MAX_CHALLENGE_SIZE &&
            challenge_response_buff_index == MAX_HASH_SIZE;

        if (!is_parse_valid)
        {
            throw std::invalid_argument("");
        }

        memcpy(username, username_buff, username_buff_index);
        memcpy(client_challenge, client_challenge_buff, client_challenge_buff_index);
        memcpy(hashed_challenge, challenge_response_buff, challenge_response_buff_index);

        message_identifier = m_identifier;
    }

    bool altered_MS_CHAPV2_m1_client_receiver_t::valid_response(
        unsigned const char *server_challenge,
        unsigned const char *shared_secret)
    {

        // the pseudorandom string (A), the session identifier (IdS), the user password, under the SHA256.
        std::string data_to_hash;
        utils::push_back(data_to_hash, server_challenge, MAX_CHALLENGE_SIZE);
        utils::push_back(data_to_hash, shared_secret, MAX_KEY_SIZE);

        std::string a = encryption::compute_hash(data_to_hash);
        std::string b = utils::string_from_bytes(hashed_challenge, MAX_HASH_SIZE);

        /**/
        return encryption::compute_hash(data_to_hash)
                   .compare(utils::string_from_bytes(hashed_challenge, MAX_HASH_SIZE)) == 0;
    }

    altered_MS_CHAPV2_m2_server_sender_t::altered_MS_CHAPV2_m2_server_sender_t(unsigned const char *client_challenge, unsigned const char *shared_secret)
    {

        /**/
        memcpy(this->client_challenge, client_challenge, sizeof(this->client_challenge));
        memcpy(this->shared_secret, shared_secret, sizeof(this->shared_secret));

        /**/
        message_identifier = altered_MS_CHAPV2_identifier_t(m2_server);
    }

    void altered_MS_CHAPV2_m2_server_sender_t::send(SSL *ssl)
    {

        std::string data_to_hash;
        utils::push_back(data_to_hash, client_challenge, sizeof(client_challenge));
        utils::push_back(data_to_hash, shared_secret, sizeof(shared_secret));

        /**/
        std::string hash = encryption::compute_hash(data_to_hash);

        /**/
        std::string message_to_send = message_identifier.to_s();
        utils::push_back(message_to_send, hash.c_str(), hash.size());

        /**/
        ssl_utils::write_or_throw(ssl, message_to_send.c_str(), message_to_send.size());
    }

    altered_MS_CHAPV2_m2_server_receiver_t::altered_MS_CHAPV2_m2_server_receiver_t() {
        bzero(hashed_challenge, sizeof(hashed_challenge));
    }

    void altered_MS_CHAPV2_m2_server_receiver_t::receive(SSL *ssl)
    {
        /**/
        char raw_message[256];
        size_t n = ssl_utils::read_or_throw(ssl, raw_message, sizeof(raw_message));

        altered_MS_CHAPV2_identifier_t m_identifier(m2_server);
        if (!utils::start_with(raw_message, n, m_identifier.to_s()))
        {
            throw std::invalid_argument("");
        }

        char challenge_response_buff[MAX_HASH_SIZE];
        bzero(challenge_response_buff, sizeof(challenge_response_buff));

        size_t challenge_response_buff_index = 0;
        size_t start = m_identifier.to_s().size();

        for (size_t i = start; i < n; i++)
        {
            challenge_response_buff[challenge_response_buff_index] = raw_message[i];
            challenge_response_buff_index += 1;

            if (challenge_response_buff_index == MAX_HASH_SIZE)
            {
                break;
            }
        }

        bool is_parse_valid = challenge_response_buff_index == MAX_HASH_SIZE;

        if (!is_parse_valid)
        {
            throw std::invalid_argument("");
        }

        memcpy(hashed_challenge, challenge_response_buff, challenge_response_buff_index);
        message_identifier = m_identifier;
    }

    bool altered_MS_CHAPV2_m2_server_receiver_t::valid_response(unsigned const char *client_challenge, unsigned const char *shared_secret)
    {

        std::string data_to_hash;
        utils::push_back(data_to_hash, client_challenge, MAX_CHALLENGE_SIZE);
        utils::push_back(data_to_hash, shared_secret, MAX_KEY_SIZE);

        return encryption::compute_hash(data_to_hash)
                   .compare(utils::string_from_bytes(hashed_challenge, MAX_HASH_SIZE)) == 0;
    }

    int complete_synced_altered_MS_CHAPV2_server_flow(
        SSL *ssl,
        credential_fetcher *fetcher,
        unsigned char *key_buffer)
    {
        altered_MS_CHAPV2_m1_server_sender_t m1_server_message;
        TRY_EXP_OR_RETURN(m1_server_message.send(ssl), -1);

        altered_MS_CHAPV2_m1_client_receiver_t m1_client_message;
        TRY_EXP_OR_RETURN(m1_client_message.receive(ssl), -2);

        /**/
        std::string shared_secret = fetcher->secret_by_username(m1_client_message.username);
        if (shared_secret.empty())
        {
            ssl_utils::free_ssl(ssl, NULL);
            return -3;
        }

        const unsigned char *secret_p = (const unsigned char *)shared_secret.c_str();

        bool valid_response = m1_client_message.valid_response(m1_server_message.server_challenge, secret_p);
        if (!valid_response)
        {
            /**/
            ssl_utils::free_ssl(ssl, NULL);
            return -4;
        }

        /**/
        altered_MS_CHAPV2_m2_server_sender_t m2_s(m1_client_message.client_challenge, secret_p);
        TRY_EXP_OR_RETURN(m2_s.send(ssl), -5);

        /**/
        std::string key_no_hash;
        utils::push_back(key_no_hash, m1_server_message.server_challenge, MAX_CHALLENGE_SIZE);
        utils::push_back(key_no_hash, m1_client_message.client_challenge, MAX_CHALLENGE_SIZE);
        utils::push_back(key_no_hash, secret_p, MAX_KEY_SIZE);

        /**/
        std::string key = encryption::compute_hash(key_no_hash);
        memcpy(key_buffer, key.c_str(), key.size());

        /**/
        return 0;
    }

    int complete_synced_altered_MS_CHAPV2_client_flow(
        SSL *ssl,
        const unsigned char *secret,
        const char *username,
        unsigned char *key_buffer)
    {

        altered_MS_CHAPV2_m1_server_receiver_t m1_sr;
        TRY_EXP_OR_RETURN(m1_sr.receive(ssl), -1);

        altered_MS_CHAPV2_m1_client_sender_t m1_cs(username, m1_sr.server_challenge, secret);
        TRY_EXP_OR_RETURN(m1_cs.send(ssl), -2);

        altered_MS_CHAPV2_m2_server_receiver_t m2_sr;
        TRY_EXP_OR_RETURN(m2_sr.receive(ssl), -3);

        bool valid_response = m2_sr.valid_response(m1_cs.client_challenge, secret);
        if (!valid_response)
        {
            /**/
            ssl_utils::free_ssl(ssl, NULL);
            return -4;
        }

        /**/
        std::string key_no_hash;
        utils::push_back(key_no_hash, m1_sr.server_challenge, MAX_CHALLENGE_SIZE);
        utils::push_back(key_no_hash, m1_cs.client_challenge, MAX_CHALLENGE_SIZE);
        utils::push_back(key_no_hash, secret, MAX_KEY_SIZE);

        /**/
        std::string key = encryption::compute_hash(key_no_hash);
        memcpy(key_buffer, key.c_str(), key.size());

        return 0;
    }
}