#include "key_exchange_utils.h"

#include <stdexcept>
#include <iostream>

#include <ssl_utils.h>
#include <random_utils.h>
#include <encryption.h>
#include <utils.h>

#define PUSH_BACK(str, buffer, buffer_size)  \
    for (size_t i = 0; i < buffer_size; i++) \
    {                                        \
        str.push_back(buffer[i]);            \
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

    altered_MS_CHAPV2_m1_server_sender_t::altered_MS_CHAPV2_m1_server_sender_t() {}

    altered_MS_CHAPV2_m1_server_sender_t::altered_MS_CHAPV2_m1_server_sender_t(unsigned int session_id)
    {

        /**/
        random_utils::random random;
        random.generate_timestamp_random_16(server_challenge, false);

        /**/
        this->session_id = session_id;

        /**/
        message_identifier = altered_MS_CHAPV2_identifier_t(m1_server);
    }

    void altered_MS_CHAPV2_m1_server_sender_t::send(SSL *ssl)
    {

        /**/
        std::string message_to_send = message_identifier.to_s();
        message_to_send
            .append(std::to_string(session_id))
            .append(".");

        /**/
        PUSH_BACK(message_to_send, server_challenge, sizeof(server_challenge));

        /**/
        ssl_utils::write_or_throw(ssl, message_to_send.c_str(), message_to_send.size());
    }

    altered_MS_CHAPV2_m1_server_receiver_t::altered_MS_CHAPV2_m1_server_receiver_t() {}

    altered_MS_CHAPV2_m1_server_receiver_t::altered_MS_CHAPV2_m1_server_receiver_t(const char *raw_message, size_t n)
    {

        /**/
        altered_MS_CHAPV2_identifier_t m_identifier(m1_server);

        /**/
        char session_id_buff[MAX_SESSION_ID_SIZE];
        bzero(session_id_buff, sizeof(session_id_buff));

        /**/
        unsigned char challenge[MAX_CHALLENGE_SIZE];

        /**/
        bool reading_session_id = true;
        bool reading_challenge = false;

        size_t session_id_index = 0;
        size_t challenge_index = 0;
        size_t start_index = m_identifier.to_s().size();

        for (size_t i = start_index; i < n; i++)
        {

            char b_data = raw_message[i];

            if (reading_session_id)
            {

                if (isdigit(b_data))
                {

                    /**/
                    if (session_id_index == MAX_SESSION_ID_SIZE)
                    {

                        throw std::invalid_argument("");
                    }
                    else
                    {
                        session_id_buff[session_id_index] = b_data;
                        session_id_index += 1;
                        continue;
                    }
                }
                else if (b_data == '.')
                {

                    /**/
                    reading_session_id = false;
                    reading_challenge = true;
                    continue;
                }
                else
                {

                    /**/
                    throw std::invalid_argument("");
                }
            }

            if (reading_challenge)
            {

                if (challenge_index == MAX_CHALLENGE_SIZE)
                {

                    /**/
                    throw std::invalid_argument("");
                }
                else
                {
                    challenge[challenge_index] = b_data;
                    challenge_index += 1;
                }
            }
        }

        if (session_id_index > MAX_SESSION_ID_SIZE || challenge_index != MAX_CHALLENGE_SIZE)
        {

            /**/
            throw std::invalid_argument("");
        }

        /**/
        session_id = std::stoi(session_id_buff);
        message_identifier = m_identifier;
        memcpy(server_challenge, challenge, sizeof(server_challenge));
    }

    altered_MS_CHAPV2_m1_client_sender_t::altered_MS_CHAPV2_m1_client_sender_t() {}

    altered_MS_CHAPV2_m1_client_sender_t::altered_MS_CHAPV2_m1_client_sender_t(
        const char *username,
        unsigned const char *server_challenge,
        unsigned const char *shared_secret,
        unsigned int session_id)
    {

        /**/
        message_identifier = altered_MS_CHAPV2_identifier_t(m1_client);

        /**/
        random_utils::random random;
        random.generate_timestamp_random_16(client_challenge, false);

        /**/
        bzero(this->username, sizeof(this->username));
        memcpy(this->username, username, strlen(username));

        /**/
        memcpy(this->server_challenge, server_challenge, sizeof(this->server_challenge));

        /**/
        memcpy(this->shared_secret, shared_secret, sizeof(this->shared_secret));

        /**/
        this->session_id = session_id;
    }

    void altered_MS_CHAPV2_m1_client_sender_t::send(SSL *ssl)
    {

        /**/
        std::string data_to_hash;
        PUSH_BACK(data_to_hash, server_challenge, sizeof(server_challenge));
        PUSH_BACK(data_to_hash, std::to_string(session_id), std::to_string(session_id).size());
        PUSH_BACK(data_to_hash, shared_secret, sizeof(shared_secret));
        std::string computed_hash = encryption::compute_hash(data_to_hash);

        /**/
        std::string message_to_send = message_identifier.to_s();
        message_to_send
            .append(username)
            .append(".");

        PUSH_BACK(message_to_send, client_challenge, sizeof(client_challenge));
        PUSH_BACK(message_to_send, computed_hash, computed_hash.size());

        /**/
        ssl_utils::write_or_throw(ssl, message_to_send.c_str(), message_to_send.size());
    }

    altered_MS_CHAPV2_m1_client_receiver_t::altered_MS_CHAPV2_m1_client_receiver_t() {}

    altered_MS_CHAPV2_m1_client_receiver_t::altered_MS_CHAPV2_m1_client_receiver_t(const char *raw_message, size_t n)
    {

        // Username.pseudo|hash
        /**/
        altered_MS_CHAPV2_identifier_t m_identifier(m1_client);

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
        unsigned int session_id,
        unsigned const char *server_challenge,
        unsigned const char *shared_secret)
    {

        std::string session_id_str = std::to_string(session_id);

        // the pseudorandom string (A), the session identifier (IdS), the user password, under the SHA256.
        std::string data_to_hash;
        PUSH_BACK(data_to_hash, server_challenge, MAX_CHALLENGE_SIZE);
        PUSH_BACK(data_to_hash, session_id_str, session_id_str.size());
        PUSH_BACK(data_to_hash, shared_secret, MAX_KEY_SIZE);

        /**/
        return encryption::compute_hash(data_to_hash)
            .compare(utils::string_from_bytes(hashed_challenge, MAX_HASH_SIZE)) == 0;
    }

    altered_MS_CHAPV2_m2_server_sender_t::altered_MS_CHAPV2_m2_server_sender_t() {}

    altered_MS_CHAPV2_m2_server_sender_t::altered_MS_CHAPV2_m2_server_sender_t(const char *client_challenge, const char *shared_secret)
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
        PUSH_BACK(data_to_hash, client_challenge, sizeof(client_challenge));
        PUSH_BACK(data_to_hash, shared_secret, sizeof(shared_secret));

        /**/
        std::string hash = encryption::compute_hash(data_to_hash);

        /**/
        std::string message_to_send = message_identifier.to_s();
        PUSH_BACK(message_to_send, hash, hash.size());

        /**/
        ssl_utils::write_or_throw(ssl, message_to_send.c_str(), message_to_send.size());
    }

    altered_MS_CHAPV2_m2_server_receiver_t::altered_MS_CHAPV2_m2_server_receiver_t() {}

    altered_MS_CHAPV2_m2_server_receiver_t::altered_MS_CHAPV2_m2_server_receiver_t(const char *raw_message, size_t n)
    {

        altered_MS_CHAPV2_identifier_t m_identifier(m2_server);

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
        PUSH_BACK(data_to_hash, client_challenge, MAX_CHALLENGE_SIZE);
        PUSH_BACK(data_to_hash, shared_secret, MAX_KEY_SIZE);

        return encryption::compute_hash(data_to_hash)
            .compare(utils::string_from_bytes(hashed_challenge, MAX_HASH_SIZE)) == 0;
    }

    altered_MS_CHAPV2_message::altered_MS_CHAPV2_message() {}

    std::optional<altered_MS_CHAPV2_message> parse(const char *raw_message, size_t n)
    {

        altered_MS_CHAPV2_identifier_t m1_s(m1_server);
        altered_MS_CHAPV2_identifier_t m2_s(m2_server);
        altered_MS_CHAPV2_identifier_t m1_c(m1_client);

        altered_MS_CHAPV2_identifier_t m_identifier;
        if (utils::start_with(raw_message, n, m1_s.to_s()))
        {
            m_identifier = m1_s;
        }
        else if (utils::start_with(raw_message, n, m2_s.to_s()))
        {
            m_identifier = m2_s;
        }
        else if (utils::start_with(raw_message, n, m1_c.to_s()))
        {
            m_identifier = m1_c;
        }
        else
        {
            return std::nullopt;
        }

        altered_MS_CHAPV2_message message;
        try
        {
            if (m_identifier.message_type == m1_s.message_type)
            {
                message.type = m1_server;
                message.m1_server = altered_MS_CHAPV2_m1_server_receiver_t(raw_message, n);
                return message;
            }
            else if (m_identifier.message_type == m2_s.message_type)
            {
                message.type = m2_server;
                message.m2_server = altered_MS_CHAPV2_m2_server_receiver_t(raw_message, n);
                return message;
            }
            else
            {
                message.type = m1_client;
                message.m1_client = altered_MS_CHAPV2_m1_client_receiver_t(raw_message, n);
                return message;
            }
        }
        catch (const std::exception &e)
        {
            std::cerr << "Exception caught during parsing: " << e.what() << '\n';
            return std::nullopt;
        }
    }
}