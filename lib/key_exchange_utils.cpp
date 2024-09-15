#include "key_exchange_utils.h"

#include <stdexcept>
#include <iostream>

#include <ssl_utils.h>
#include <random_utils.h>
#include <encryption.h>
#include <utils.h>

#define COPY_N_SLIDE(dst, src, n_src, slider_index) \
for (size_t i = 0; i < n_src; i++)                  \
{                                                   \
    dst[slider_index] = src[i];                     \
    slider_index += 1;                              \
}

#define PUSH_BACK(str, buffer, buffer_size) \
for (size_t i = 0; i < buffer_size; i++)    \
{                                           \
    str.push_back(buffer[i]);               \
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
            type_str = std::string("m1_client");
        if (message_type == m1_server)
            type_str = std::string("m1_server");
        if (message_type == m2_server)
            type_str = std::string("m2_server");

        std::string identifier(protocol_name);
        identifier
            .append(":")
            .append(type_str);

        return identifier;
    }

    altered_MS_CHAPV2_m1_server_sender_t::altered_MS_CHAPV2_m1_server_sender_t() {}

    altered_MS_CHAPV2_m1_server_sender_t::altered_MS_CHAPV2_m1_server_sender_t(unsigned int session_id)
    {

        random_utils::random random;

        /**/
        bzero(server_challenge, sizeof(server_challenge));
        random.generate_16(server_challenge, false);

        /**/
        this->session_id = session_id;

        /**/
        this->message_identifier =
            altered_MS_CHAPV2_identifier_t(altered_MS_CHAPV2_message_type::m1_server);
    }

    void altered_MS_CHAPV2_m1_server_sender_t::send(SSL *ssl)
    {

        /**/
        std::string message_to_send = message_identifier.to_s();
        message_to_send
            .append(std::to_string(session_id))
            .append(".");

        /**/
        for (size_t i = 0; i < sizeof(server_challenge); i++)
        {
            message_to_send.push_back(server_challenge[i]);
        }

        /**/
        ssl_utils::write_or_throw(ssl, message_to_send.c_str(), message_to_send.size());
    }

    altered_MS_CHAPV2_m1_server_receiver_t::altered_MS_CHAPV2_m1_server_receiver_t() {}

    altered_MS_CHAPV2_m1_server_receiver_t::altered_MS_CHAPV2_m1_server_receiver_t(const char *raw_message, size_t n)
    {

        /**/
        altered_MS_CHAPV2_identifier_t m_identifier(m1_server);

        /**/
        char session_id[MAX_SESSION_ID_SIZE];
        unsigned char challenge[MAX_CHALLENGE_SIZE];
        bzero(session_id, sizeof(session_id));
        bzero(challenge, sizeof(challenge));

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
                        session_id[session_id_index] = b_data;
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
        this->session_id = std::stoi(session_id);
        this->message_identifier = m_identifier;
        memcpy(this->server_challenge, challenge, sizeof(server_challenge));
    }

    altered_MS_CHAPV2_m1_client_sender_t::altered_MS_CHAPV2_m1_client_sender_t() {}

    altered_MS_CHAPV2_m1_client_sender_t::altered_MS_CHAPV2_m1_client_sender_t(
        const char *username,
        unsigned const char *server_challenge,
        unsigned const char *shared_secret,
        unsigned int session_id)
    {

        random_utils::random random;

        /**/
        bzero(this->username, sizeof(this->username));
        bzero(this->client_challenge, sizeof(this->client_challenge));
        bzero(this->server_challenge, sizeof(this->server_challenge));
        bzero(this->shared_secret, sizeof(this->shared_secret));

        /**/
        this->session_id = session_id;

        /**/
        this->message_identifier =
            altered_MS_CHAPV2_identifier_t(altered_MS_CHAPV2_message_type::m1_client);

        /**/
        memcpy(this->username, username, strlen(username));
        memcpy(this->server_challenge, server_challenge, sizeof(this->server_challenge));
        memcpy(this->shared_secret, shared_secret, sizeof(this->shared_secret));

        /**/
        random.generate_16(this->client_challenge, false);
    }

    void altered_MS_CHAPV2_m1_client_sender_t::send(SSL *ssl)
    {

        /**/
        std::string message_to_send = message_identifier.to_s();
        message_to_send
            .append(username)
            .append(".");

        /**/
        for (size_t i = 0; i < sizeof(client_challenge); i++)
        {
            message_to_send.push_back(client_challenge[i]);
        }

        unsigned char challenge_response[512];
        size_t challenge_response_index = 0;
        bzero(challenge_response, sizeof(challenge_response));

        /**/
        COPY_N_SLIDE(challenge_response, server_challenge, sizeof(server_challenge), challenge_response_index);

        /**/
        std::string session_id_str = std::to_string(session_id);
        COPY_N_SLIDE(challenge_response, session_id_str, session_id_str.size(), challenge_response_index);
        COPY_N_SLIDE(challenge_response, shared_secret, sizeof(shared_secret), challenge_response_index);

        /**/
        unsigned char challenge_hash[encryption::SHA_256_SIZE];
        if (!encryption::packet(challenge_response, challenge_response_index).getShaSum(challenge_hash))
        {

            /**/
            throw std::invalid_argument("hash cannot be computed");
        }

        for (size_t i = 0; i < sizeof(challenge_hash); i++)
        {
            message_to_send.push_back(challenge_hash[i]);
        }

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
        char client_challenge_buff[MAX_CHALLENGE_SIZE];
        char challenge_response_buff[MAX_HASH_SIZE];

        /**/
        bzero(username_buff, sizeof(username_buff));
        bzero(client_challenge_buff, sizeof(client_challenge_buff));
        bzero(challenge_response_buff, sizeof(challenge_response_buff));

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
        unsigned const char *shared_secret
    ) {

        std::string session_id_str = std::to_string(session_id);

        // the pseudorandom string (A), the session identifier (IdS), the user password, under the SHA256.
        std::string data_to_hash;
        PUSH_BACK(data_to_hash, server_challenge, MAX_CHALLENGE_SIZE);
        PUSH_BACK(data_to_hash, session_id_str, session_id_str.size());
        PUSH_BACK(data_to_hash, shared_secret, MAX_KEY_SIZE);

        /**/
        std::string challenge_hash = encryption::compute_hash(data_to_hash);
        return strncmp(challenge_hash.c_str(), (const char *) hashed_challenge, MAX_HASH_SIZE) == 0;
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

        unsigned char challenge_response[512];
        bzero(challenge_response, sizeof(challenge_response));

        /**/
        size_t challenge_response_index = 0;

        /**/
        COPY_N_SLIDE(challenge_response, client_challenge, sizeof(client_challenge), challenge_response_index);
        COPY_N_SLIDE(challenge_response, shared_secret, sizeof(shared_secret), challenge_response_index);

        unsigned char challenge_hash[encryption::SHA_256_SIZE];
        if (!encryption::packet(challenge_response, challenge_response_index).getShaSum(challenge_hash))
        {

            /**/
            throw std::invalid_argument("hash cannot be computed");
        }

        /**/
        std::string message_to_send = message_identifier.to_s();
        PUSH_BACK(message_to_send, challenge_hash, sizeof(challenge_hash));

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

    bool altered_MS_CHAPV2_m2_server_receiver_t::valid_response(unsigned const char *client_challenge, unsigned const char *shared_secret) {

        /* the pseudorandom string (B) and the user's password are all encrypted*/

        std::string data_to_hash;
        PUSH_BACK(data_to_hash, client_challenge, MAX_CHALLENGE_SIZE);
        PUSH_BACK(data_to_hash, shared_secret, MAX_KEY_SIZE);

        return utils::equal(encryption::compute_hash(data_to_hash), utils::string_from_bytes(hashed_challenge, MAX_HASH_SIZE));
    }

    altered_MS_CHAPV2_message::altered_MS_CHAPV2_message() {}

    std::optional<altered_MS_CHAPV2_message> parse(const char *raw_message, size_t n)
    {

        std::optional<altered_MS_CHAPV2_message> ret_value = std::nullopt;

        altered_MS_CHAPV2_identifier_t m_identifier;
        altered_MS_CHAPV2_identifier_t m1_s = altered_MS_CHAPV2_identifier_t(m1_server);
        altered_MS_CHAPV2_identifier_t m2_s = altered_MS_CHAPV2_identifier_t(m2_server);
        altered_MS_CHAPV2_identifier_t m1_c = altered_MS_CHAPV2_identifier_t(m1_client);

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
            return ret_value;
        }

        try
        {
            if (m_identifier.message_type == m1_s.message_type)
            {

                /**/
                altered_MS_CHAPV2_message message;
                message.type = m1_server;
                message.m1_server = altered_MS_CHAPV2_m1_server_receiver_t(raw_message, n);
                ret_value = message;
            }
            else if (m_identifier.message_type == m2_s.message_type)
            {

                /**/
                altered_MS_CHAPV2_message message;
                message.type = m2_server;
                message.m2_server = altered_MS_CHAPV2_m2_server_receiver_t(raw_message, n);
                ret_value = message;
            }
            else
            {

                /**/
                altered_MS_CHAPV2_message message;
                message.type = m1_client;
                message.m1_client = altered_MS_CHAPV2_m1_client_receiver_t(raw_message, n);
                ret_value = message;
            }
        }
        catch (const std::exception &e)
        {
            std::cerr << e.what() << '\n';
        }

        return ret_value;
    }

}