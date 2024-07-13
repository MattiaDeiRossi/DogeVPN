#include "client_credentials_utils.h"

namespace client_credentials_utils {

	int initialize(const char* username, const char* password, client_credentials *result) {

		char data[MAX_CREDENTIALS_SIZE];
		int size = utils::concat_with_separator(
			username, strlen(username),
			password, strlen(password),
			data, MAX_CREDENTIALS_SIZE,
			USER_PASSWORD_SEPARATOR
		);

		return initialize(data, size, result);
	}

	int initialize(const char* data, size_t num, client_credentials *result) {

		/* The maximum length for the credentials message is fixed:
	    *  	- The argument num cannot exceed CREDENTIALS_MESSAGE_MAX_LENGTH
		*  	- The argument num must be at least MIN_PASSWORD_SIZE + 2 bytes long (username.password)
	    */
		if ((num < MIN_PASSWORD_SIZE + 2) || (num > MAX_CREDENTIALS_SIZE)) return -1;

		bool reading_username = true;
	    char *usr_p = result->username;
	    char *pwd_p = result->password;

	    size_t password_length = 0;

		memset(result, 0, sizeof(client_credentials));

	    for (size_t i = 0; i < num; ++i) {
	        
	        char bdata = data[i];
	        
	        if (reading_username) {

	            // While reading credentilas alway checking if the separator is the current byte.
	            if (bdata == USER_PASSWORD_SEPARATOR) {
	                reading_username = false;
	            } else {
	                *usr_p = bdata;
	                usr_p++;
	            }
	        } else {

	            // From now on the data that is being read represents the password.
	            *pwd_p = bdata;
	            pwd_p++;
	            password_length++;
	        }
	    }

	    /* A minimum length of bytes for the password is required.
	    *  If the minimum length is not respected, than an error is returned.
	    */
	    if (password_length < MIN_PASSWORD_SIZE) {
	    	return -1;
	    }

		return 0;
	}

	void log_client_credentials(const client_credentials *credentials) {

		const char *message = "%s\n  Username: %s\n  Password: %s\n";
		printf(message, "Reading client credentials", credentials->username, credentials->password);
	}
}