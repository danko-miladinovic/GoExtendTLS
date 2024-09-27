#ifndef _TLS_EXTENSION_SERVER_
#define _TLS_EXTENSION_SERVER_

#define CUSTOM_NONCE_EXT_TYPE 12345  // Custom extension type ID
#define SERVER_ATT_REPORT_EXT_TYPE 54321 
#define CLIENT_RANDOM_SIZE 32

int start_tls_server(char *cert_file, char *key_file, int port);


int tls_extension_client(char *address, int port);

#endif // _TLS_EXTENSION_SERVER_