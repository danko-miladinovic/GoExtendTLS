#ifndef _TLS_EXTENSION_SERVER_
#define _TLS_EXTENSION_SERVER_

int tls_extension_server(char *cert_file, char *key_file, int port);
int tls_extension_client(char *address, int port);

#endif // _TLS_EXTENSION_SERVER_