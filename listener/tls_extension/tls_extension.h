#ifndef TLS_EXTENSION_H
#define TLS_EXTENSION_H

#include <openssl/ssl.h>
#include <arpa/inet.h>
#include <pthread.h>

#define CUSTOM_NONCE_EXT_TYPE 12345  // Custom extension type ID
#define SERVER_ATT_REPORT_EXT_TYPE 54321 
#define CLIENT_RANDOM_SIZE 32
#define TLS_CLIENT_CTX 0
#define TLS_SERVER_CTX 1
#define SSL_ERROR_WANT_READ_WRITE 2

typedef struct tls_server_c
{
    SSL_CTX *ctx;
    int server_fd;
    struct sockaddr_in addr;
} tls_server_connection;

typedef struct tls_c
{
    SSL_CTX *ctx;
    SSL *ssl;
    int socket_fd;
    struct sockaddr_in local_addr;
    struct sockaddr_in remote_addr;
    pthread_mutex_t lock;
    int is_shutdown;
} tls_connection;

tls_server_connection* start_tls_server(char *ip, char *cert_file, char *key_file, int port);
tls_connection* tls_server_accept(tls_server_connection *tls_server);
int tls_server_close(tls_server_connection *tls_server);
int tls_read(tls_connection *conn, void *buf, int num);
int tls_write(tls_connection *conn, const void *buf, int num);
int tls_close(tls_connection *conn);
int tls_extension_client(char *address, int port);

#endif // TLS_EXTENSION_H