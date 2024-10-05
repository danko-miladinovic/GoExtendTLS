#ifndef TLS_EXTENSION_H
#define TLS_EXTENSION_H

#include <openssl/ssl.h>
#include <arpa/inet.h>
#include <pthread.h>

#define CUSTOM_NONCE_EXT_TYPE 12345  // Custom extension type ID
#define SERVER_ATT_REPORT_EXT_TYPE 54321 
#define EVIDENCE_REQUEST_HELLO_EXTENSION_TYPE 65
#define ATTESTATION_CERTIFICATE_EXTENSION_TYPE 66
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
} tls_connection;

void sprint_string_hex(char* dst, const unsigned char* s, int len);
tls_server_connection* start_tls_server(char *ip, char *cert_file, char *key_file, int port);
tls_connection* tls_server_accept(tls_server_connection *tls_server);
int tls_server_close(tls_server_connection *tls_server);
int tls_read(tls_connection *conn, void *buf, int num);
int tls_write(tls_connection *conn, const void *buf, int num);
int tls_close(tls_connection *conn);
int tls_extension_client(char *address, int port);

// Extensions
void evidence_request_ext_free_cb(SSL *s, unsigned int ext_type,
                                    unsigned int context,
                                    const unsigned char *out,
                                    void *add_arg);
int evidence_request_ext_add_cb(SSL *s, unsigned int ext_type,
                                unsigned int context,
                                const unsigned char **out,
                                size_t *outlen, X509 *x,
                                size_t chainidx, int *al,
                                void *add_arg);
int evidence_request_ext_parse_cb(SSL *s, unsigned int ext_type,
                                          unsigned int context,
                                          const unsigned char *in,
                                          size_t inlen, X509 *x,
                                          size_t chainidx, int *al,
                                          void *parse_arg);
void  attestation_certificate_ext_free_cb(SSL *s, unsigned int ext_type,
                                    unsigned int context,
                                    const unsigned char *out,
                                    void *add_arg);
int attestation_certificate_ext_add_cb(SSL *s, unsigned int ext_type,
                                unsigned int context,
                                const unsigned char **out,
                                size_t *outlen, X509 *x,
                                size_t chainidx, int *al,
                                void *add_arg);
int  attestation_certificate_ext_parse_cb(SSL *s, unsigned int ext_type,
                                          unsigned int context,
                                          const unsigned char *in,
                                          size_t inlen, X509 *x,
                                          size_t chainidx, int *al,
                                          void *parse_arg);

#endif // TLS_EXTENSION_H