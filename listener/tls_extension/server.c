#include "tls_extension.h"
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>

void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX *create_context(int is_server) {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    if (is_server) {
        method = TLS_server_method();
    } else {
        method = TLS_client_method();
    }
    
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        return NULL; // exit(EXIT_FAILURE);
    }

    return ctx;
}

int configure_context(SSL_CTX *ctx, char *cert_file, char *key_file) {
    printf("Cert file: %s\n", cert_file);
    printf("Key file: %s\n", key_file);
    // Load server certificate and private key
    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        perror("could not configure context");
        return EXIT_FAILURE;
    }
    return 0;
}

void sprint_string_hex(char* dst, const unsigned char* s, int len){ 
    for(int i = 0; i < len; i++){
        sprintf(dst, "%02x", (unsigned int) *s++);
        dst+=2;
    }
}

int compute_sha256_of_public_key(X509 *cert, unsigned char *hash) {
    EVP_PKEY *pkey = NULL;
    unsigned char *pubkey_buf = NULL;
    int pubkey_len = 0;

    pkey = X509_get_pubkey(cert);
    if (pkey == NULL) {
        fprintf(stderr, "Failed to extract public key from certificate\n");
        return 0;
    }
    
    // Convert the public key to DER format (binary encoding)
    pubkey_len = i2d_PUBKEY(pkey, &pubkey_buf);
    if (pubkey_len <= 0) {
        fprintf(stderr, "Failed to convert public key to DER format\n");
        EVP_PKEY_free(pkey);
        return 0;
    }
    
    // Compute the SHA-256 hash of the DER-encoded public key
    SHA256(pubkey_buf, pubkey_len, hash);
    
    // Clean up
    EVP_PKEY_free(pkey);
    OPENSSL_free(pubkey_buf);  // Free memory allocated by i2d_PUBKEY
    
    return 1;  // Success
}

/* --------------------- NONCE EXTENSION --------------------- */

void nonce_server_ext_free_cb(SSL *s, unsigned int ext_type,
                                    unsigned int context,
                                    const unsigned char *out,
                                    void *add_arg)
{
    printf("nonce_server_ext_free_cb from server called\n");
}

int nonce_server_ext_add_cb(SSL *s, unsigned int ext_type,
                                unsigned int context,
                                const unsigned char **out,
                                size_t *outlen, X509 *x,
                                size_t chainidx, int *al,
                                void *add_arg)
{
    unsigned char* client_random_buffer = malloc(CLIENT_RANDOM_SIZE);
    unsigned char* client_random_print_buffer = malloc(CLIENT_RANDOM_SIZE * 2 + 1); 
    printf("nonce_server_ext_add_cb from server called\n");
    printf("Context: %u\n", context);

    switch (ext_type) {
        case CUSTOM_NONCE_EXT_TYPE:
            printf("NONCE EXTENSION CALLED SERVER!\n");
            break;
        default:
            printf("DEFAULT FOR NONCE SERVER EXT_TYPE CALLED\n");
            break;
    }
    return 0;
}

int nonce_server_ext_parse_cb(SSL *s, unsigned int ext_type,
                                          unsigned int context,
                                          const unsigned char *in,
                                          size_t inlen, X509 *x,
                                          size_t chainidx, int *al,
                                          void *parse_arg)
{
    char* hex_buffer = malloc(inlen*2 + 1); 
    sprint_string_hex(hex_buffer, in, inlen);

    printf("nonce_server_ext_parse_cb from server called\n");
    printf("Receiving nonce from client: %s\n", hex_buffer);
    return 1;
}

/* ----------------------------------------------------------- */

/* --------------------- ATTESTATION EXTENSION --------------------- */

void  attestation_server_ext_free_cb(SSL *s, unsigned int ext_type,
                                    unsigned int context,
                                    const unsigned char *out,
                                    void *add_arg)
{
    printf("attestation_server_ext_free_cb from server called\n");
}

int attestation_server_ext_add_cb(SSL *s, unsigned int ext_type,
                                unsigned int context,
                                const unsigned char **out,
                                size_t *outlen, X509 *x,
                                size_t chainidx, int *al,
                                void *add_arg)
{
    unsigned char *hash = malloc(SHA256_DIGEST_LENGTH);
    printf("attestation_server_ext_add_cb from server called\n");

    printf("Context for AR: %u\n", context);

    switch (ext_type) {
        case SERVER_ATT_REPORT_EXT_TYPE:
            printf("ATTESTATION\n");
            compute_sha256_of_public_key(x, hash);
            *out = hash;
            *outlen = SHA256_DIGEST_LENGTH;
            break;
        default:
            printf("DEFAULT FOR ATT EXT_TYPE CALLED\n");
            break;
    }
    return 1;
}

int  attestation_server_ext_parse_cb(SSL *s, unsigned int ext_type,
                                          unsigned int context,
                                          const unsigned char *in,
                                          size_t inlen, X509 *x,
                                          size_t chainidx, int *al,
                                          void *parse_arg)
{
    // char* hex_buffer = malloc(inlen*2 + 1); 
    // sprint_string_hex(hex_buffer, in, inlen);

    printf("attestation_server_ext_parse_cb from server called\n");
    // printf("Receiving nonce from client: %s\n", hex_buffer);
    return 1;
}

/* ----------------------------------------------------------------- */

int add_custom_tls_extension(SSL_CTX *ctx) {
    uint32_t flags_nonce = SSL_EXT_CLIENT_HELLO | SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS;
    uint32_t flags_attestation = SSL_EXT_CLIENT_HELLO | SSL_EXT_TLS1_3_CERTIFICATE; // SSL_EXT_TLS1_3_SERVER_HELLO

    // SSL_CTX_add_custom_ext(ctx, 
    //                     CUSTOM_NONCE_EXT_TYPE,
    //                     flags_nonce,
    //                     nonce_server_ext_add_cb, 
    //                     nonce_server_ext_free_cb, 
    //                     NULL, 
    //                     nonce_server_ext_parse_cb, 
    //                     NULL);
    
    SSL_CTX_add_custom_ext(ctx, 
                        SERVER_ATT_REPORT_EXT_TYPE,
                        flags_attestation,
                        attestation_server_ext_add_cb, 
                        attestation_server_ext_free_cb, 
                        NULL, 
                        attestation_server_ext_parse_cb, 
                        NULL);

    return 1;
}

// Function to start the tls server
tls_server_connection* start_tls_server(char *cert_file, char *key_file, int port) {
    // int server_fd;
    // struct sockaddr_in addr;
    // SSL_CTX *ctx;

    tls_server_connection *tls_server = (tls_server_connection*)malloc(sizeof(tls_server_connection));

    init_openssl();
    tls_server->ctx = create_context(TLS_SERVER_CTX);
    if (tls_server->ctx == NULL) {
        free(tls_server);
        perror("Unable to create contex");
        return NULL;
    }

    if (configure_context(tls_server->ctx, cert_file, key_file) != 0) {
        free(tls_server);
        perror("Unable to create contex");
        return NULL;
    }
    // add_custom_tls_extension(tls_server->ctx);

    tls_server->server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (tls_server->server_fd < 0) {
        free(tls_server);
        perror("Unable to create socket");
        return NULL;
    }

    tls_server->addr.sin_family = AF_INET;
    tls_server->addr.sin_port = htons(port);
    tls_server->addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(tls_server->server_fd, (struct sockaddr*)&(tls_server->addr), sizeof(tls_server->addr)) < 0) {
        free(tls_server);
        perror("Unable to bind");
        return NULL;
    }

    if (listen(tls_server->server_fd, 1) < 0) {
        free(tls_server);
        perror("Unable to listen");
        return NULL;
    }

    printf("Listening on port: %d\n", port);

    // while (1) {

    //     } else {
    //         SSL_write(ssl, "Hello, Secure World!\n", strlen("Hello, Secure World!\n"));
    //     }

    //     SSL_shutdown(ssl);
    //     SSL_free(ssl);
    //     close(client);
    // }

    // close(server_fd);
    // SSL_CTX_free(ctx);
    // cleanup_openssl();
    return tls_server;
}

// Function to accept a client connection
tls_connection* tls_server_accept(tls_server_connection *tls_server) {
    // struct sockaddr_in addr;
    uint32_t len = sizeof(tls_server->addr);
    tls_connection *conn = (tls_connection*)malloc(sizeof(tls_connection));

    int client_fd = accept(tls_server->server_fd, (struct sockaddr*)&(tls_server->addr), &len);
    if (client_fd < 0) {
        perror("Unable to accept");
        free(conn);
        return NULL;
    }

    conn->ssl = SSL_new(tls_server->ctx);
    conn->socket_fd = client_fd;
    conn->ctx = NULL;
    SSL_set_fd(conn->ssl, client_fd);

    if (SSL_accept(conn->ssl) <= 0) {
        printf("Unable to accept. Handshake failed.\n");
        free(conn);
        return NULL;
    }

    return conn;
}

// Function to close the server
int tls_server_close(tls_server_connection *tls_server) {
    close(tls_server->server_fd);
    SSL_CTX_free(tls_server->ctx);
    cleanup_openssl();
    free(tls_server);
    return 0;
}

int tls_read(tls_connection *conn, void *buf, int num) {
    return SSL_read(conn->ssl, buf, num);
}

int tls_write(tls_connection *conn, const void *buf, int num) {
    return SSL_write(conn->ssl, buf, num);
}

void tls_close(tls_connection *conn) {
    if (conn != NULL) {
        // if (conn->ssl != NULL) {
        //     SSL_shutdown(conn->ssl);
        // }
        // if (conn->socket_fd >= 0) {
        //     close(conn->socket_fd);
        // }
        // SSL_free(conn->ssl);
        // if (conn->ctx != NULL) {
        //     SSL_CTX_free(conn->ctx);
        // }
        free(conn);
    }
}

void tls_close_cleanup(tls_connection *conn) {
    tls_close(conn);
    cleanup_openssl();
}

void custom_free(void *ptr) {
    free(ptr);
}

tls_connection* new_tls_connection(char *address, int port) {
    SSL_CTX *ctx;
    SSL *ssl;
    int server_fd;
    struct sockaddr_in addr;
    tls_connection *tls_client = (tls_connection*)malloc(sizeof(tls_connection));

    init_openssl();
    ctx = create_context(TLS_CLIENT_CTX);
    if (ctx == NULL) {
        perror("could not create context");
        free(tls_client);
        return NULL;
    }
    // add_custom_tls_extension(ctx);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("unable to create socket");
        free(tls_client);
        return NULL;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, address, &addr.sin_addr);

    if (connect(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("unable to connect");
        free(tls_client);
        return NULL;
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, server_fd);

    if (SSL_connect(ssl) <= 0) {
        perror("unable to connect");
        free(tls_client);
        return NULL;
    }

    tls_client->socket_fd = server_fd;
    tls_client->ssl = ssl;
    tls_client->ctx = ctx;
    return tls_client;
}