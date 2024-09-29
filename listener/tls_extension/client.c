#include <openssl/ssl.h>
#include <openssl/err.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

// #define HOST "127.0.0.1"
// #define PORT 4433
#define CUSTOM_NONCE_EXT_TYPE 12345  // Custom extension type ID
#define SERVER_ATT_REPORT_EXT_TYPE 54321  // Custom extension type for server response
#define CLIENT_RANDOM_SIZE 32

void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX *create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = SSLv23_client_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
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

int nonce_client_ext_add_cb(SSL *s, unsigned int ext_type,
                                        unsigned int context,
                                        const unsigned char **out,
                                        size_t *outlen, X509 *x,
                                        size_t chainidx, int *al,
                                        void *add_arg)
{
    unsigned char* client_random_buffer = malloc(CLIENT_RANDOM_SIZE);
    unsigned char* client_random_print_buffer = malloc(CLIENT_RANDOM_SIZE * 2 + 1); 

    SSL_get_client_random(s, client_random_buffer, CLIENT_RANDOM_SIZE);
    
    printf("nonce_client_ext_add_cb from client called!\n");

    switch (ext_type) {
        case CUSTOM_NONCE_EXT_TYPE:
            sprint_string_hex((char*)client_random_print_buffer, (const unsigned char*)client_random_buffer, CLIENT_RANDOM_SIZE);
            printf("ADDING NONCE TO THE ATTESTATION EXTENSION: %s\n", client_random_print_buffer);
            SSL_get_client_random(s, client_random_buffer, CLIENT_RANDOM_SIZE); 
            free(client_random_print_buffer);
            *out = client_random_buffer;
            *outlen = CLIENT_RANDOM_SIZE;
            break;
        case SERVER_ATT_REPORT_EXT_TYPE:
            printf("AAAAA\n");
            // *out = client_random_buffer;
            // *outlen = client_random_print_buffer;
            break;
        default:
            break;
    }

    return 1;
}

void nonce_client_ext_free_cb(SSL *s, unsigned int ext_type,
                                          unsigned int context,
                                          const unsigned char *out,
                                          void *add_arg)
{
    free((void*)out);
    printf("nonce_client_ext_free_cb from client called!\n");
}

int nonce_client_ext_parse_cb(SSL *s, unsigned int ext_type,
                                          unsigned int context,
                                          const unsigned char *in,
                                          size_t inlen, X509 *x,
                                          size_t chainidx, int *al,
                                          void *parse_arg)
{
    printf("nonce_client_ext_parse_cb from client called!\n");
    return 1;
}

/* ----------------------------------------------------------- */

/* --------------------- ATTESTATION EXTENSION --------------------- */

int attestaton_client_ext_add_cb(SSL *s, unsigned int ext_type,
                                        unsigned int context,
                                        const unsigned char **out,
                                        size_t *outlen, X509 *x,
                                        size_t chainidx, int *al,
                                        void *add_arg)
{
    printf("attestaton_client_ext_add_cb from client called!\n");

    printf("Context: %u\n", context);

    switch (ext_type) {
        case SERVER_ATT_REPORT_EXT_TYPE:
            printf("AAAAA\n");
            // *out = client_random_buffer;
            // *outlen = client_random_print_buffer;
            break;
        default:
            break;
    }

    return 1;
}

void  attestation_client_ext_free_cb(SSL *s, unsigned int ext_type,
                                          unsigned int context,
                                          const unsigned char *out,
                                          void *add_arg)
{
    printf("attestation_client_ext_free_cb from client called!\n");
}

int  attestation_client_ext_parse_cb(SSL *s, unsigned int ext_type,
                                          unsigned int context,
                                          const unsigned char *in,
                                          size_t inlen, X509 *x,
                                          size_t chainidx, int *al,
                                          void *parse_arg)
{
    printf("attestation_client_ext_parse_cb from client called!\n");
    char* hex_buffer = malloc(inlen*2 + 1); 
    sprint_string_hex(hex_buffer, in, inlen);
    printf("Receiving sha256 of public key from server: %s\n", hex_buffer);

    if (x != NULL) {
        unsigned char hash[SHA256_DIGEST_LENGTH];

        printf("X509 certificate is not null.\n");
        printf("Context: %u\n", context);

        compute_sha256_of_public_key(x, hash);
        sprint_string_hex(hex_buffer, hash, 32);
        printf("Receiving sha256 of public key from server: %s\n", hex_buffer);
    }

    // verify_attestation(in,inlen);
    // printf("=== ATTESTATION EXTENXION (%lu): Message from server ===\n", sizeof(attestation_report));
    // print_attestation_report_hex((attestation_report*)in);
    return 1;
}

/* ----------------------------------------------------------------- */

int add_custom_tls_extension(SSL_CTX *ctx) {
    uint32_t flags_nonce = SSL_EXT_CLIENT_HELLO | SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS; 
    uint32_t flags_report = SSL_EXT_CLIENT_HELLO | SSL_EXT_TLS1_3_CERTIFICATE;
                        // SSL_EXT_TLS1_3_SERVER_HELLO |
                        // SSL_EXT_CLIENT_HELLO;

    // SSL_CTX_add_custom_ext(ctx, 
    //                     CUSTOM_NONCE_EXT_TYPE,
    //                     flags_nonce,
    //                     nonce_client_ext_add_cb, 
    //                     nonce_client_ext_free_cb, 
    //                     NULL, 
    //                     nonce_client_ext_parse_cb, 
    //                     NULL);

    SSL_CTX_add_custom_ext(ctx, 
                        SERVER_ATT_REPORT_EXT_TYPE,
                        flags_report,
                        attestaton_client_ext_add_cb, 
                        attestation_client_ext_free_cb, 
                        NULL, 
                        attestation_client_ext_parse_cb, 
                        NULL);
    return 1;
}

int tls_extension_client(char *address, int port) {
    SSL_CTX *ctx;
    SSL *ssl;
    int server;
    struct sockaddr_in addr;

    init_openssl();
    ctx = create_context();
    add_custom_tls_extension(ctx);

    server = socket(AF_INET, SOCK_STREAM, 0);
    if (server < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, address, &addr.sin_addr);

    if (connect(server, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Unable to connect");
        exit(EXIT_FAILURE);
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, server);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
    } else {
        char buffer[1024] = {0};
        SSL_read(ssl, buffer, sizeof(buffer));
        printf("Received: %s\n", buffer);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(server);
    SSL_CTX_free(ctx);
    cleanup_openssl();

    return 0;
}
