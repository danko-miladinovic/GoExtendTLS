#include "tls_extension.h"


/*
    Evidence request extension
    - Contains a random nonce that goes into the attestation report
    - Is sent in the ClientHello message
*/
void evidence_request_ext_free_cb(SSL *s, unsigned int ext_type,
                                    unsigned int context,
                                    const unsigned char *out,
                                    void *add_arg)
{
    printf("evidence_request_ext_free_cb called\n");
}

int evidence_request_ext_add_cb(SSL *s, unsigned int ext_type,
                                unsigned int context,
                                const unsigned char **out,
                                size_t *outlen, X509 *x,
                                size_t chainidx, int *al,
                                void *add_arg)
{
    printf("evidence_request_ext_add_cb called\n");
    printf("evidence_request_ext_add_cb Context: %u\n", context);

    switch (context)
    {
    case SSL_EXT_CLIENT_HELLO:
        {
            unsigned char* client_random_buffer = malloc(CLIENT_RANDOM_SIZE);
            unsigned char* client_random_print_buffer = malloc(CLIENT_RANDOM_SIZE * 2 + 1);

            SSL_get_client_random(s, client_random_buffer, CLIENT_RANDOM_SIZE);
            printf("evidence_request_ext_add_cb Context: SSL_EXT_CLIENT_HELLO\n");
            sprint_string_hex((char*)client_random_print_buffer, (const unsigned char*)client_random_buffer, CLIENT_RANDOM_SIZE);
            printf("ADDING NONCE TO THE ATTESTATION EXTENSION: %s\n", client_random_print_buffer);
            free(client_random_print_buffer);
            *out = client_random_buffer;
            *outlen = CLIENT_RANDOM_SIZE;
            return 1;
        }
    case SSL_EXT_TLS1_3_SERVER_HELLO:
    case SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS:
        printf("evidence_request_ext_add_cb from server: %u\n", context);
        return 0;
    default:
        printf("Context is default: %u\n", context);
        break;
    }

    switch (ext_type) {
        case EVIDENCE_REQUEST_HELLO_EXTENSION_TYPE:
            printf("NONCE EXTENSION CALLED SERVER!\n");
            break;
        default:
            printf("DEFAULT FOR evidence_request CALLED\n");
            break;
    }
    return 0;
}

int evidence_request_ext_parse_cb(SSL *s, unsigned int ext_type,
                                          unsigned int context,
                                          const unsigned char *in,
                                          size_t inlen, X509 *x,
                                          size_t chainidx, int *al,
                                          void *parse_arg)
{
    char* hex_buffer = malloc(inlen*2 + 1); 

    // if (context == SSL_EXT_CLIENT_HELLO) {
    //     printf("evidence_request_ext_parse_cb for SSL_EXT_CLIENT_HELLO\n");
    //     free(hex_buffer);
    //     return 1;
    // }

    sprint_string_hex(hex_buffer, in, inlen);

    printf("evidence_request_ext_parse_cb called\n");
    printf("Receiving nonce from client: %s\n", hex_buffer);
    free(hex_buffer);
    return 1;
}

/*
    Attestation Certificate extension
    - Contains the attestation report
    - The attestation report contains the hash of the nonce and the Publik Key of the x.509 Agent certificate
*/
void  attestation_certificate_ext_free_cb(SSL *s, unsigned int ext_type,
                                    unsigned int context,
                                    const unsigned char *out,
                                    void *add_arg)
{
    printf("attestation_certificate_ext_free_cb from server called\n");
}

int attestation_certificate_ext_add_cb(SSL *s, unsigned int ext_type,
                                unsigned int context,
                                const unsigned char **out,
                                size_t *outlen, X509 *x,
                                size_t chainidx, int *al,
                                void *add_arg)
{
    unsigned char *hash = malloc(SHA256_DIGEST_LENGTH);
    printf("attestation_certificate_ext_add_cb called\n");

    printf("Context for AR: %u\n", context);

    switch (context)
    {
    case SSL_EXT_TLS1_3_CERTIFICATE:
        printf("attestation_certificate_ext_add_cb: SSL_EXT_TLS1_3_CERTIFICATE\n");
        compute_sha256_of_public_key(x, hash);
        *out = hash;
        *outlen = SHA256_DIGEST_LENGTH;
        return 1;
    default:
        printf("Default attestation_certificate_ext_add_cb called: %u\n", context);
        return 1;
    }
}

int  attestation_certificate_ext_parse_cb(SSL *s, unsigned int ext_type,
                                          unsigned int context,
                                          const unsigned char *in,
                                          size_t inlen, X509 *x,
                                          size_t chainidx, int *al,
                                          void *parse_arg)
{   
    char* hex_buffer = malloc(inlen*2 + 1); 
    sprint_string_hex(hex_buffer, in, inlen);
    printf("Receiving sha256 of public key from server: %s\n", hex_buffer);
    printf("attestation_certificate_ext_parse_cb, context: %u\n", context);

    if (x != NULL) {
        unsigned char hash[SHA256_DIGEST_LENGTH];

        printf("X509 certificate is not null.\n");
        printf("Context: %u\n", context);

        compute_sha256_of_public_key(x, hash);
        sprint_string_hex(hex_buffer, hash, 32);
        printf("Receiving sha256 of public key from server: %s\n", hex_buffer);
    }


    return 1;
}