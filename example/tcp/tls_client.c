#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h> 
#include <openssl/ssl.h>
#include <openssl/err.h>

#define SERVER_HOST "127.0.0.1"
#define SERVER_PORT "6666"

void handle_openssl_error() {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

int main() {
    SSL_CTX *ctx;
    SSL *ssl;
    int sockfd;
    struct addrinfo hints, *res, *p;
    char buffer[1024];

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) handle_openssl_error();

#ifdef NO_VERIFY
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
#else
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    printf("Verify mode: %d\n", SSL_VERIFY_PEER);
    if (!SSL_CTX_load_verify_locations(ctx, "certs/ca-cert.pem", NULL))
        handle_openssl_error();
#endif

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    int status = getaddrinfo(SERVER_HOST, SERVER_PORT, &hints, &res);
    if (status != 0) {
        fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
        exit(EXIT_FAILURE);
    }

    for (p = res; p != NULL; p = p->ai_next) {
        sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockfd < 0) continue;

        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == 0) break; 

        close(sockfd);
    }

    if (p == NULL) {
        fprintf(stderr, "Failed to connect to %s\n", SERVER_HOST);
        exit(EXIT_FAILURE);
    }
    
    freeaddrinfo(res);

    ssl = SSL_new(ctx);
    
    SSL_set_tlsext_host_name(ssl, SERVER_HOST);
    
    SSL_set_fd(ssl, sockfd);

    if (SSL_connect(ssl) <= 0) {
        handle_openssl_error();
    } 

    while (1) {
        printf("Enter message: ");
        if (!fgets(buffer, sizeof(buffer), stdin)) break;
        
        if (SSL_write(ssl, buffer, strlen(buffer)) <= 0) {
            printf("Error sending data\n");
            break;
        }

        int len = SSL_read(ssl, buffer, sizeof(buffer) - 1);
        if (len > 0) {
            buffer[len] = '\0';
            printf("Server replied: %s\n", buffer);
        } else {
            printf("Connection closed by server\n");
            break;
        }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);
    EVP_cleanup();

    return 0;
}