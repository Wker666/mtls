#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 6666

void handle_openssl_error() {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

int main() {
    SSL_CTX *ctx;
    SSL *ssl;
    int sockfd, clientfd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len;
    char buffer[1024];

    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) handle_openssl_error();

    if (SSL_CTX_use_certificate_file(ctx, "certs/ca-cert.pem", SSL_FILETYPE_PEM) <= 0) handle_openssl_error();
    if (SSL_CTX_use_PrivateKey_file(ctx, "certs/ca-key.pem", SSL_FILETYPE_PEM) <= 0) handle_openssl_error();

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    if (listen(sockfd, 1) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    printf("Waiting for client connection...\n");
    client_len = sizeof(client_addr);
    clientfd = accept(sockfd, (struct sockaddr*)&client_addr, &client_len);
    if (clientfd < 0) {
        perror("accept");
        exit(EXIT_FAILURE);
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, clientfd);

    if (SSL_accept(ssl) <= 0) handle_openssl_error();

    while (1) {
        int len = SSL_read(ssl, buffer, sizeof(buffer) - 1);
        if (len > 0) {
            buffer[len] = '\0';
            printf("Received: %s\n", buffer);

            SSL_write(ssl, buffer, len);
        } else {
            break;
        }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(clientfd);
    close(sockfd);
    SSL_CTX_free(ctx);
    EVP_cleanup();

    return 0;
}
