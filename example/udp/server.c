#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

int main() {
    SSL_library_init();
    SSL_CTX *ctx = SSL_CTX_new(DTLS_server_method());

    SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM);

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(6666), .sin_addr.s_addr = INADDR_ANY };
    bind(fd, (struct sockaddr *)&addr, sizeof(addr));

    printf("DTLS Server listening on 6666...\n");

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t len = sizeof(client_addr);
        
        char buf[1];
        recvfrom(fd, buf, 1, MSG_PEEK, (struct sockaddr *)&client_addr, &len);
        connect(fd, (struct sockaddr *)&client_addr, len);

        SSL *ssl = SSL_new(ctx);
        BIO *bio = BIO_new_dgram(fd, BIO_NOCLOSE);
        SSL_set_bio(ssl, bio, bio);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
        } else {
            char read_buf[1024] = {0};
            SSL_read(ssl, read_buf, sizeof(read_buf));
            printf("Received: %s\n", read_buf);
            SSL_write(ssl, "Hello from C Server", 19);
        }

        SSL_free(ssl);
        struct sockaddr_in any = { .sin_family = AF_UNSPEC };
        connect(fd, (struct sockaddr *)&any, sizeof(any));
    }
    return 0;
}