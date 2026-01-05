#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>

int main() {
    SSL_library_init();
    SSL_CTX *ctx = SSL_CTX_new(DTLS_client_method());
    SSL *ssl = SSL_new(ctx);

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in dest_addr = { .sin_family = AF_INET, .sin_port = htons(6666) };
    inet_pton(AF_INET, "127.0.0.1", &dest_addr.sin_addr);
    connect(fd, (struct sockaddr *)&dest_addr, sizeof(dest_addr));

    BIO *bio = BIO_new_dgram(fd, BIO_NOCLOSE);
    BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &dest_addr);
    SSL_set_bio(ssl, bio, bio);

    if (SSL_connect(ssl) <= 0) {
        printf("DTLS Handshake Failed\n");
    } else {
        SSL_write(ssl, "Hello from C Client", 19);
        char buf[1024] = {0};
        SSL_read(ssl, buf, sizeof(buf));
        printf("Server replied: %s\n", buf);
    }

    SSL_free(ssl);
    return 0;
}