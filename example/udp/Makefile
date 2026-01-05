CC = gcc
CFLAGS = -Wall -g
LDFLAGS = -lssl -lcrypto

SERVER_BIN = dtls_server
CLIENT_BIN = dtls_client

all: $(SERVER_BIN) $(CLIENT_BIN)

$(SERVER_BIN): server.c
	$(CC) $(CFLAGS) server.c -o $(SERVER_BIN) $(LDFLAGS)

$(CLIENT_BIN): client.c
	$(CC) $(CFLAGS) client.c -o $(CLIENT_BIN) $(LDFLAGS)

cert:
	openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -nodes -subj "/C=CN/CN=localhost"

clean:
	rm -f $(SERVER_BIN) $(CLIENT_BIN) server.key server.crt

.PHONY: all clean cert