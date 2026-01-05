CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -lssl -lcrypto
HOOK_LDFLAGS = -shared -ldl

CLIENT = tls_client
SERVER = tls_server
HOOK_LIB = hook.so

CLIENT_SRC = tls_client.c
SERVER_SRC = tls_server.c
HOOK_SRC = hook.c

ifeq ($(VERIFY), 0)
    CLIENT_CFLAGS += -DNO_VERIFY
endif

all: $(CLIENT) $(SERVER) $(HOOK_LIB)

$(CLIENT): $(CLIENT_SRC)
	$(CC) $(CFLAGS) $(CLIENT_CFLAGS) $(CLIENT_SRC) -o $(CLIENT) $(LDFLAGS)

$(SERVER): $(SERVER_SRC)
	$(CC) $(CFLAGS) $(SERVER_SRC) -o $(SERVER) $(LDFLAGS)

$(HOOK_LIB): $(HOOK_SRC)
	$(CC) $(CFLAGS) -fPIC $(HOOK_SRC) -o $(HOOK_LIB) $(HOOK_LDFLAGS)

clean:
	rm -f $(CLIENT) $(SERVER) $(HOOK_LIB)

.PHONY: all clean