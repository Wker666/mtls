#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <openssl/x509.h>

typedef int (*orig_verify_func)(X509_STORE_CTX *ctx);

int X509_verify_cert(X509_STORE_CTX *ctx) {
    static orig_verify_func real_verify = NULL;
    if (!real_verify) {
        real_verify = (orig_verify_func)dlsym(RTLD_NEXT, "X509_verify_cert");
    }
    printf("[Hook] X509_verify_cert called! Forcing success...\n");
    return 1; 
}