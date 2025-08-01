#include <iostream>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <cstring>

#define SERVER_IP "127.0.0.1"
#define PORT 5555
#define CERT_FILE "KeysAndCerts/client_cert.pem"
#define KEY_FILE "KeysAndCerts/client_private_key.pem"
#define CA_CERT_FILE "KeysAndCerts/ca_cert.pem"

void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX* create_context() {
    const SSL_METHOD* method = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void configure_context(SSL_CTX* ctx) {
    // Load client cert and key
    if (SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Load and trust the CA cert
    if (!SSL_CTX_load_verify_locations(ctx, CA_CERT_FILE, nullptr)) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
    SSL_CTX_set_verify_depth(ctx, 1);
}

int main() {
    init_openssl();
    SSL_CTX* ctx = create_context();
    configure_context(ctx);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    inet_pton(AF_INET, SERVER_IP, &addr.sin_addr);

    if (connect(sock, (sockaddr*)&addr, sizeof(addr)) != 0) {
        perror("Connection failed");
        exit(EXIT_FAILURE);
    }

    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
    } else {
        std::cout << "TLS handshake successful.\n";

        std::string msg = "Hello from Secure Client!";
        SSL_write(ssl, msg.c_str(), msg.length());

        char buffer[1024] = {0};
        SSL_read(ssl, buffer, sizeof(buffer));
        std::cout << "Server says: " << buffer << "\n";
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
    return 0;
}
