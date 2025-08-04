#include <iostream>
#include <cstring>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 5555
#define CERT_FILE "KeysAndCerts/server_cert.pem"
#define KEY_FILE "KeysAndCerts/server_private_key.pem"
#define CA_CERT_FILE "KeysAndCerts/ca_cert.pem"
#define CRL_FILE "KeysAndCerts/ca_crl.pem"

void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX* create_context() {
    const SSL_METHOD* method = TLS_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

void configure_context(SSL_CTX* ctx) {
    // Load server certificate and private key
    if (SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    // Set to require and verify client certificate
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);

    // Load CA certificate to verify client
    if (!SSL_CTX_load_verify_locations(ctx, CA_CERT_FILE, nullptr)) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    // ========== NEW: CRL Integration Start ==========
    X509_STORE* store = SSL_CTX_get_cert_store(ctx);
    if (!store) {
        std::cerr << "Error: Failed to get X509_STORE from SSL_CTX\n";
        exit(EXIT_FAILURE);
    }

    X509_LOOKUP* lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
    if (!lookup) {
        std::cerr << "Error: Failed to add CRL lookup\n";
        exit(EXIT_FAILURE);
    }

    if (!X509_LOOKUP_load_file(lookup, CRL_FILE, X509_FILETYPE_PEM)) {
        std::cerr << "Error: Failed to load CRL file: " << CRL_FILE << "\n";
        exit(EXIT_FAILURE);
    }

    X509_VERIFY_PARAM* param = X509_VERIFY_PARAM_new();
    if (!param) {
        std::cerr << "Error: Failed to create X509_VERIFY_PARAM\n";
        exit(EXIT_FAILURE);
    }

    X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
    SSL_CTX_set1_param(ctx, param);
    X509_VERIFY_PARAM_free(param);
    // ========== CRL Integration End ==========
}

int main() {
    init_openssl();
    SSL_CTX* ctx = create_context();
    configure_context(ctx);

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    sockaddr_in addr {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(sockfd, 1) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    std::cout << "Server is listening on port " << PORT << "...\n";

    sockaddr_in client_addr;
    socklen_t len = sizeof(client_addr);
    int client_sock = accept(sockfd, (struct sockaddr*)&client_addr, &len);
    if (client_sock < 0) {
        perror("Accept failed");
        exit(EXIT_FAILURE);
    }

    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client_sock);

    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
    } else {
        std::cout << "SSL Connection established successfully.\n";
        const char* reply = "Hello from server!";
        SSL_write(ssl, reply, strlen(reply));

        // int ans = SSL_write(ssl, reply, strlen(reply));
        // std::cout << ans << std::endl;

        char buffer[1024] = {0};
        SSL_read(ssl, buffer, sizeof(buffer));
        std::cout << "Client says: " << buffer << "\n";
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_sock);
    close(sockfd);

    SSL_CTX_free(ctx);
    cleanup_openssl();

    return 0;
}
