#include <iostream>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509_vfy.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <cstring>

#define SERVER_IP "127.0.0.1"
#define PORT 5555
#define CERT_FILE "KeysAndCerts/client_cert.pem"
#define KEY_FILE "KeysAndCerts/client_private_key.pem"
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

    // Create a new X509 store and load CA cert
    X509_STORE* store = X509_STORE_new();
    if (!store) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    X509_LOOKUP* lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
    if (!lookup || !X509_LOOKUP_load_file(lookup, CA_CERT_FILE, X509_FILETYPE_PEM)) {
        std::cerr << "Failed to load CA cert into store\n";
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Load CRL
    X509_CRL* crl = nullptr;
    FILE* crl_file = fopen(CRL_FILE, "r");
    if (!crl_file || !(crl = PEM_read_X509_CRL(crl_file, nullptr, nullptr, nullptr))) {
        std::cerr << "Failed to load CRL file\n";
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    fclose(crl_file);

    if (X509_STORE_add_crl(store, crl) != 1) {
        std::cerr << "Failed to add CRL to store\n";
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Set CRL flags
    X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);

    // Attach store to SSL_CTX
    SSL_CTX_set_cert_store(ctx, store);

    // Also enable peer verification
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
    SSL_CTX_set_verify_depth(ctx, 2);
}

int main() {
    init_openssl();
    SSL_CTX* ctx = create_context();
    configure_context(ctx);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
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
        std::cerr << "TLS handshake failed. Possibly due to revoked server certificate.\n";
        ERR_print_errors_fp(stderr);
    } else {
        std::cout << "TLS handshake successful.\n";

        char buffer[1024] = {0};
        SSL_read(ssl, buffer, sizeof(buffer));
        std::cout << "Server says: " << buffer << "\n";
        
        std::string msg = "Hello from Secure Client!";
        SSL_write(ssl, msg.c_str(), msg.length());
         

    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
    return 0;
}
