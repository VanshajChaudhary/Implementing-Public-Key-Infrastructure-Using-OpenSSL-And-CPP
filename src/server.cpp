#include<bits/stdc++.h>
#include<openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <netinet/in.h>  // Required for struct sockaddr_in, htons, etc
#include <arpa/inet.h>   // Optional, for inet_pton etc
#include "../include/cxxopts.hpp"

#include "../include/ca_setup.hpp"

using namespace std;


int main(int argc, char* argv[]){

    cxxopts::Options options("PKI Server", "CLI-based Secure Server using OpenSSL");

    options.add_options()
        ("port", "Port number to bind", cxxopts::value<int>()->default_value("8080"))
        ("cert", "Server certificate path", cxxopts::value<std::string>())
        ("key", "Server private key path", cxxopts::value<std::string>())
        ("ca", "CA certificate path", cxxopts::value<std::string>()->default_value("./KeysAndCerts/RootCA_Certificate.pem"))
        ("help", "Print help");

    auto result = options.parse(argc, argv);

    if (result.count("help")) {
        cout << options.help() << endl;
        return 0;
    }

    int port = result["port"].as<int>();
    std::string certPath = result["cert"].as<std::string>();
    std::string keyPath = result["key"].as<std::string>();
    std::string caPath = result["ca"].as<std::string>();

    // Step 1: Initialize OpenSSL (once)

    SSL_library_init();         // ALWAYS RETURNS 1
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();


    // Step 2: Create SSL_CTX (server-side context)

    SSL_CTX*  serverCTX = SSL_CTX_new(TLS_server_method());

    if ( !(serverCTX)){
        cerr<< "serverCTX Not Created" << endl;
        return 1;
    }


    // Step 3: Load Server Certificate and Pvt Key

    if (!(SSL_CTX_use_certificate_file(serverCTX, "/home/avdesh_chaudhary/PKI/KeysAndCerts/Server_Certificate.pem", SSL_FILETYPE_PEM))) {
        cerr << "Failed to Load Server Certificate" << endl;
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(serverCTX);
        return 1;
    }    

    if (!(SSL_CTX_use_PrivateKey_file(serverCTX, "/home/avdesh_chaudhary/PKI/KeysAndCerts/Server_PrivateKey.pem", SSL_FILETYPE_PEM))){
        cerr << "Failed to load Server Private Key" << endl;
        ERR_print_errors_fp(stderr);  // Display OpenSSL error stack
        SSL_CTX_free(serverCTX);
        return 1;
    }

    if (!(SSL_CTX_load_verify_locations(serverCTX, caPath.c_str(), NULL))){  // Checks the Pvt Key of Server with it's certificate
        cerr << "Server Private Key doesn't Match with Server Certificate" << endl;
        ERR_print_errors_fp(stderr);  // Display OpenSSL error stack
        SSL_CTX_free(serverCTX);
        return 1;
    }  


    // Step 4: Load & Trust Root CA Certificate

    
    // Load trusted CA cert for verifying client
    if ( !(SSL_CTX_load_verify_locations(serverCTX, "/home/avdesh_chaudhary/PKI/KeysAndCerts/RootCA_Certificate.pem", NULL))){
        cerr << "Failed to Load CA Certificate" << endl;
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(serverCTX);
        return 1;
    } 

    // Enforce client certificate verification
    SSL_CTX_set_verify(serverCTX, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);


    // Step 4. Socket Creation and Binding 

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    // int port = 8080;

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    cout << "Bind Successful" << endl;

    if (listen(server_fd, SOMAXCONN) < 0) {
        perror("Listen failed");
        close(server_fd);
        return 1;
    }

    cout << "Listen Successful" << endl;

    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &addr_len);
    if (client_fd < 0) {
        perror("Accept failed");
        close(server_fd);
        return 1;
    }

    cout << "Accept Passed" << endl;

    SSL* ssl = SSL_new(serverCTX);
    SSL_set_fd(ssl, client_fd);

    int ssl_accept_status = SSL_accept(ssl);
    if (ssl_accept_status <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(client_fd);
        close(server_fd);
        SSL_CTX_free(serverCTX);
        return 1;
    }

    char buffer[4096] = {0};

    // Step 8: Receive message from client
    int bytes_read = SSL_read(ssl, buffer, sizeof(buffer));
    if (bytes_read <= 0) {
        cerr << "Failed to read data from client over SSL" << endl;
        ERR_print_errors_fp(stderr);
    } else {
        cout << "Secure message received from client: " << buffer << endl;
    }

    // Step 9: Send reply to client
    const char* reply = "Hello from Secure Server!";
    int bytes_written = SSL_write(ssl, reply, strlen(reply));
    if (bytes_written <= 0) {
        cerr << "Failed to send data to client over SSL" << endl;
        ERR_print_errors_fp(stderr);
    }

    // Step 10: Cleanup and shutdown

    SSL_shutdown(ssl);       // Gracefully close the SSL session
    SSL_free(ssl);           // Free the SSL structure
    close(client_fd);        // Close the accepted client socket
    close(server_fd);        // Close the server listening socket
    SSL_CTX_free(serverCTX); // Free the SSL context


return 0;

}

