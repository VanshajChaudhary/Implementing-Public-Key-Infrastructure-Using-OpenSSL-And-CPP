#ifndef CA_SETUP_HPP
#define CA_SETUP_HPP

#include <bits/stdc++.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/asn1.h>

#define ONEDAY (24 * 60 * 60)

using namespace std;

// -------------------------
// Key Generation
// -------------------------    
EVP_PKEY* keyGeneration(int bits);  
bool save_private_key(EVP_PKEY* key, const char* filepath);

// -------------------------
// Self-Signed CA Certificate Creation
// -------------------------
X509* create_self_signed_cert(EVP_PKEY* key, int validityDays, const string& commonName);
bool save_cert_to_pem(X509* cert, const char* filepath);

// -------------------------
// Certificate Signing Request (CSR)
// -------------------------
X509_REQ* create_csr(EVP_PKEY* key, const string& commonName);
bool save_csr_to_file(X509_REQ* req, const char* filepath);

// -------------------------
// Signing CSR with CA Certificate
// -------------------------
X509* sign_csr_with_ca(X509_REQ* csr, EVP_PKEY* caPrivateKey, X509* caCert, int validityDays);
bool save_signed_cert_to_file(X509* cert, const char* filepath);

// -------------------------
// Certificate Verification
// -------------------------
bool verify_cert(const char* certPath, const char* caCertPath);
X509* load_certificate_from_file(const char* filepath);

// -------------------------
// Certificate Revocation List
// -------------------------

int revoke_certificate(const std::string& certPath, const std::string& revokedListFile);
int generate_crl(const std::string& caKeyPath, const std::string& caCertPath,
                 const std::string& revokedListFile, const std::string& crlOutPath);

// Helper functions for CRL handling
X509_CRL* create_empty_crl();
bool save_crl_to_pem(X509_CRL* crl, const char* filepath);



#endif // CA_SETUP_HPP
