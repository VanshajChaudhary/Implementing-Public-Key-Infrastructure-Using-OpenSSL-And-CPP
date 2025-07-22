#ifndef CA_SETUP_HPP
#define CA_SETUP_HPP

#include<bits/stdc++.h>
#include<openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>  // Required for PEM_write_RSAPrivateKey
#include <openssl/asn1.h>

#define ONEDAY 24*60*60

using namespace std;

// Key Generation
EVP_PKEY* keyGeneration(int bits);
EVP_PKEY* generate_RSA_Key_Pair(int bits);
bool save_private_key(EVP_PKEY* key, const char *Pvt_Key_Path);
// bool save_public_key(EVP_PKEY* key, const char *filename);


// CA Creation
X509* CA_Creation(EVP_PKEY* key, int validity, const string& CA_Cert_FilePath);
X509* create_self_signed_cert(EVP_PKEY* key, int validityDays, const string& CN_NAME);
bool save_cert_to_pem(X509* cert, const char* CA_Cert_FilePath);


// CSR Creation
X509_REQ* CSR_Creation (EVP_PKEY* key, const string& CSRFilePath);
X509_REQ* create_csr(EVP_PKEY* key, const string& CommonName);
bool save_csr_to_file(X509_REQ* req, const char* CSRFilePath);


// CSR Signing
X509* signCSR(X509_REQ* CSR, EVP_PKEY* ca_key, X509* cert, int validity, const string& CertificateFilePath);
X509* sign_csr_with_ca(X509_REQ* csr, EVP_PKEY* caPrivateKey, X509* caCert, int validity);
bool save_cert_to_pem(X509* cert, const char* CA_Cert_FilePath);


// Certificate Verification
bool certificateVerification(const string& CertificateFilePath, const string& CA_Cert_FilePath);
bool verify_cert(const char* CertificateFilePath, const char* CA_Cert_FilePath);
X509* load_certificate_from_file(const char* filename);





#endif