#include "../include/ca_setup.hpp"

using namespace std;

// ----------------------------------------
// Key Generation
// ----------------------------------------
EVP_PKEY* keyGeneration(int bits) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) {
        cerr << "Error: Failed to create EVP_PKEY_CTX." << endl;
        return nullptr;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        cerr << "Error: Failed to initialize keygen context." << endl;
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) {
        cerr << "Error: Failed to set RSA key size." << endl;
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        cerr << "Error: Key generation failed." << endl;
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

bool save_private_key(EVP_PKEY* key, const char* filepath) {
    FILE* fp = fopen(filepath, "wb");
    if (!fp) {
        cerr << "Error: Cannot open file to save private key: " << filepath << endl;
        return false;
    }
    bool success = PEM_write_PrivateKey(fp, key, nullptr, nullptr, 0, nullptr, nullptr);
    fclose(fp);
    return success;
}

// ----------------------------------------
// CA Certificate Creation
// ----------------------------------------
X509* create_self_signed_cert(EVP_PKEY* key, int validityDays, const string& commonName) {
    X509* cert = X509_new();
    if (!cert) {
        cerr << "Error: Could not create X509 structure." << endl;
        return nullptr;
    }

    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), validityDays * ONEDAY);
    X509_set_pubkey(cert, key);

    X509_NAME* name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (unsigned char*)commonName.c_str(), -1, -1, 0);

    X509_set_issuer_name(cert, name);  // Self-signed
    if (!X509_sign(cert, key, EVP_sha256())) {
        cerr << "Error: Signing CA certificate failed." << endl;
        X509_free(cert);
        return nullptr;
    }

    return cert;
}

bool save_cert_to_pem(X509* cert, const char* filepath) {
    FILE* fp = fopen(filepath, "wb");
    if (!fp) {
        cerr << "Error: Cannot open file to save certificate: " << filepath << endl;
        return false;
    }
    bool success = PEM_write_X509(fp, cert);
    fclose(fp);
    return success;
}

// ----------------------------------------
// CSR Creation
// ----------------------------------------
X509_REQ* create_csr(EVP_PKEY* key, const string& commonName) {
    X509_REQ* req = X509_REQ_new();
    if (!req) {
        cerr << "Error: Could not create CSR object." << endl;
        return nullptr;
    }

    X509_REQ_set_version(req, 1);
    X509_NAME* name = X509_REQ_get_subject_name(req);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (unsigned char*)commonName.c_str(), -1, -1, 0);
    X509_REQ_set_pubkey(req, key);

    if (!X509_REQ_sign(req, key, EVP_sha256())) {
        cerr << "Error: Signing CSR failed." << endl;
        X509_REQ_free(req);
        return nullptr;
    }

    return req;
}

bool save_csr_to_file(X509_REQ* req, const char* filepath) {
    FILE* fp = fopen(filepath, "wb");
    if (!fp) {
        cerr << "Error: Cannot open file to save CSR: " << filepath << endl;
        return false;
    }
    bool success = PEM_write_X509_REQ(fp, req);
    fclose(fp);
    return success;
}

// ----------------------------------------
// Signing CSR with CA
// ----------------------------------------
X509* sign_csr_with_ca(X509_REQ* csr, EVP_PKEY* caPrivateKey, X509* caCert, int validityDays) {
    X509* cert = X509_new();
    if (!cert) {
        cerr << "Error: Could not create certificate from CSR." << endl;
        return nullptr;
    }

    ASN1_INTEGER_set(X509_get_serialNumber(cert), 2);
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), validityDays * ONEDAY);

    X509_set_issuer_name(cert, X509_get_subject_name(caCert));
    X509_set_subject_name(cert, X509_REQ_get_subject_name(csr));

    EVP_PKEY* req_pubkey = X509_REQ_get_pubkey(csr);
    X509_set_pubkey(cert, req_pubkey);
    EVP_PKEY_free(req_pubkey);

    if (!X509_sign(cert, caPrivateKey, EVP_sha256())) {
        cerr << "Error: Failed to sign certificate with CA." << endl;
        X509_free(cert);
        return nullptr;
    }

    return cert;
}

bool save_signed_cert_to_file(X509* cert, const char* filepath) {
    FILE* fp = fopen(filepath, "wb");
    if (!fp) {
        cerr << "Error: Cannot open file to save signed certificate: " << filepath << endl;
        return false;
    }
    bool success = PEM_write_X509(fp, cert);
    fclose(fp);
    return success;
}

// ----------------------------------------
// Certificate Verification
// ----------------------------------------
X509* load_certificate_from_file(const char* filepath) {
    FILE* fp = fopen(filepath, "rb");
    if (!fp) {
        cerr << "Error: Cannot open certificate file: " << filepath << endl;
        return nullptr;
    }
    X509* cert = PEM_read_X509(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    return cert;
}

bool verify_cert(const char* certPath, const char* caCertPath) {
    X509* cert = load_certificate_from_file(certPath);
    X509* caCert = load_certificate_from_file(caCertPath);
    if (!cert || !caCert) {
        cerr << "Error: Failed to load cert or CA cert." << endl;
        return false;
    }

    X509_STORE* store = X509_STORE_new();
    X509_STORE_add_cert(store, caCert);

    X509_STORE_CTX* ctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(ctx, store, cert, nullptr);

    int ret = X509_verify_cert(ctx);

    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    X509_free(cert);
    X509_free(caCert);

    return (ret == 1);
}
