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

// ----------------------------------------
// Certificate Revocation List
// ----------------------------------------

int revoke_certificate(const std::string& certPath, const std::string& revokedListFile) {

    int returnResult = 2;

    FILE* certFile = fopen(certPath.c_str(), "r");
    if (!certFile) {
        cout << "Hello1" << endl;
        std::cerr << "Error: Unable to open certificate to revoke.\n";
        return returnResult;
    }returnResult += 1;

    X509* cert = PEM_read_X509(certFile, nullptr, nullptr, nullptr);
    fclose(certFile);
    if (!cert) {
        cout << "Hello2" << endl;
        std::cerr << "Error: Failed to read certificate.\n";
        return returnResult;
    }returnResult += 1;

    ASN1_INTEGER* serial = X509_get_serialNumber(cert);
    BIGNUM* bn = ASN1_INTEGER_to_BN(serial, nullptr);
    char* hex = BN_bn2hex(bn);
    std::string serialHex(hex);

    BN_free(bn);
    OPENSSL_free(hex);
    X509_free(cert);

    std::ofstream file(revokedListFile, std::ios::app);
    if (!file.is_open()) {
        cout << "Hello3" << endl;
        std::cerr << "Error: Failed to open revoked list file.\n";
        return returnResult;
    }returnResult += 1;

    cout << "Hello4" << endl;
    cout << returnResult << endl;
    cout << "Hello5" << endl;

    file << serialHex << std::endl;
    cout << "Hello6" << endl;

    file.close();
    cout << "Hello7" << endl;

    return 0;
}

int generate_crl(const std::string& caKeyPath, const std::string& caCertPath,
                 const std::string& revokedListFile, const std::string& crlOutPath) {
    FILE* caKeyFile = fopen(caKeyPath.c_str(), "r");
    FILE* caCertFile = fopen(caCertPath.c_str(), "r");
    if (!caKeyFile || !caCertFile) {
        std::cerr << "Error: Unable to open CA key or cert.\n";
        return 1;
    }

    EVP_PKEY* caKey = PEM_read_PrivateKey(caKeyFile, nullptr, nullptr, nullptr);
    X509* caCert = PEM_read_X509(caCertFile, nullptr, nullptr, nullptr);
    fclose(caKeyFile);
    fclose(caCertFile);

    if (!caKey || !caCert) {
        std::cerr << "Error: Failed to load CA key/cert.\n";
        return 1;
    }

    X509_CRL* crl = X509_CRL_new();
    X509_CRL_set_version(crl, 1);  // v2

    X509_NAME* issuer = X509_get_subject_name(caCert);
    X509_CRL_set_issuer_name(crl, issuer);

    ASN1_TIME* lastUpdate = ASN1_TIME_new();
    ASN1_TIME* nextUpdate = ASN1_TIME_new();
    ASN1_TIME_set(lastUpdate, time(nullptr));
    ASN1_TIME_set(nextUpdate, time(nullptr) + 30 * 24 * 3600);  // +30 days

    X509_CRL_set1_lastUpdate(crl, lastUpdate);
    X509_CRL_set1_nextUpdate(crl, nextUpdate);

    ASN1_TIME_free(lastUpdate);
    ASN1_TIME_free(nextUpdate);

    std::ifstream infile(revokedListFile);
    std::string serialHex;
    while (std::getline(infile, serialHex)) {
        BIGNUM* bn = nullptr;
        ASN1_INTEGER* asn1_serial = nullptr;

        BN_hex2bn(&bn, serialHex.c_str());
        asn1_serial = BN_to_ASN1_INTEGER(bn, nullptr);

        X509_REVOKED* revoked = X509_REVOKED_new();
        X509_REVOKED_set_serialNumber(revoked, asn1_serial);

        ASN1_TIME* revocationDate = ASN1_TIME_new();
        ASN1_TIME_set(revocationDate, time(nullptr));
        X509_REVOKED_set_revocationDate(revoked, revocationDate);

        X509_CRL_add0_revoked(crl, revoked);

        ASN1_TIME_free(revocationDate);
        ASN1_INTEGER_free(asn1_serial);
        BN_free(bn);
    }

    infile.close();

    X509_CRL_sort(crl);
    X509_CRL_sign(crl, caKey, EVP_sha256());

    FILE* crlOut = fopen(crlOutPath.c_str(), "w+");
    if (!crlOut || !PEM_write_X509_CRL(crlOut, crl)) {
        std::cerr << "Error: Failed to write CRL.\n";
        return 1;
    }

    fclose(crlOut);
    X509_CRL_free(crl);
    EVP_PKEY_free(caKey);
    X509_free(caCert);
    return 0;
}

X509_CRL* create_empty_crl() {
    X509_CRL* crl = X509_CRL_new();
    if (!crl) {
        cerr << "Error: Could not create new CRL structure.\n";
        return nullptr;
    }

    // Set version to V2
    if (!X509_CRL_set_version(crl, 1)) {
        cerr << "Error: Failed to set CRL version.\n";
        X509_CRL_free(crl);
        return nullptr;
    }

    // Set lastUpdate and nextUpdate
    ASN1_TIME* lastUpdate = ASN1_TIME_new();
    ASN1_TIME* nextUpdate = ASN1_TIME_new();
    ASN1_TIME_set(lastUpdate, time(NULL));
    ASN1_TIME_set(nextUpdate, time(NULL) + ONEDAY); // Valid for 1 day

    X509_CRL_set1_lastUpdate(crl, lastUpdate);
    X509_CRL_set1_nextUpdate(crl, nextUpdate);

    ASN1_TIME_free(lastUpdate);
    ASN1_TIME_free(nextUpdate);

    return crl;
}

bool save_crl_to_pem(X509_CRL* crl, const char* filepath) {
    FILE* fp = fopen(filepath, "wb");
    if (!fp) {
        cerr << "Error: Could not open CRL file for writing: " << filepath << "\n";
        return false;
    }
    
    bool success = PEM_write_X509_CRL(fp, crl);
    fclose(fp);
    cout << success << endl;
    cout << "Before PEM_write_X509_CRL" << endl;
    if (!success) {
        cerr << "Error: Failed to write CRL to PEM.\n";
        return false;
    }
    cout << "After PEM_write_X509_CRL" << endl;

    return true;
}


