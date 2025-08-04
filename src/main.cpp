#include <bits/stdc++.h>
#include "../include/cxxopts.hpp"
#include "../include/ca_setup.hpp"


using namespace std;

int main(int argc, char* argv[]) {
    try {
        cxxopts::Options options("mini-pki", "CLI-based PKI Tool");

        options.add_options()
            ("init-ca", "Initialize Root CA")
            ("gen-csr", "Generate CSR")
            ("sign-csr", "Sign a CSR using CA")
            ("verify-cert", "Verify a certificate")
            ("cn", "Common Name (CN)", cxxopts::value<string>())
            ("csr", "Path to CSR file", cxxopts::value<string>())
            ("cert", "Certificate to verify", cxxopts::value<string>())
            ("out", "Output certificate path", cxxopts::value<string>())
            ("key-bits", "RSA key size (default 2048)", cxxopts::value<int>()->default_value("2048"))
            ("help", "Print help")
            ("generate-crl", "Generate CRL")
            ("revoke-cert", "Revoke a certificate")
            ("revoke", "Certificate to revoke", cxxopts::value<std::string>())
            ("crl-out", "CRL output path", cxxopts::value<std::string>());

        auto result_args = options.parse(argc, argv);

        if (result_args.count("help") || argc == 1) {
            cout << options.help() << endl;
            return 0;
        }

        int keyBits = result_args["key-bits"].as<int>();

        // ---- Init CA ----
        if (result_args.count("init-ca")) {
            if (!result_args.count("cn")) {
                cerr << "Error: --cn is required for --init-ca\n";
                return 1;
            }

            string cn = result_args["cn"].as<string>();
            EVP_PKEY* ca_key = keyGeneration(keyBits);
            save_private_key(ca_key, "KeysAndCerts/ca_private_key.pem");

            X509* ca_cert = create_self_signed_cert(ca_key, 365, cn);
            save_cert_to_pem(ca_cert, "KeysAndCerts/ca_cert.pem");

            cout << "CA key and certificate generated successfully.\n";
        }

        // ---- Generate CSR ----
        else if (result_args.count("gen-csr")) {
            if (!result_args.count("cn")) {
                cerr << "Error: --cn is required for --gen-csr\n";
                return 1;
            }

            string cn = result_args["cn"].as<string>();
            EVP_PKEY* key = keyGeneration(keyBits);
            save_private_key(key, "KeysAndCerts/client_private_key.pem");

            X509_REQ* req = create_csr(key, cn);
            save_csr_to_file(req, "KeysAndCerts/client_csr.pem");

            cout << "Private key and CSR generated successfully.\n";
        }

        // ---- Sign CSR ----
        else if (result_args.count("sign-csr")) {
            if (!result_args.count("csr") || !result_args.count("out")) {
                cerr << "Error: --csr and --out are required for --sign-csr\n";
                return 1;
            }

            string csrPath = result_args["csr"].as<string>();
            string outPath = result_args["out"].as<string>();

            FILE* caKeyFile = fopen("KeysAndCerts/ca_private_key.pem", "r");
            FILE* caCertFile = fopen("KeysAndCerts/ca_cert.pem", "r");
            FILE* csrFile = fopen(csrPath.c_str(), "r");

            if (!caKeyFile || !caCertFile || !csrFile) {
                cerr << "Error: Failed to open CA key/cert or CSR file.\n";
                return 1;
            }

            EVP_PKEY* ca_key = PEM_read_PrivateKey(caKeyFile, nullptr, nullptr, nullptr);
            X509* ca_cert = PEM_read_X509(caCertFile, nullptr, nullptr, nullptr);
            X509_REQ* csr = PEM_read_X509_REQ(csrFile, nullptr, nullptr, nullptr);

            fclose(caKeyFile);
            fclose(caCertFile);
            fclose(csrFile);

            if (!ca_key || !ca_cert || !csr) {
                cerr << "Error: Failed to parse CA key, cert, or CSR.\n";
                return 1;
            }

            X509* signedCert = sign_csr_with_ca(csr, ca_key, ca_cert, 365);
            save_cert_to_pem(signedCert, outPath.c_str());

            cout << "CSR signed successfully. Certificate saved to: " << outPath << endl;
        }

        // ---- Verify Certificate ----
        else if (result_args.count("verify-cert")) {
            if (!result_args.count("cert")) {
                cerr << "Error: --cert is required for --verify-cert\n";
                return 1;
            }

            string certPath = result_args["cert"].as<string>();
            bool verifyResult = verify_cert(certPath.c_str(), "KeysAndCerts/ca_cert.pem");

            if (verifyResult)
                cout << "✅ Certificate is valid and verified.\n";
            else
                cout << "❌ Certificate verification failed.\n";
        }

        // ---- Generate CRL ----
        else if (result_args.count("generate-crl")) {
        if (!result_args.count("crl-out")) {
        cerr << "Error: --crl-out is required for --generate-crl\n";
        return 1;
        }

        string crlOutPath = result_args["crl-out"].as<string>();

        X509_CRL* crl = create_empty_crl(); // from ca_setup.cpp
        save_crl_to_pem(crl, crlOutPath.c_str()); // from ca_setup.cpp

        cout << "Empty CRL generated at: " << crlOutPath << endl;
        }

        // ---- Revoke Certificate ----
        else if (result_args.count("revoke-cert")) {
            if (!result_args.count("revoke") || !result_args.count("crl-out")) {
             cerr << "Error: --revoke and --crl-out are required for --revoke-cert\n";
        return 1;
        }

        string certToRevokePath = result_args["revoke"].as<string>();
        string crlOutPath = result_args["crl-out"].as<string>();

        bool success = revoke_certificate(certToRevokePath, crlOutPath);
        cout << success << endl;
        if (success == 0)
            cout << "Certificate revoked and CRL updated at: " << crlOutPath << endl;
        else
            cout << "Failed to revoke certificate.\n";
        }

        

    } catch (const std::exception& e) {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }

    return 0;
}
