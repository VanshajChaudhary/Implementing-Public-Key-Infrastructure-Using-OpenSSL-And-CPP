// #include<bits/stdc++.h>
// #include<openssl/x509.h>
// #include <openssl/x509v3.h>
// #include <openssl/evp.h>
// #include <openssl/rsa.h>
// #include <openssl/pem.h>  // Required for PEM_write_RSAPrivateKey
// #include <openssl/asn1.h>
// #include "../include/ca_setup.hpp"
// #include "../include/cxxopts.hpp"


// #define ONEDAY 24*60*60


// using namespace std;


// int main(){


//     cout << endl;



//     /*CA Creation*/ 

//     cout << "--------Generation of Certificate Authority--------" << endl;

//     // Key Generation

//     int bits;
//     cout << "Enter the No of Bits (2048 bits or 4096 bits) :" ;
//     cin >> bits; 
//     cout << endl;

//     EVP_PKEY* ca_key = keyGeneration(bits);
//     if ( !(ca_key) ){
//         return 1;
//     }


//     // CA Creation


//     int validity; 
//     cout << "Enter the No. of Validity days : " ;
//     cin >> validity;

//     string CA_Cert_FilePath;
//     cout << "Enter File name to save Root certificate in .pem format : ";
//     cin >> CA_Cert_FilePath;


//     X509* CAcert = CA_Creation(ca_key, validity, CA_Cert_FilePath);
//     if ( !(CAcert) ){

//         EVP_PKEY_free(ca_key);

//         return 1;
//     }



//     /*Server Side */ 
    
//     cout << endl << "-------- Generation of Server side Keys and Certificates --------" << endl;

//     // Key Generation

//     EVP_PKEY* server_key = keyGeneration(bits);
//     if ( !(server_key) ){
//         EVP_PKEY_free(ca_key);
//         X509_free(CAcert);       
//         return 1;
//     }

//     // Creation of CSR

//     string Server_CSRFilePath;
//     cout << " Enter the CSR FileName and Path for Server : ";
//     cin >> Server_CSRFilePath;

//     // EVP_PKEY* csr_key = keyGeneration(bits);
//     // if ( !(csr_key) ){
//     //     EVP_PKEY_free(ca_key);
//     //     return 1;
//     // }


//     X509_REQ* createCSR_Server = CSR_Creation(server_key, Server_CSRFilePath);
    
//     if ( !(createCSR_Server) ){

//         EVP_PKEY_free(ca_key);
//         X509_free(CAcert);       
//         EVP_PKEY_free(server_key);

//     return 1;
//     }


//     // SIGNING THE CSR WITH CA KEY


//     string Server_CertificateFilePath;
//     cout << "Enter Certificate Name and File Path for Server : " ;
//     cin >> Server_CertificateFilePath;

//     X509* signingCSR_Server = signCSR(createCSR_Server, ca_key, CAcert, validity, Server_CertificateFilePath);

//     if( !(signingCSR_Server) ){
        
//         EVP_PKEY_free(ca_key);
//         X509_free(CAcert);       
//         EVP_PKEY_free(server_key);
//         X509_REQ_free(createCSR_Server);

//     return 1;
//     }

//     // VERIFICATION


//     if ( !(certificateVerification(Server_CertificateFilePath, CA_Cert_FilePath)) ){
        
//         EVP_PKEY_free(ca_key);
//         X509_free(CAcert);       
//         EVP_PKEY_free(server_key);
//         X509_REQ_free(createCSR_Server);
//         X509_free(signingCSR_Server);

//         return 1;
//     }



//     /*Client Side */ 
    
//     cout << endl << "-------- Generation of Client side Keys and Certificates --------" << endl;

//     // Key Generation

//     EVP_PKEY* client_key = keyGeneration(bits);
//     if ( !(client_key) ){
//         EVP_PKEY_free(ca_key);
//         X509_free(CAcert);       
//         EVP_PKEY_free(server_key);
//         X509_REQ_free(createCSR_Server);
//         X509_free(signingCSR_Server);  
//         return 1;
//     }

//     // Creation of CSR

//     string Client_CSRFilePath;
//     cout << " Enter the CSR FileName and Path for Client: ";
//     cin >> Client_CSRFilePath;

//     // EVP_PKEY* csr_key = keyGeneration(bits);
//     // if ( !(csr_key) ){
//     //     EVP_PKEY_free(ca_key);
//     //     return 1;
//     // }


//     X509_REQ* createCSR_Client = CSR_Creation(client_key, Client_CSRFilePath);
    
//     if ( !(createCSR_Client) ){

//         EVP_PKEY_free(ca_key);
//         X509_free(CAcert);       
//         EVP_PKEY_free(server_key);
//         X509_REQ_free(createCSR_Server);
//         X509_free(signingCSR_Server);  
//         EVP_PKEY_free(client_key);

//     return 1;
//     }


//     /*SIGNING THE CSR WITH CA KEY*/


//     string Client_CertificateFilePath;
//     cout << "Enter Certificate Name and File Path for Client: " ;
//     cin >> Client_CertificateFilePath;

//     X509* signingCSR_Client = signCSR(createCSR_Client, ca_key, CAcert, validity, Client_CertificateFilePath);

//     if( !(signingCSR_Client) ){
        
//         EVP_PKEY_free(ca_key);
//         X509_free(CAcert);       
//         EVP_PKEY_free(server_key);
//         X509_REQ_free(createCSR_Server);
//         X509_free(signingCSR_Server);  
//         EVP_PKEY_free(client_key);
//         X509_REQ_free(createCSR_Client);        

//     return 1;
//     }

//     // VERIFICATION


//     if ( !(certificateVerification(Client_CertificateFilePath, CA_Cert_FilePath)) ){
        
//         EVP_PKEY_free(ca_key);
//         X509_free(CAcert);       
//         EVP_PKEY_free(server_key);
//         X509_REQ_free(createCSR_Server);
//         X509_free(signingCSR_Server);  
//         EVP_PKEY_free(client_key);
//         X509_REQ_free(createCSR_Client);
//         X509_free(signingCSR_Client);          

//         return 1;
//     }



// }



// NEW CLI BASED CODE 

#include <iostream>
#include <fstream>
#include "../include/ca_setup.hpp"
#include "../include/cxxopts.hpp"

using namespace std;

int main(int argc, char* argv[]) {
    try {
        cxxopts::Options options("mini-pki", "Modular PKI Tool using OpenSSL");

        options.add_options()
            ("init-ca", "Generate CA Key & Self-Signed Certificate")
            ("generate-csr", "Generate Key and CSR")
            ("sign-csr", "Sign CSR using CA")
            ("verify-cert", "Verify certificate using CA certificate")

            ("cn", "Common Name (CN)", cxxopts::value<string>())
            ("csr-file", "Path to CSR file", cxxopts::value<string>())
            ("cert-out", "Output path for signed certificate", cxxopts::value<string>())
            ("cert", "Certificate to verify", cxxopts::value<string>())
            ("ca", "CA certificate path", cxxopts::value<string>())
            ("key-out", "Private key output file", cxxopts::value<string>())
            ("csr-out", "CSR output file", cxxopts::value<string>())
            ("cert-out-ca", "CA Certificate output file", cxxopts::value<string>())

            ("h,help", "Print usage");

        auto result = options.parse(argc, argv);

        if (result.count("help") || argc == 1) {
            cout << options.help() << endl;
            return 0;
        }

        // --- INIT CA ---
        if (result.count("init-ca")) {
            if (!result.count("cn")) {
                cerr << "❌ Error: --cn required with --init-ca" << endl;
                return 1;
            }

            string cn = result["cn"].as<string>();
            string cert_out = result.count("cert-out-ca") ? result["cert-out-ca"].as<string>() : "KeysAndCerts/RootCA_Certificate.pem";
            string key_out = result.count("key-out") ? result["key-out"].as<string>() : "KeysAndCerts/RootCA_PrivateKey.pem";

            EVP_PKEY* ca_key = keyGeneration(2048);
            if (!save_private_key(ca_key, key_out.c_str())) {
                cerr << "❌ Failed to save CA private key" << endl;
                return 1;
            }

            X509* ca_cert = create_self_signed_cert(ca_key, 365, cn);
            if (!save_cert_to_pem(ca_cert, cert_out.c_str())) {
                cerr << "❌ Failed to save CA certificate" << endl;
                return 1;
            }

            cout << "✅ CA certificate and key generated." << endl;
        }

        // --- GENERATE CSR ---
        else if (result.count("generate-csr")) {
            if (!result.count("cn")) {
                cerr << "❌ Error: --cn required with --generate-csr" << endl;
                return 1;
            }

            string cn = result["cn"].as<string>();
            string key_out = result.count("key-out") ? result["key-out"].as<string>() : "KeysAndCerts/Server_PrivateKey.pem";
            string csr_out = result.count("csr-out") ? result["csr-out"].as<string>() : "KeysAndCerts/Server_CSR.pem";

            EVP_PKEY* key = keyGeneration(2048);
            if (!save_private_key(key, key_out.c_str())) {
                cerr << "❌ Failed to save private key" << endl;
                return 1;
            }

            X509_REQ* csr = create_csr(key, cn);
            if (!save_csr_to_file(csr, csr_out.c_str())) {
                cerr << "❌ Failed to save CSR" << endl;
                return 1;
            }

            cout << "✅ CSR and private key generated." << endl;
        }

        // --- SIGN CSR ---
        else if (result.count("sign-csr")) {
            if (!result.count("csr-file") || !result.count("cert-out")) {
                cerr << "❌ Error: --csr-file and --cert-out required with --sign-csr" << endl;
                return 1;
            }

            string csr_file = result["csr-file"].as<string>();
            string cert_out = result["cert-out"].as<string>();

            EVP_PKEY* ca_key = EVP_PKEY_new();
            X509* ca_cert = load_certificate_from_file("KeysAndCerts/RootCA_Certificate.pem");

            FILE* ca_key_fp = fopen("KeysAndCerts/RootCA_PrivateKey.pem", "r");
            if (!ca_key_fp || !PEM_read_PrivateKey(ca_key_fp, &ca_key, NULL, NULL)) {
                cerr << "❌ Failed to load CA private key" << endl;
                return 1;
            }
            fclose(ca_key_fp);

            FILE* csr_fp = fopen(csr_file.c_str(), "r");
            if (!csr_fp) {
                cerr << "❌ Failed to open CSR file" << endl;
                return 1;
            }
            X509_REQ* csr = PEM_read_X509_REQ(csr_fp, NULL, NULL, NULL);
            fclose(csr_fp);

            X509* signed_cert = sign_csr_with_ca(csr, ca_key, ca_cert, 365);
            if (!save_cert_to_pem(signed_cert, cert_out.c_str())) {
                cerr << "❌ Failed to save signed certificate" << endl;
                return 1;
            }

            cout << "✅ CSR signed and certificate saved." << endl;
        }

        // --- VERIFY CERT ---
        else if (result.count("verify-cert")) {
            if (!result.count("cert") || !result.count("ca")) {
                cerr << "❌ Error: --cert and --ca required with --verify-cert" << endl;
                return 1;
            }

            string cert_file = result["cert"].as<string>();
            string ca_file = result["ca"].as<string>();

            if (verify_cert(cert_file.c_str(), ca_file.c_str())) {
                cout << "✅ Certificate verification succeeded." << endl;
            } else {
                cout << "❌ Certificate verification failed." << endl;
                return 1;
            }
        }

        else {
            cerr << "❌ No valid operation specified. Use --help to see options." << endl;
            return 1;
        }

    } catch (const std::exception& e){
        cerr << "❌ Error parsing options: " << e.what() << endl;
        return 1;
    }

    return 0;
}


