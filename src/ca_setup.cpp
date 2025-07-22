#include<bits/stdc++.h>
#include<openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>  // Required for PEM_write_RSAPrivateKey
#include <openssl/asn1.h>
#include "../include/ca_setup.hpp"

#define ONEDAY 24*60*60


using namespace std;


// Key Generation 

EVP_PKEY* generate_RSA_Key_Pair(int bits){

    // Step 1 : Creation of RSA Key Context 
    
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);  //Creates a new EVP_PKEY_CTX structure (context) for key 
                                                                 // generation using Algo like RSA, DSA, EC, etc.


    if (!ctx){
        cerr << "RSA Context wasn't Created" << endl;
        // EVP_PKEY_CTX_free(ctx);  /* HOW DO WE FREE IF IT WAS NOT CREATED */
        return NULL;
    }



    // Step 2 : Initialising Key Genration

    if ( !(EVP_PKEY_keygen_init(ctx))){           // Initializes the key generation process for the context.
        cerr << "Key Initialisation wasn't successful" << endl;
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }



    // Step 3 : Setting Key Bits Size 

    if ( !(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits))){ // Sets the RSA key length (in bits) for the key pair to be generated.
        cerr << "Bit Size was not successfully set" << endl;
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }



    // Step 4 : Setting up Public Exponent(Harcoded as default,i.e., 65537)

    BIGNUM* e = BN_new();   
    BN_set_word(e, 65537);

    if ( !(EVP_PKEY_CTX_set_rsa_keygen_pubexp(ctx, e))){
        cerr << "Pulic Exponent wasn't set Correctly" << endl;
        BN_free(e);  // I missed it here earlier leading to segmentation fault
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }



    // Step 5 : Key Generation 

    EVP_PKEY* key = NULL; // Didn't do EVP_PKEY_new() as EVP_PKEY_keygen() allocates EVP_PKEY internally which is used by OpenSSL
                          // to store public and private keys.
                        

    // if ( !(EVP_PKEY_keygen(ctx, &key))){
    //     cerr << "Key Generation wasn't done successfully" << endl;  
    //     BN_free(e);                             
    //     EVP_PKEY_free(key);                       /* THIS GIVES ERROR AS WE MIGHT NOT NOT IF *key WAS ALWAYS ALLOCATED */
    //     EVP_PKEY_CTX_free(ctx);
    //     return NULL;
    // }

    if (!(EVP_PKEY_keygen(ctx, &key))) {
        cerr << "Key Generation wasn't done successfully" << endl;  
        if (key){
            EVP_PKEY_free(key);  // Only free if it's not NULL, i.e., only when it was allocated
        }
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    // BN_free(e);  /* C++ HANDLS THIS INTERNALLY, THUS, GIVING THIS HERE RESULTS TO SEGMENTATION FAULT

    EVP_PKEY_CTX_free(ctx);  // Not of any use now, Only one containg the keys is useful
    
    return key; // Returns the pointer to the structure where both Pvt and Public Keys are stored 

}

bool save_private_key(EVP_PKEY* key, const char *Pvt_Key_Path){

    // Step 1: Opening the File to Write the Key

    FILE *PvtFile = fopen(Pvt_Key_Path, "wb");
    if ( !(PvtFile) ){
        cerr << "Wasn't able to open the Private Key File from RSA key Context" << endl;
        return 0;
    }


    // Step 2: Writing Key into File

    const char* passcode = "Password";
    if ( !(PEM_write_PrivateKey(PvtFile , key, EVP_aes_256_cbc(), (unsigned char *)passcode, strlen(passcode), NULL, NULL))){
        cerr << "Private Key not writen successfullly" << endl;
        fclose(PvtFile);
        return 0; 
    }


    fclose (PvtFile);
    // EVP_PKEY_free(key);   Key Structure won't be freed here as it is to be used for Public key as well
                             // Also always free it in main function

    return 1; // Private File is Saved Correctly

}


// bool save_public_key(EVP_PKEY* key, const char *Public_Key_FilePath){

//     // Step 1: Opening the File to Write the Key

//     FILE *PubFile = fopen(Public_Key_FilePath, "wb");
//     if ( !(PubFile) ){
//         cerr << "Wasn't able to open the Public Key File from RSA key Context" << endl;
//         return 0;
//     }


//     // Step 2: Writing Key into File

//     if ( !(PEM_write_PUBKEY(PubFile, key))){
//         cerr << "Public Key not writen successfullly" << endl;
//         fclose(PubFile);
//         return 0; 
//     }

//     fclose (PubFile);
    
//     return 1; // Public File is Saved Correctly

// }


EVP_PKEY* keyGeneration(int bits){

    if (bits != 2048 && bits != 4096){
        cerr << "Invalid Number of bits" << endl;
        return NULL;
    }

    EVP_PKEY* key = generate_RSA_Key_Pair(bits);
    
    if (!key){
        cerr << "Key Generation Failed" << endl;
            // EVP_PKEY_free(key); // Don't need to call this if it was NULL
        return NULL;
    }

    else {

        string Pvt_Key_FilePath;
        cout << "Enter the name of the Pvt Key File in .pem format : " ; 
        cin >> Pvt_Key_FilePath;

        if ( !(save_private_key(key, Pvt_Key_FilePath.c_str())) ) {
                cerr << "Failed to save Private Key" << endl;
                EVP_PKEY_free(key);
                return NULL;
        }

        // string Public_Key_FilePath;
        // cout << "Enter the name of the Public Key File in .pem format : " ; 
        // cin >> Public_Key_FilePath;

        // if ( !(save_public_key(key, Public_Key_FilePath.c_str()))) {
        //         cerr << "Failed to save Public Key" << endl;
        //         EVP_PKEY_free(key);
        //         return NULL;
        // }

            cout << "Key Generation Successful" << endl;
            // EVP_PKEY_free(key);  // Used inside CA AUTHORITY setting Public Key  // INCLUDE IN LAST
            return key;
    }

}



// CA CREATION


X509* create_self_signed_cert(EVP_PKEY* key, int validityDays, const string& CN_NAME){

    // Step 1: Creation of X509 Certificate Object

    X509* x509 = X509_new();
    
    if ( !(x509) ){
        cerr << "Certificate Object not created"<< endl;
        return NULL;
    }


    // Step 2 : Setting Up Certificate Version

    if ( !(X509_set_version(x509, 2))){         // Version is based on 0-based indexing, i.e., Serial No : 2 for v3
        cerr << "Version was not Successfully set" << endl;
        X509_free(x509);
        return NULL;
    }


    // Step 3 : Setting Up Serial Number

    ASN1_INTEGER* serialNo = ASN1_INTEGER_new();
    
    if ( !(serialNo) ){
        cerr << "Serial Number not created" << endl;
        X509_free(x509);
        return NULL;        
    }

    if ( !(ASN1_INTEGER_set(serialNo, 1))){
        cerr << "Serial number not set correctly into ASN1 Integer" << endl;
        ASN1_INTEGER_free(serialNo);
        X509_free(x509);
        return NULL;           
    }


    if ( !(X509_set_serialNumber(x509, serialNo))){
        cerr << "Serial Number wasn't set successfully" << endl;
        ASN1_INTEGER_free(serialNo);
        X509_free(x509);
        return NULL;
    }

    ASN1_INTEGER_free(serialNo);


    // STEP 4 : Setting Validity Period

    time_t start = time(NULL);
    ASN1_TIME* notBefore = ASN1_TIME_set(NULL, start);

    time_t expiry = start + (validityDays*ONEDAY);
    ASN1_TIME* notAfter = ASN1_TIME_set(NULL, expiry);

    if ( !(notBefore) ){
        cerr << "Start Time was not initialised Properly" << endl;
        X509_free(x509);
        return NULL;        
    }

    if ( !(notAfter) ){
        cerr << "End Time was not initialised Properly" << endl;
        X509_free(x509);
        return NULL;        
    }    

    if ( (!(X509_set1_notBefore(x509, notBefore))) || (!(X509_set1_notAfter(x509, notAfter))) ) {
        cerr << "Validity Period not set Succesfully" << endl;
        X509_free(x509);
        return NULL;          
    }

    ASN1_TIME_free(notBefore);
    ASN1_TIME_free(notAfter);


    // STEP 5 : Setting Public Key into Certificate

    if (! (X509_set_pubkey(x509, key) )){
        cerr << "Public Key not set Correctly" << endl;
        X509_free(x509);
        return NULL;
    }



    // STEP 6 : Providing Subject Information (a.k.a SubjectName)

    X509_NAME* subjectName = X509_NAME_new();

    if ( !(subjectName) ){
        cerr << "Subject Name Context not Initiated Properly" << endl;
        X509_free(x509);
        return NULL;        
    }

    X509_NAME_add_entry_by_txt(subjectName, "C",  MBSTRING_ASC, (const unsigned char *)"IN", -1, -1, 0);
    X509_NAME_add_entry_by_txt(subjectName, "O",  MBSTRING_ASC, (const unsigned char *)"SELF", -1, -1, 0);
    X509_NAME_add_entry_by_txt(subjectName, "CN", MBSTRING_ASC, (const unsigned char*)CN_NAME.c_str(), -1, -1, 0);

    if ( !(X509_set_subject_name(x509, subjectName))){
        cerr << "Subject name not set properly" << endl;
        X509_free(x509);
        return NULL;           
    }

    if ( !(X509_set_issuer_name(x509, subjectName))){   // Issue name is same as subject name in case of SelfSigned
        cerr << "Issuer name not set properly" << endl;
        X509_free(x509);
        return NULL;           
    }

    X509_NAME_free(subjectName);
    
    // 
        // === EXTENSIONS BEGIN ===
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);                          // No config DB
    X509V3_set_ctx(&ctx, x509, x509, NULL, NULL, 0);    // Self-signed: issuer = subject

    // Add basicConstraints = critical,CA:TRUE
    X509_EXTENSION* ext;
    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_basic_constraints, "critical,CA:TRUE");
    if (!ext) {
        cerr << "❌ Failed to create basicConstraints extension" << endl;
        X509_free(x509);
        return NULL;
    }
    X509_add_ext(x509, ext, -1);
    X509_EXTENSION_free(ext);

    // Add keyUsage = critical,keyCertSign,cRLSign
    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_key_usage, "critical,keyCertSign,cRLSign");
    if (!ext) {
        cerr << "❌ Failed to create keyUsage extension" << endl;
        X509_free(x509);
        return NULL;
    }
    X509_add_ext(x509, ext, -1);
    X509_EXTENSION_free(ext);
    // === EXTENSIONS END ===



    // STEP 7 : SIGNING THE CERTIFICATE

    if ( !(X509_sign(x509, key, EVP_sha256()))){
        cerr << "Certficate not signed properly" << endl;
        X509_free(x509);
        return NULL;  
    }

    return x509;

}

bool save_cert_to_pem(X509* cert, const char* CA_Cert_FilePath){

    FILE *certificate = fopen(CA_Cert_FilePath, "wb");

    if (!cert) {
        cerr << "Failed to load file to Write the Certificate " << endl;
        return 0;
    }
    if ( !(PEM_write_X509(certificate, cert) ) ){
        cerr << "Failed to write certificate to file" << endl;
        fclose(certificate);
        return 0;
    }
    
    cout << "Certificate written into " << CA_Cert_FilePath << endl;
    fclose(certificate);
    

    return 1;

}

X509* CA_Creation(EVP_PKEY* key, int validity, const string& CA_Cert_FilePath){

    string CN;
    cout << "Enter the Common Name for CA AUTHORITY : " ;
    cin >> CN;

    X509* cert= create_self_signed_cert(key, validity, CN);

    if (!(cert)){
        cerr << "Certificate Not Generated Properly" << endl;
        EVP_PKEY_free(key);
        return NULL;
    }
    else{

        if ( !( save_cert_to_pem(cert, CA_Cert_FilePath.c_str()))){
            cerr << "Certificate not saved" << endl;
            EVP_PKEY_free(key);
            X509_free(cert);
            return NULL;            
        }   
    }

    cout << "Certificate Generated Properly" << endl;
    return cert;

}




// CSR Creation

X509_REQ* create_csr(EVP_PKEY* key, const string& CommonName){

    // STEP 1 : Allocation of memory structure for a new CSR

    X509_REQ* csr = X509_REQ_new();     

    if ( !(csr) ){
        cerr << "CSR structure was not created";
        return NULL;
    }

    // STEP 2 : SETTING VERSION 

    if ( !(X509_REQ_set_version(csr, 0)) ){
        cerr << "CSR Version was not correctly set" << endl;
        X509_REQ_free(csr);
        return NULL;
    }

    // STEP 3 : CREATION OF SUBJECT NAME 

    X509_NAME* subjectNameCSR = X509_NAME_new();

    if ( !(subjectNameCSR) ){
        cerr << "Subject Name Context not Initiated Properly" << endl;
        X509_REQ_free(csr);
        return NULL;    
    }

    X509_NAME_add_entry_by_txt(subjectNameCSR, "C",  MBSTRING_ASC, (const unsigned char *)"IN", -1, -1, 0);
    X509_NAME_add_entry_by_txt(subjectNameCSR, "O",  MBSTRING_ASC, (const unsigned char *)"SELF", -1, -1, 0);
    X509_NAME_add_entry_by_txt(subjectNameCSR, "CN", MBSTRING_ASC, (const unsigned char *)CommonName.c_str(), -1, -1, 0);

    if ( !(X509_REQ_set_subject_name(csr, subjectNameCSR))){
        cerr << "Subject name not set properly" << endl;
        X509_REQ_free(csr);
        return NULL;        
    }

    X509_NAME_free(subjectNameCSR);

    // STEP 4 : SETTING PUBLIC KEY IN REQUEST 


    if ( !(X509_REQ_set_pubkey(csr, key) )){
        cerr << "Public Key not set Properly in CSR" << endl;
        X509_REQ_free(csr);
        return NULL;     
    }

    // STEP 4 : Signing the CSR Using Pvt Key

    if ( !( X509_REQ_sign(csr, key, EVP_sha256()) )){
        cerr << "Couldn't sign the CSR using Pvt Key" << endl;
        X509_REQ_free(csr);
        return NULL;             
    }

    return csr;

}

bool save_csr_to_file(X509_REQ* req, const char* CSRFilePath){

    FILE* csrFile= fopen(CSRFilePath, "wb");

    if( !(csrFile) ){
        cerr << "File to save CSR was not obtained" << endl;
        return 0; 
    }

    if ( !(PEM_write_X509_REQ(csrFile, req)) ){
        cerr << "CSR was not saved in the " << CSRFilePath << endl;
        fclose(csrFile);
        return 0; 
    }

    return 1;

}

X509_REQ* CSR_Creation (EVP_PKEY* key, const string& CSRFilePath){

    // Creation of Request


    string CommonName;
    cout << "Enter your Common Name : ";
    cin >> CommonName;

    X509_REQ* CSR = create_csr(key, CommonName);

    if ( !(CSR) ){
    cerr << "CSR was not Successfuly Created" << endl;
    return NULL;
    }

    // Saving of Request 

    else{               

        if ( !(save_csr_to_file(CSR, CSRFilePath.c_str())) ){
            cout << "Unable to Save CSR" << endl;
            X509_REQ_free(CSR);
            return NULL;
        }
    }
    
    cout << "CSR was saved in the file" << endl;

    return CSR;

}




// SIGNING CSR AND CREATING CERTIFICATE 

X509* sign_csr_with_ca(X509_REQ* csr, EVP_PKEY* caPrivateKey, X509* caCert, int validity){

    // STEP 1: Creating a newCertificate Object 

    X509* signedCert = X509_new();

    if ( !(signedCert) ){
        cerr << "Unable to Create Structure for CSR Signed certificate" << endl;
        return NULL;
    }

    // STEP 2 : Setting Version of CSR Signed Certificate
    
    if ( !(X509_set_version(signedCert, 2))){
        cerr << "Unable to set version for CA Signed Cert" << endl;
        X509_free(signedCert);
        return NULL;
    }

    // STEP 3 : Setting serial number for CSR Signed Certificate

    ASN1_INTEGER* serialNoCSR = ASN1_INTEGER_new();
    
    if ( !(serialNoCSR) ){
        cerr << "Serial Number not created" << endl;
        X509_free(signedCert);
        return NULL;        
    }

    if ( !(ASN1_INTEGER_set(serialNoCSR, 2))){
        cerr << "Serial number not set correctly into ASN1 Integer" << endl;
        ASN1_INTEGER_free(serialNoCSR);
        X509_free(signedCert);
        return NULL;           
    }


    if ( !(X509_set_serialNumber(signedCert, serialNoCSR))){
        cerr << "Serial Number wasn't set successfully" << endl;
        ASN1_INTEGER_free(serialNoCSR);
        X509_free(signedCert);
        return NULL;
    }

    ASN1_INTEGER_free(serialNoCSR);


    // STEP 4 : SETTING VALIDITY PERIOD 

    time_t start = time(NULL);
    ASN1_TIME* notBefore = ASN1_TIME_set(NULL, start);

    time_t expiry = start + (validity*ONEDAY);
    ASN1_TIME* notAfter = ASN1_TIME_set(NULL, expiry);

    if ( !(notBefore) ){
        cerr << "Start Time was not initialised Properly" << endl;
        X509_free(signedCert);
        return NULL;        
    }

    if ( !(notAfter) ){
        cerr << "End Time was not initialised Properly" << endl;
        X509_free(signedCert);
        return NULL;        
    }    

    if ( (!(X509_set1_notBefore(signedCert, notBefore))) || (!(X509_set1_notAfter(signedCert, notAfter))) ) {
        cerr << "Validity Period not set Succesfully" << endl;
        X509_free(signedCert);
        return NULL;          
    }

    ASN1_TIME_free(notBefore);
    ASN1_TIME_free(notAfter);


    //STEP 5 : SETTING SUBJECT INFORMATION

    X509_NAME* subjectNameCSRSigned = X509_NAME_new();

    if ( !(subjectNameCSRSigned)){
        cerr << "Wasn't able to create structure for CSR Signed Certificate" << endl;
        X509_free(signedCert);
        return NULL;        
    } 

    X509_NAME * subjectFetch = X509_REQ_get_subject_name(csr);
    if ( !(subjectFetch)){
        cerr << "Unable to fetch subject information" << endl;
        X509_free(signedCert);
        return NULL;          
    }


    if (!(X509_set_subject_name(signedCert, subjectFetch))) {
        cerr << "Unable to set subject information in CSR Signed Certificate " << endl;
        X509_free(signedCert);
        return NULL;
    }


    // STEP 6 : SETTING ISSUER NAME

    X509_NAME* issuerCSRSigned = X509_get_subject_name(caCert);
    if ( !(issuerCSRSigned)){
        cerr << "Wasn't able to create structure for CSR Signed Certificate" << endl;
        X509_free(signedCert);
        return NULL;           
    }
    
    if ( !(X509_set_issuer_name(signedCert, issuerCSRSigned))){
        cerr << "Unable to set issuer name in CSR Signed Certificate " << endl;
        X509_free(signedCert);
        return NULL;          
    }


    // Step 7: Set public key from CSR
    
    EVP_PKEY* reqPubKey = X509_REQ_get_pubkey(csr);
    if ( !(reqPubKey) ){
        cerr << "Unable to fetch Public Key for CSR Signed Certificate" << endl;
        X509_free(signedCert);
        return NULL;        
    }
    if (!(X509_set_pubkey(signedCert, reqPubKey))){
        cerr << "Unable to set Public Key for CSR Signed Certificate" << endl;
        X509_free(signedCert);
        EVP_PKEY_free(reqPubKey); 
        return NULL;              
    }


    // Step 8: Sign the new certificate using CA's private key

    if (!X509_sign(signedCert, caPrivateKey, EVP_sha256())) {
        X509_free(signedCert);
        return NULL;
    } 

    X509_NAME_free(subjectNameCSRSigned);
    EVP_PKEY_free(reqPubKey); 

    return signedCert;

}

X509* signCSR(X509_REQ* CSR, EVP_PKEY* ca_key, X509* cert, int validity, const string& CertificateFilePath){

    X509* CASignedCSR = sign_csr_with_ca(CSR, ca_key, cert, validity);

    if ( !( CASignedCSR)){
        cerr << "Signing of CSR with CA Key wasn't done" << endl;
        return NULL;
    }
    else{
        if (!save_cert_to_pem(CASignedCSR, CertificateFilePath.c_str())) {
        cerr << "Signed certificate could not be saved" << endl;
        X509_free(CASignedCSR);
        return NULL;
        }
    }
    cout << "CSR successfully signed and certificate saved!" << endl;
    return CASignedCSR;

}





// CERTIFICATE VERIFICATION

X509* load_certificate_from_file(const char* filename) {
    FILE* fp = fopen(filename, "rb");
    if (!fp) {
        cerr << "Failed to open certificate file: " << filename << endl;
        return NULL;
    }
    X509* CERT = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);
    return CERT;
}


bool verify_cert(const char* CertificateFilePath, const char* CA_Cert_FilePath) {
    //verify_cert(CA_Cert_FilePath.c_str(), CertificateFilePath.c_str)

    // Load the CA certificate (trusted)
    X509* caCert = load_certificate_from_file(CA_Cert_FilePath);

    // Load the certificate to verify (e.g., CSR signed certificate)
    X509* certToVerify = load_certificate_from_file(CertificateFilePath);

    if (!caCert || !certToVerify) {
        cerr << "Failed to load certificate(s) for verification" << endl;
        if (caCert) X509_free(caCert);
        if (certToVerify) X509_free(certToVerify);
        return false;
    }

    // 1. Create a trusted certificate store
    X509_STORE* store = X509_STORE_new();
    if (!store) {
        cerr << "Failed to create X509 store" << endl;
        X509_free(caCert);
        X509_free(certToVerify);
        return false;
    }

    if (!X509_STORE_add_cert(store, caCert)) {
        cerr << "Failed to add CA cert to store" << endl;
        X509_free(caCert);
        X509_free(certToVerify);
        X509_STORE_free(store);
        return false;
    }

    // 2. Create and initialize verification context
    X509_STORE_CTX* ctx = X509_STORE_CTX_new();
    if (!ctx || !X509_STORE_CTX_init(ctx, store, certToVerify, NULL)) {
        cerr << "Failed to initialize verification context" << endl;
        X509_free(caCert);
        X509_free(certToVerify);
        X509_STORE_free(store);
        if (ctx) X509_STORE_CTX_free(ctx);
        return false;
    }

    // 3. Perform the verification
    int result = X509_verify_cert(ctx);

    if (result != 1) {
        cerr << "Verification failed: " << X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)) << endl;
    }

    // 4. Cleanup
    X509_free(caCert);
    X509_free(certToVerify);
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);

    return result == 1;
}


bool certificateVerification(const string& CertificateFilePath, const string& CA_Cert_FilePath){

    if (! verify_cert( CertificateFilePath.c_str(), CA_Cert_FilePath.c_str())){
        cerr << "Certificate Verification Failed" << endl;
        return 0;
    } 
    cout << "Verification Passed Successfully" << endl;
    return 1;

}  







