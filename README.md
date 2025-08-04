# Implementing Public Key Infrastructure using OpenSSL and C++


<!-- Commands to Run

1. make
2. ./mini-pki --init-ca --cn "My Root CA"
3. ./mini-pki --gen-csr --cn "localhost"
4. mv KeysAndCerts/client_private_key.pem KeysAndCerts/server_private_key.pem
5. mv KeysAndCerts/client_csr.pem KeysAndCerts/server_csr.pem
6. ./mini-pki --sign-csr --csr KeysAndCerts/server_csr.pem --out KeysAndCerts/server_cert.pem./7. ./mini-pki --gen-csr --cn "client"
8. ./mini-pki --sign-csr --csr KeysAndCerts/client_csr.pem --out KeysAndCerts/client_cert.pem
9. openssl ca -gencrl \
  -keyfile KeysAndCerts/ca_private_key.pem \
  -cert KeysAndCerts/ca_cert.pem \
  -out KeysAndCerts/ca_crl.pem \
  -config openssl.cnf

  

./mini-pki-server
./mini-pki-client -->