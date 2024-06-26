# ECDSA Key creation


### Create private key
    openssl ecparam -name P-384 -genkey -noout -out ec-P-384-priv-key.pem

### Create public key
    openssl ec -in ec-P-384-priv-key.pem -pubout > ec-P-384-pub-key.pem