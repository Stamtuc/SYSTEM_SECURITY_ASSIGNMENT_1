Stamatis Daskalakis - AM: 2022030172
Filippos Voulgaris - AM: 2022030039

OpenSSL documentation (definitions and terms): https://docs.openssl.org/3.0/



--Description of tool--

A client-server application in C that uses OpenSSL (libssl, libcrypto) to communicate over TLS 1.2 with mutual authentication. Both sides present X.509 certificates signed by our own CA (RootCA) and verify the peer.

server: accepts only TLS 1.2 and requires a valid client certificate. It replies with the XML response for Sousi/123 (case-sensitive), and with Invalid Message otherwise.

client: verifies the server, sends <Body><UserName>..</UserName><Password>..</Password></Body> and prints the reply.

rclient: same as the client, but its certificate is signed by an untrusted CA (FraudCA). The handshake is rejected.



--Certificate Creation and Signature Commands--

# CREATE A CERTIFICATE AUTHORITY (CA) AND USE IT TO SIGN BOTH SERVER AND CLIENT CERTIFICATES

openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout ca.key -out ca.crt -subj "/C=GR/ST=Crete/L=Chania/O=TechnicalUniversityofCrete/OU=ECE Lab/CN=RootCA"

# GENERATE SERVER CERTIFICATE (SIGNED BY CA)
# 1. CREATE SERVER KEY AND CSR

openssl req -new -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj "/C=GR/ST=Crete/L=Chania/O=TechnicalUniversityofCrete/OU=ECE Lab/CN=localhost"

# 2. SIGN WITH CA

openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365 -sha256

# GENERATE CLIENT CERTIFICATE (SIGNED BY CA)
# 1. CREATE CLIENT KEY AND CSR

openssl req -new -newkey rsa:2048 -nodes -keyout client.key -out client.csr -subj "/C=GR/ST=Crete/L=Chania/O=TechnicalUniversityofCrete/OU=ECE Lab/CN=client"

# 2. SIGN WITH CA

openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 365 -sha256

# CREATE A SECOND CA THAT THE SERVER DOES NOT TRUST, AND USE IT TO SIGN A NEW CLIENT CERTIFICATE (rclient.crt / rclient.key)

openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout fraud_ca.key -out fraud_ca.crt -subj "/C=GR/ST=Crete/L=Chania/O=FraudOrg/OU=Fraud Lab/CN=FraudCA"

# 1. CREATE ROGUE CLIENT KEY AND CSR

openssl req -new -newkey rsa:2048 -nodes -keyout rclient.key -out rclient.csr -subj "/C=GR/ST=Crete/L=Chania/O=FraudOrg/OU=Fraud Lab/CN=rclient"

# 2. SIGN WITH THE UNTRUSTED CA

openssl x509 -req -in rclient.csr -CA fraud_ca.crt -CAkey fraud_ca.key -CAcreateserial -out rclient.crt -days 365 -sha256



--Command Parameters--

openssl req: creates certificate requests (CSRs, PKCS#10) and self-signed certificates.

# CREATE A CERTIFICATE AUTHORITY (CA)
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout ca.key -out ca.crt -subj "/C=GR/.../CN=RootCA"

# CREATE SERVER / CLIENT KEY AND CSR
openssl req -new -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj "/C=GR/.../CN=localhost"

-new: generates a new certificate request.
-newkey rsa:2048: generates a new 2048-bit RSA private key (implies -new).
-nodes: the private key is not encrypted (deprecated in 3.0; same as -noenc).
-keyout: file for the new private key.
-out: output file.
-x509: outputs a self-signed certificate instead of a request (used for the CAs).
-days: validity period in days (default 30).
-subj: subject name. C country, ST state, L locality, O organization, OU unit, CN common name.


openssl x509: certificate handling; here the CA signs a CSR.

# SIGN WITH CA
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365 -sha256

-req: the input is a CSR instead of a certificate.
-in: input file.
-CA: CA certificate used for signing; its subject becomes the issuer of the new certificate.
-CAkey: CA private key that creates the signature.
-CAcreateserial: creates the serial number file (ca.srl) if it does not exist.
-out: output certificate.
-days: validity period in days.
-sha256: digest used for the signature.



--Answers--

What does "tlsv1 alert unknown ca" mean?

"A valid certificate chain or partial chain was received, but the certificate was not accepted because the CA certificate could not be located or couldn't be matched with a known, trusted CA.
This message is always fatal." (OpenSSL, SSL_alert_type_string(3))
 
FraudCA is not in the server's trusted CA file (ca.crt). The server therefore terminates the handshake.

What would change with TLS 1.3?

The server would still refuse the connection.In TLS 1.3 "the last peer to communicate in the handshake is the client" (OpenSSL, SSL_connect(3)).
The rclient's SSL_connect(),therefore succeeds,and the "unknown ca" alert is received later, on SSL_read(). 

The server would still refuse the connection.In TLS 1.3 "the last peer to communicate in the handshake is the client" (OpenSSL, SSL_connect(3)).
The rclient's SSL_connect(),therefore succeeds,and the "unknown ca" alert is received later, on SSL_read(). 
