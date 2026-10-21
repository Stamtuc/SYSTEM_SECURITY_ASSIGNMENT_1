#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>


#define FAIL -1

int OpenListener(int port) {
    int sd, on = 1;
    struct sockaddr_in addr;

    sd = socket(PF_INET, SOCK_STREAM, 0);
    if (sd < 0) {
        perror("Can't create socket");
        exit(EXIT_FAILURE);
    }

    /* Allow restarting the server immediately (avoids "Address already in use") */
    setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        perror("Can't bind port");
        exit(EXIT_FAILURE);
    }

    if (listen(sd, 10) != 0) {
        perror("Can't configure listening port");
        exit(EXIT_FAILURE);
    }

    return sd;
}

SSL_CTX* InitServerCTX(void) {
    /* TODO:
     * 1. Create a new TLS server context (TLS_server_method)
     *    (OpenSSL >= 1.1 initializes itself, no SSL_library_init() etc. needed)
     * 2. Restrict the protocol to TLS 1.2
     *    (SSL_CTX_set_min_proto_version / SSL_CTX_set_max_proto_version)
     * 3. Load the CA certificate used to verify clients (SSL_CTX_load_verify_locations)
     * 4. Require a valid client certificate (mutual TLS) using SSL_CTX_set_verify
     *    with SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT
     */
    //SSL_CTX *ctx = NULL;
    
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (ctx == NULL) {
        perror("Failure to create a new SSL_CTX object.");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if( SSL_CTX_set_min_proto_version(ctx,TLS1_2_VERSION)!=1 ||
         SSL_CTX_set_max_proto_version(ctx,TLS1_2_VERSION)!=1) {
          perror("Failure to set TLS version.");
          ERR_print_errors_fp(stderr);
          exit(EXIT_FAILURE); 
     }
   
    if(SSL_CTX_load_verify_locations(ctx, "ca.crt", NULL) != 1) {
        perror("Failure to load CA certificate.");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    
    return ctx;
}

void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile) {
    /* TODO:
     * 1. Load server certificate using SSL_CTX_use_certificate_file
     * 2. Load server private key using SSL_CTX_use_PrivateKey_file
     * 3. Check that private key matches the certificate using SSL_CTX_check_private_key
     * On any failure: ERR_print_errors_fp(stderr) and exit
     */


    if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) != 1) {
        fprintf(stderr, "Failed to load certificate %s\n", CertFile);
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) != 1) {
        fprintf(stderr, "Failed to load private key %s\n", KeyFile);
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_check_private_key(ctx) != 1) {
        fprintf(stderr, "Private key does not match the certificate\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

void ShowCerts(SSL* ssl) {
    /* TODO:
     * 1. Get client certificate (if any) using SSL_get1_peer_certificate
     * 2. Print Subject and Issuer names (X509_get_subject_name, X509_get_issuer_name,
     *    X509_NAME_oneline)
     * 3. Free the certificate with X509_free
     */
    char *string;
    X509 *cert = SSL_get1_peer_certificate(ssl);

    if (cert == NULL) {
        printf("No client certificate provided.\n");
        return;
    }

    printf("Client certificate:\n");

    string = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
    printf("Subject: %s\n", string);
    OPENSSL_free(string);

    string = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
    printf("Issuer: %s\n", string);
    OPENSSL_free(string);

    X509_free(cert);
}



void Servlet(SSL* ssl) {
    char buf[1024] = {0};
    int sd = SSL_get_fd(ssl);
    int bytes;

    if (SSL_accept(ssl) == FAIL) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    ShowCerts(ssl);

    bytes = SSL_read(ssl, buf, sizeof(buf) - 1);
    if (bytes <= 0) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    buf[bytes] = '\0';
    printf("Client message: %s\n", buf);

    /* TODO:
     * 1. Parse XML from client message to extract UserName and Password
     * 2. Compare credentials to the predefined values "Sousi" / "123"
     * 3. Send the XML response from the assignment if they match,
     *    otherwise send "Invalid Message"
     */

cleanup:
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sd);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <port>\n", argv[0]);
        exit(0);
    }

    int port = atoi(argv[1]);
    SSL_CTX *ctx = NULL;

    /* TODO:
     * 1. Initialize SSL context using InitServerCTX
     * 2. Load server certificate and key using LoadCertificates
     */
    ctx = InitServerCTX();
    LoadCertificates(ctx, "server.crt", "server.key");




    int server = OpenListener(port);

    while (1) {
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        SSL *ssl = NULL;

        int client = accept(server, (struct sockaddr*)&addr, &len);
        if (client < 0) {
            perror("accept");
            continue;
        }
        printf("Connection from %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

        /* TODO:
         * 1. Create new SSL object from ctx
         * 2. Set file descriptor for SSL using SSL_set_fd
         * 3. Call Servlet to handle the client
         */
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);
        Servlet(ssl);
    }

    close(server);
    SSL_CTX_free(ctx);
}
