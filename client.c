#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define FAIL -1

int OpenConnection(const char *hostname, int port)
{
    int sd;
    struct hostent *host;
    struct sockaddr_in addr;

    if ((host = gethostbyname(hostname)) == NULL)
    {
        fprintf(stderr, "%s: unknown host\n", hostname);
        exit(EXIT_FAILURE);
    }

    sd = socket(PF_INET, SOCK_STREAM, 0);
    if (sd < 0)
    {
        perror("Can't create socket");
        exit(EXIT_FAILURE);
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    memcpy(&addr.sin_addr, host->h_addr_list[0], sizeof(addr.sin_addr));

    if (connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0)
    {
        close(sd);
        perror("Connection failed");
        exit(EXIT_FAILURE);
    }

    return sd;
}

SSL_CTX* InitCTX(void)
{
    /* TODO:
     * 1. Create a new TLS client context (TLS_client_method)
     *    (OpenSSL >= 1.1 initializes itself, no SSL_library_init() etc. needed)
     * 2. Restrict the protocol to TLS 1.2
     *    (SSL_CTX_set_min_proto_version / SSL_CTX_set_max_proto_version)
     * 3. Load the CA certificate used to verify the server (SSL_CTX_load_verify_locations)
     * 4. Require a valid server certificate using SSL_CTX_set_verify with SSL_VERIFY_PEER
     */
    SSL_CTX *ctx = NULL;

    if (ctx == NULL)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
    /* TODO:
     * 1. Load client certificate using SSL_CTX_use_certificate_file
     * 2. Load client private key using SSL_CTX_use_PrivateKey_file
     * 3. Verify that private key matches certificate using SSL_CTX_check_private_key
     * On any failure: ERR_print_errors_fp(stderr) and exit
     */
}

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        printf("Usage: %s <hostname> <port>\n", argv[0]);
        exit(0);
    }

    char *hostname = argv[1];
    int port = atoi(argv[2]);
    SSL_CTX *ctx = NULL;
    SSL *ssl;
    int server;

    /* TODO:
     * 1. Initialize SSL context using InitCTX
     * 2. Load client certificate and key using LoadCertificates
     */

    server = OpenConnection(hostname, port);
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, server);

    /* TODO:
     * 1. Establish SSL connection using SSL_connect (print OpenSSL errors on failure)
     * 2. Print the negotiated protocol/cipher and the server certificate
     * 3. Ask the user to enter username and password
     * 4. Build the XML message dynamically, in exactly this format:
     *    <Body><UserName>%s</UserName><Password>%s</Password></Body>
     * 5. Send the XML message over SSL (SSL_write)
     * 6. Read the server response (SSL_read) and print it
     */

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(server);
    SSL_CTX_free(ctx);
    return 0;
}
