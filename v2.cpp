//apparently works with openssl 0.9.2b. No idea if it works with version 3.0.7 (Dec 2022 version)

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <memory.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

// Make these what you want for cert & key files
const char *certificateFilePath = "./foo-cert.pem";
const char *keyFilePath = "./foo-cert.pem";

int main()
{
    int
        err, listen_sd, sd;
    struct sockaddr_in
        sa_serv;
    struct sockaddr_in
        sa_cli;
    size_t
        client_len;
    SSL_CTX 
        *ctx;
    SSL
        *ssl;
    X509
        *client_cert;
    char
        *str, buf[4096];
    SSL_METHOD
        *meth;

    // SSL preliminaries. We keep the certificate and key with the context.

    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    meth = TLS_server_method();
    ctx = SSL_CTX_new(meth);
    if(!ctx)
    {
        ERR_print_errors_fp(stderr);
        exit(2);
    }

    if(SSL_CTX_use_certificate_file(ctx, certificateFilePath, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(3);
    }
    
    if(SSL_CTX_use_PrivateKey_file(ctx, keyFilePath, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(4);
    }

    if(!SSL_CTX_check_private_key(ctx))
    {
        fprintf(stderr,"Private key does not match the certificate public key\n");
        exit(5);
    }


    // Prepare TCP socket for receiving connections

    listen_sd = socket(AF_INET, SOCK_STREAM, 0);

    if(listen_sd == -1)
        exit(1);

    memset(&sa_serv, 0, sizeof(sa_serv));
    sa_serv.sin_family      = AF_INET;
    sa_serv.sin_addr.s_addr = INADDR_ANY;
    sa_serv.sin_port        = htons(1111);          // Server Port number

    err = bind(listen_sd, (struct sockaddr*) &sa_serv, sizeof(sa_serv));
    if(err == -1)
        exit(1);
    
    // Receive a TCP connection.

    err = listen(listen_sd, 5);
    if(err == -1)
        exit(1);

    client_len = sizeof(sa_cli);
    
    sd = accept(listen_sd, (struct sockaddr*) &sa_cli, &client_len);
    if(sd == -1)
        exit(1);
    
    close(listen_sd);

    printf("Connection from %lx, port %x\n",
    sa_cli.sin_addr.s_addr, sa_cli.sin_port);


    // TCP connection is ready. Do server side SSL.

    ssl = SSL_new(ctx);
    if(ssl == NULL)
        exit(1);

    SSL_set_fd(ssl, sd);
    err = SSL_accept(ssl);
    if(err == -1)
        exit(2);

    // Get the cipher - opt /

    printf("SSL connection using %s\n", SSL_get_cipher(ssl));

    // Get client's certificate (note: beware of dynamic allocation) - opt

    client_cert = SSL_get_peer_certificate(ssl);
    if(client_cert != NULL)
    {
        printf("Client certificate:\n");

        str = X509_NAME_oneline(X509_get_subject_name(client_cert), 0, 0);
        if(str == NULL)
            exit(1);
        
        printf("\t subject: %s\n", str);
        OPENSSL_free(str);

        str = X509_NAME_oneline(X509_get_issuer_name(client_cert), 0, 0);
        if(str == NULL)
            exit(1);
        
        printf("\t issuer: %s\n", str);
        OPENSSL_free(str);

        // We could do all sorts of certificate verification stuff here before
        // deallocating the certificate.

        X509_free(client_cert);
    }
    else
        printf("Client does not have certificate.\n");

    // DATA EXCHANGE - Receive message and send reply.

    err = SSL_read(ssl, buf, sizeof(buf) - 1);
    if(err == -1)
        exit(2);
    
    buf[err] = '\0';
    printf("Got %d chars:'%s'\n", err, buf);

    err = SSL_write(ssl, "I hear you.", strlen("I hear you."));
    if(err == -1)
        exit(2);

    // Clean up.

    close(sd);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
}
