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

int setUpListenedSocket(unsigned short portNumber)
{
    struct sockaddr_in
        listenerAddress;
    int
        listenerFd
    
    listenerFd = socket(AF_INET, SOCK_STREAM, 0);
     
    if(listenerFd < 0)
        return -1

    memset(&listenerAddress, 0, sizeof(struct sockaddr_in));
    
    listenerAddress.sin_family = AF_INET;
    listenerAddress.sin_addr.s_addr = INADDR_ANY;
    listenerAddress.sin_port = htons(portNumber);
    
    //assigns the address to the socket
    if(bind(listenerFd, (const struct sockaddr*) &listenerAddress, sizeof(struct sockaddr_in)) == -1)
        return -1;

    //sets the socket to listen mode.
    if(listen(pvListenerFd, SOMAXCONN) == -1)
        return -1;

    return listenerFd;
}

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

    listen_sd = setUpListenedSocket(1111);

    sd = accept(listen_sd, NULL, NULL);
    if(sd == -1)
        exit(1);
    
    close(listen_sd);

    // TCP connection is ready. Do server side SSL.

    ssl = SSL_new(ctx);
    if(ssl == NULL)
        exit(1);

    SSL_set_fd(ssl, sd);
    err = SSL_accept(ssl); // a return value 1 is success, 0 is controlled failure, < 0 is fatal failure
    
    if(err == -1)
        exit(2);

    // DATA EXCHANGE - Receive message and send reply.

    err = SSL_read(ssl, buf, sizeof(buf) - 1); //returns bytes read
    if(err == -1)
        exit(2);
    
    buf[err] = '\0';
    printf("Got %d chars:'%s'\n", err, buf);

    err = SSL_write(ssl, "I hear you.", strlen("I hear you.")); //returns bytes written
    if(err == -1)
        exit(2);

    // Clean up.

    close(sd);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
}
