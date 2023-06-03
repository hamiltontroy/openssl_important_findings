//  Made by Troy A. Hamilton (12/21/2022)
//  No guarantees offered. Constructive comments to wmmmwd@gmail.com

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

#define preloadAlgorithms OpenSSL_add_ssl_algorithms
#define tlsRead SSL_read
#define tlsWrite SSL_write
#define handshakeWithClient SSL_accept


int tcpListenerSocket(unsigned short portNumber)
{
    struct sockaddr_in
        listenerAddress;
    int
        listenerFd, valueReturned;
    
    listenerFd = socket(AF_INET, SOCK_STREAM, 0);
     
    if(listenerFd < 0)
        return -1;

    memset(&listenerAddress, 0, sizeof(struct sockaddr_in));
    
    listenerAddress.sin_family = AF_INET;
    listenerAddress.sin_addr.s_addr = INADDR_ANY;
    listenerAddress.sin_port = htons(portNumber);
    
    //assigns the address to the socket
    if(bind(listenerFd, (const struct sockaddr*) &listenerAddress, sizeof(struct sockaddr_in)) == -1)
        return -1;

    //sets the socket to listen mode.
    if(listen(ListenerFd, SOMAXCONN) == -1)
        return -1;

    return listenerFd;
}

SSL_CTX *tlsServerConfig(const char *cert, const char *key)
{
    SSL_CTX 
        *ctx;
    
    //Commencing initial configuration
    
    ctx = SSL_CTX_new(TLS_server_method());
    if(ctx == NULL)
        return NULL;

    valueReturned = SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM);
    if(valueReturned != 1)
        return NULL;
    
    valueReturned = SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM);
    if(valueReturned != 1)
        return NULL;

    valueReturned = SSL_CTX_check_private_key(ctx);
    if(valueReturned != 1)
        return NULL;
    
    //Initial configuration complete
    
    return ctx;
}

SSL *tcpBindTls(int socketfd, SSL_CTX *ctx)
{
    SSL
        *ssl;
    
    //Some more SSL configuration
    ssl = SSL_new(ctx);
    if(ssl == NULL)
        return NULL;

    valueReturned = SSL_set_fd(ssl, socketfd);
    if(valueReturned != 1)
    {
        SSL_free(ssl);
        return NULL;
    }
    
    return ssl;
}

int main()
{
    SSL_CTX 
        *ctx;
    int
        listenerSocket, clientSocket, valueReturned;
    SSL
        *ssl;
    char
        buffer[1024], *message = "I got your message, the TLS connection was successful!\n";
    
    preloadAlgorithms();
    
    ctx = tlsServerConfig("certificate.pem", "key.pem");
    if(ctx == NULL)
        return -1;
    
    listenerSocket = tcpListenerSocket(1025); //Sets up a tcp socket ready to accept() on port 1025
    if(listenerSocket < 0)
        return -1;
    
    clientSocket = accept(listenerSocket, NULL, NULL);
    if(clientSocket < 0)
        return -1;
    
    close(listenerSocket);
    
    ssl = tcpBindTls(clientSocket, ctx);
    if(ssl == NULL)
        return -1;
    
    valueReturned = handshakeWithClient(ssl);
    if(valueReturned != 1)
        return -1;
    
    //Do actual communication now
    valueReturned = tlsRead(ssl, buffer, sizeof(buffer) - 1);
    if(valueReturned < 1)
        return -1;
    
    buffer[valueReturned] = '\0'; // NULL terminate the buffer for printing
    
    printf("%s\n", buffer);
    
    valueReturned = tlsWrite(ssl, message, strlen(message));
    if(valueReturned < strlen(message))
        return -1;
    
    close(clientSocket);
    SSL_free(ssl);
    SSL_CTX_free(ctx);

    return 0;
}
