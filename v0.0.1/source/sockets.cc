#ifndef _WIN32
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <fcntl.h>
#include <netdb.h>
#include <unistd.h>
#include "websocket.h"

#define BUFFER_SIZE 2048

extern "C"
{
    void* gc_alloc(int size);

    int create_socket(int *port)
    {
        int listen_socket;
        struct sockaddr_in listen_socket_address;

        if ((listen_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        {
            return 1;
        }

        const int enable1 = 1;
        if (setsockopt(listen_socket, SOL_SOCKET, SO_REUSEADDR, &enable1, sizeof(int)) < 0)
            perror("setsockopt(SO_REUSEADDR) failed");

        const int enable2 = 1;
        if (setsockopt(listen_socket, SOL_SOCKET, SO_REUSEPORT, &enable2, sizeof(int)) < 0)
            perror("setsockopt(SO_REUSEPORT) failed");
        

        listen_socket_address.sin_family = AF_INET;
        listen_socket_address.sin_addr.s_addr = INADDR_ANY;
        listen_socket_address.sin_port = htons(*port);

        if (bind(listen_socket, (struct sockaddr *)&listen_socket_address, sizeof(listen_socket_address)) < 0)
        {
            return 1;
        }

        struct sockaddr_in sin;
        socklen_t len = sizeof(sin);
        if (getsockname(listen_socket, (struct sockaddr *)&sin, &len) != -1)
            *port = ntohs(sin.sin_port);


        if (listen(listen_socket, INT32_MAX) < 0)
        {
            return 1;
        }

        return listen_socket;
    }

    int open_socket(int *port, bool *run_socket, char *(*request_handler)(char *, char *), char *data)
    {
        int listen_socket = create_socket(port);
        struct sockaddr_in client;
        int client_size = sizeof(client);
        int client_socket;


        char buffer[BUFFER_SIZE] = {0};
        while (*run_socket)
        {
            if ((client_socket = accept(listen_socket, (struct sockaddr *)&client, (socklen_t *)&client_size)) < 0)
            {
                return 1;
            }

            if (read(client_socket, buffer, BUFFER_SIZE) < 0)
            {
                close(client_socket);
                return 1;
            }

            char *response = request_handler(data, buffer);

            if (write(client_socket, response, strlen(response)) == 0)
            {
                close(client_socket);
                return 1;
            }

            close(client_socket);
        }

        return 0;
    }

    int open_web_socket(int* current_client, int *port, bool *run_socket, void (*message_handler)(void *, int, char *), void *data)
    {
        int listen_socket = create_socket(port);
        struct sockaddr_in client;
        int client_size = sizeof(client);
        int client_socket;

        struct timeval timeout;      
        timeout.tv_sec = 10;
        timeout.tv_usec = 0;
        
        if (setsockopt (listen_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                    sizeof timeout) < 0)
            perror("setsockopt failed\n");

        if (setsockopt (listen_socket, SOL_SOCKET, SO_SNDTIMEO, &timeout,
                    sizeof timeout) < 0)
            perror("setsockopt failed\n");

        char buffer[BUFFER_SIZE] = {0};
        while (*run_socket)
        {
            if ((client_socket = accept(listen_socket, (struct sockaddr *)&client, (socklen_t *)&client_size)) < 0)
            {
                return 1;
            }
            *current_client = client_socket;
            if (read(client_socket, buffer, BUFFER_SIZE) < 0)
            {
                close(client_socket);
                return 1;
            }

            char *response = handleBuffer(buffer);

            if (write(client_socket, response, strlen(response)) == 0)
            {
                close(client_socket);
                return 1;
            }
            
            memset(buffer, 0, BUFFER_SIZE);

            int recvResult;
            
            while ((recvResult = recv(client_socket, buffer, BUFFER_SIZE, 0)))
            {
                struct MessageData messagedata = createMessageData((uint8_t *)buffer);

                if (messagedata.opcode == OPCODE_PING)
                {
                    int len = 0;
                    char *senddata = createSendData(messagedata.payload, OPCODE_PONG, &len);
                    write(client_socket, senddata, len);
                }
                else if (messagedata.opcode == OPCODE_TXT)
                {
                    message_handler(data, client_socket, messagedata.payload);
                }

                memset(buffer, 0, BUFFER_SIZE);
            }

            close(client_socket);
        }

        return 0;
    }

    #define REQUEST_BUFFER_SIZE 4096
    const char* create_request(char* host, int port, char* request) {
        struct hostent *server;
        struct sockaddr_in serv_addr;
        int sockfd, bytes, sent, received, total;
        char* response = (char*)gc_alloc(REQUEST_BUFFER_SIZE);

        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) return "Error: couldn't open socket";

        server = gethostbyname(host);
        if (server == NULL) {
            return "Error: no such host";
        }

        memset(&serv_addr,0,sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(port);
        memcpy(&serv_addr.sin_addr.s_addr,server->h_addr,server->h_length);

        if (connect(sockfd,(struct sockaddr *)&serv_addr,sizeof(serv_addr)) < 0)
            return "Error: while connectin";

        total = strlen(request);
        sent = 0;
        do {
            bytes = write(sockfd,request+sent,total-sent);
            if (bytes < 0)
                return "Error: couldn't write message to socket";
            if (bytes == 0)
                break;
            sent+=bytes;
        } while (sent < total);

        memset(response,0,REQUEST_BUFFER_SIZE);
        total = REQUEST_BUFFER_SIZE-1;
        received = 0;
        do {
            bytes = read(sockfd,response+received,total-received);
            if (bytes < 0)
                return "Error: reading response";
            if (bytes == 0)
                break;
            received+=bytes;
        } while (received < total);

        if (received == total)
            return "Error: response is bigger than response buffer";

        close(sockfd);

        return response;
    }
}
#else
#include <winsock2.h>
#include <Ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <Windows.h>
#include <iostream>
#include <string.h>
#include "websocket.h"
#pragma comment(lib, "ws2_32.lib")

#define _WINSOCK_DEPRECATED_NO_WARNINGS

#define BUFFER_SIZE 2048

extern "C" void *gc_alloc(int bytes);
extern "C" char *runtime_int_to_string(int number);

SOCKET create_socket(int *port)
{
    int iResult;

    SOCKET ListenSocket = INVALID_SOCKET;

    struct addrinfo *result = NULL;
    struct addrinfo hints;

    int iSendResult;

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    // Resolve the server address and port
    iResult = getaddrinfo(NULL, runtime_int_to_string(*port), &hints, &result);
    if (iResult != 0)
    {
        return 1;
    }

    // Create a SOCKET for the server to listen for client connections.
    ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (ListenSocket == INVALID_SOCKET)
    {
        freeaddrinfo(result);
        return 1;
    }

    const int enable1 = 1;
    if (setsockopt(ListenSocket, SOL_SOCKET, SO_REUSEADDR, (char *)&enable1, sizeof(enable1)) < 0)
    {
        char errbuf[300];
        FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, WSAGetLastError(),
                      0, errbuf, sizeof(errbuf), NULL);
        printf("setsockopt(SO_REUSEADDR): %s", errbuf);
    }
    
    // const int enable2 = 1;
    // if (setsockopt(ListenSocket, SOL_SOCKET, SO_BROADCAST, (char *)&enable2, sizeof(enable2)) < 0)
    // {
    //     char errbuf[300];
    //     FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, WSAGetLastError(),
    //                   0, errbuf, sizeof(errbuf), NULL);
    //     printf("setsockopt(SO_REUSEPORT): %s", errbuf);
    // }

    // Setup the TCP listening socket
    iResult = bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen);
    if (iResult == SOCKET_ERROR)
    {
        freeaddrinfo(result);
        closesocket(ListenSocket);
        return 1;
    }

    struct sockaddr_in sin;
    int addrlen = sizeof(sin);
    if (getsockname(ListenSocket, (struct sockaddr *)&sin, &addrlen) == 0 &&
        sin.sin_family == AF_INET &&
        addrlen == sizeof(sin))
    {
        *port = ntohs(sin.sin_port);
    }

    freeaddrinfo(result);

    iResult = listen(ListenSocket, SOMAXCONN);
    if (iResult == SOCKET_ERROR)
    {
        closesocket(ListenSocket);
        return 1;
    }

    return ListenSocket;
}

extern "C"
{
    int windowsStart()
    {
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
        {
            return 1;
        }

        return 0;
    }

    void windowsCleanup()
    {
        WSACleanup();
    }

    int open_web_socket(int* current_client,int *port, bool *run_socket, void (*message_handler)(char *, int, char *), char *data)
    {
        SOCKET ListenSocket = create_socket(port);
        SOCKET ClientSocket = INVALID_SOCKET;

        int iSendResult;
        int iRecvResult;

        char buffer[BUFFER_SIZE];
        while (*run_socket)
        {
            ClientSocket = accept(ListenSocket, NULL, NULL);
            *current_client = ClientSocket;

            if (ClientSocket == INVALID_SOCKET)
            {
                closesocket(ListenSocket);
                return 1;
            }

            iRecvResult = recv(ClientSocket, buffer, BUFFER_SIZE, 0);
            if (iRecvResult > 0)
            {
                char *response = handleBuffer(buffer);

                iSendResult = send(ClientSocket, response, strlen(response), 0);
                if (iSendResult == SOCKET_ERROR)
                {
                    closesocket(ClientSocket);
                    return 1;
                }

                ZeroMemory(buffer, BUFFER_SIZE);

                while ((iRecvResult = recv(ClientSocket, buffer, BUFFER_SIZE, 0)))
                {
                    struct MessageData messagedata = createMessageData((uint8_t *)buffer);

                    if (messagedata.opcode == OPCODE_PING)
                    {
                        int len = 0;
                        char *senddata = createSendData(messagedata.payload, OPCODE_PONG, &len);
                        send(ClientSocket, senddata, strlen(senddata), 0);
                    }
                    else if (messagedata.opcode == OPCODE_TXT)
                    {
                        message_handler(data, ClientSocket, messagedata.payload);
                    }
                    else
                    {
                    }

                    ZeroMemory(buffer, BUFFER_SIZE);
                }
            }
            else if (iRecvResult < 0)
            {
                closesocket(ClientSocket);
                return 1;
            }

            close_socket(ClientSocket);
        }

        return 0;
    }

    int open_socket(int *port, bool *run_socket, char *(*request_handler)(char *, char *), char *data)
    {
        SOCKET ListenSocket = create_socket(port);
        SOCKET ClientSocket = INVALID_SOCKET;

        int iSendResult;
        int iRecvResult;

        char buffer[BUFFER_SIZE];
        while (*run_socket)
        {
            ClientSocket = accept(ListenSocket, NULL, NULL);

            if (ClientSocket == INVALID_SOCKET)
            {
                closesocket(ListenSocket);
                return 1;
            }

            iRecvResult = recv(ClientSocket, buffer, BUFFER_SIZE, 0);

            char *response = request_handler(data, buffer);
            iSendResult = send(ClientSocket, response, strlen(response), 0);
            if (iSendResult == SOCKET_ERROR)
            {
                closesocket(ClientSocket);
                return 1;
            }

            close_socket(ClientSocket);
        }

        return 0;
    }

#define REQUEST_BUFFER_SIZE 4096
    const char *create_request(char *host, int port, char *request)
    {
        struct hostent *server;
        struct sockaddr_in serv_addr;
        int sockfd, bytes, sent, received, total;
        char *response = (char *)gc_alloc(REQUEST_BUFFER_SIZE);

        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0)
            return "Error: couldn't open socket";

        server = gethostbyname(host);
        if (server == NULL)
        {
            return "Error: no such host";
        }

        memset(&serv_addr, 0, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(port);
        memcpy(&serv_addr.sin_addr.s_addr, server->h_addr, server->h_length);

        if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
            return "Error: while connectin";

        total = strlen(request);
        sent = 0;
        do
        {
            bytes = send(sockfd, request + sent, total - sent, 0);
            if (bytes < 0)
                return "Error: couldn't write message to socket";
            if (bytes == 0)
                break;
            sent += bytes;
        } while (sent < total);

        memset(response, 0, REQUEST_BUFFER_SIZE);
        total = REQUEST_BUFFER_SIZE - 1;
        received = 0;
        do
        {
            bytes = recv(sockfd, response + received, total - received, 0);
            if (bytes < 0)
                return "Error: reading response";
            if (bytes == 0)
                break;
            received += bytes;
        } while (received < total);

        if (received == total)
            return "Error: response is bigger than response buffer";

        closesocket(sockfd);

        return response;
    }
}
#endif