#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>

#pragma comment(lib, "ws2_32.lib")

#define PORT 21
#define BUFFER_SIZE 1024

const char *FTP_USER = "admin";
const char *FTP_PASS = "MerdeMerde2023+";

void handle_client(SOCKET client_socket) {
    char buffer[BUFFER_SIZE];
    char user[BUFFER_SIZE];
    char pass[BUFFER_SIZE];
    int recv_size;

    send(client_socket, "220 Welcome to Simple FTP Server\r\n", 35, 0);

    // Receive USER command
    recv_size = recv(client_socket, buffer, BUFFER_SIZE, 0);
    buffer[recv_size] = '\0';
    sscanf(buffer, "USER %s", user);
    send(client_socket, "331 Username OK, need password\r\n", 32, 0);

    // Receive PASS command
    recv_size = recv(client_socket, buffer, BUFFER_SIZE, 0);
    buffer[recv_size] = '\0';
    sscanf(buffer, "PASS %s", pass);

    // Check credentials
    if (strcmp(user, FTP_USER) == 0 && strcmp(pass, FTP_PASS) == 0) {
        send(client_socket, "230 User logged in, proceed\r\n", 29, 0);
    } else {
        send(client_socket, "530 Not logged in\r\n", 19, 0);
    }

    // Closing connection
    closesocket(client_socket);
}

int main() {
    WSADATA wsa;
    SOCKET server_socket, client_socket;
    struct sockaddr_in server, client;
    int client_len = sizeof(client);

    printf("\nInitialising Winsock...");
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
        printf("Failed. Error Code : %d", WSAGetLastError());
        return 1;
    }
    printf("Initialised.\n");

    if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
        printf("Could not create socket : %d", WSAGetLastError());
        return 1;
    }
    printf("Socket created.\n");

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr("10.0.1.35");
    server.sin_port = htons(PORT);

    if (bind(server_socket, (struct sockaddr *)&server, sizeof(server)) == SOCKET_ERROR) {
        printf("Bind failed with error code : %d", WSAGetLastError());
        return 1;
    }
    printf("Bind done.\n");

    listen(server_socket, 3);

    printf("Waiting for incoming connections...\n");
    while ((client_socket = accept(server_socket, (struct sockaddr *)&client, &client_len)) != INVALID_SOCKET) {
        printf("Connection accepted.\n");
        handle_client(client_socket);
    }

    if (client_socket == INVALID_SOCKET) {
        printf("Accept failed with error code : %d", WSAGetLastError());
        return 1;
    }

    closesocket(server_socket);
    WSACleanup();

    return 0;
}
