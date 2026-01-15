/*
 * Test1 - Authentication System with Vulnerabilities
 * 
 * Vulnerabilities:
 * 1. [EASY] Stack buffer overflow in get_username() - obvious gets() usage
 * 2. [MEDIUM] Format string vulnerability in log_attempt() - printf with user input
 * 3. [HARD] Integer overflow in check_access_level() - subtle arithmetic overflow
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_USERS 10
#define LOG_SIZE 256

// Global user database
struct User {
    char username[32];
    char password[32];
    int access_level;
    unsigned int login_count;
};

struct User users[MAX_USERS];
int user_count = 0;

// Initialize some default users
void init_users() {
    strcpy(users[0].username, "admin");
    strcpy(users[0].password, "admin123");
    users[0].access_level = 100;
    users[0].login_count = 0;
    
    strcpy(users[1].username, "guest");
    strcpy(users[1].password, "guest");
    users[1].access_level = 10;
    users[1].login_count = 0;
    
    user_count = 2;
}

/*
 * VULNERABILITY 1 [EASY]: Stack Buffer Overflow
 * Using gets() which has no bounds checking
 * Attacker can overflow the 64-byte buffer to overwrite return address
 */
void get_username(char *dest) {
    char buffer[64];
    printf("Enter username: ");
    gets(buffer);  // VULN: No bounds checking, classic stack overflow
    strcpy(dest, buffer);
}

/*
 * VULNERABILITY 2 [MEDIUM]: Format String Vulnerability
 * User-controlled string passed directly to printf
 * Attacker can use %x, %n to read/write memory
 */
void log_attempt(const char *username, int success) {
    char log_buffer[LOG_SIZE];
    char timestamp[32];
    
    // Get fake timestamp
    snprintf(timestamp, sizeof(timestamp), "[%d]", (int)time(NULL) % 100000);
    
    if (success) {
        snprintf(log_buffer, sizeof(log_buffer), "%s Login successful: %s", timestamp, username);
    } else {
        snprintf(log_buffer, sizeof(log_buffer), "%s Login failed: %s", timestamp, username);
    }
    
    // VULN: Format string - log_buffer contains user input (username)
    // If username contains %x or %n, it will be interpreted as format specifier
    printf(log_buffer);
    printf("\n");
}

/*
 * VULNERABILITY 3 [HARD]: Integer Overflow in Access Check
 * Subtle arithmetic overflow when calculating combined access level
 * If bonus is large enough, the multiplication can overflow and wrap around
 */
int check_access_level(int user_idx, unsigned int bonus) {
    if (user_idx < 0 || user_idx >= user_count) {
        return 0;
    }
    
    unsigned int base_level = users[user_idx].access_level;
    unsigned int login_bonus = users[user_idx].login_count;
    
    // VULN: Integer overflow - if bonus is very large (e.g., 0xFFFFFFFF)
    // the multiplication can overflow, resulting in a small number
    // that passes the check when it shouldn't
    unsigned int combined = base_level + (bonus * login_bonus);
    
    // This check can be bypassed via integer overflow
    if (combined >= 50) {
        return 1;  // Access granted
    }
    return 0;  // Access denied
}

int authenticate(const char *username, const char *password) {
    for (int i = 0; i < user_count; i++) {
        if (strcmp(users[i].username, username) == 0) {
            if (strcmp(users[i].password, password) == 0) {
                users[i].login_count++;
                return i;
            }
        }
    }
    return -1;
}

void admin_panel() {
    printf("\n=== ADMIN PANEL ===\n");
    printf("Welcome to the admin panel!\n");
    printf("You have full system access.\n");
    printf("==================\n\n");
}

void user_panel() {
    printf("\n=== USER PANEL ===\n");
    printf("Welcome! You have limited access.\n");
    printf("=================\n\n");
}

void print_menu() {
    printf("\n=== Authentication System ===\n");
    printf("1. Login\n");
    printf("2. Check Access (requires login)\n");
    printf("3. View Logs\n");
    printf("4. Exit\n");
    printf("Choice: ");
}

int main() {
    char username[128];
    char password[64];
    int choice;
    int current_user = -1;
    unsigned int bonus;
    
    init_users();
    printf("Authentication System v1.0\n");
    printf("WARNING: This system contains intentional vulnerabilities for testing.\n\n");
    
    while (1) {
        print_menu();
        scanf("%d", &choice);
        getchar();  // consume newline
        
        switch (choice) {
            case 1:
                // Uses vulnerable get_username function
                get_username(username);
                
                printf("Enter password: ");
                fgets(password, sizeof(password), stdin);
                password[strcspn(password, "\n")] = 0;
                
                current_user = authenticate(username, password);
                
                // Log attempt with potential format string vuln
                log_attempt(username, current_user >= 0);
                
                if (current_user >= 0) {
                    printf("Login successful!\n");
                } else {
                    printf("Login failed!\n");
                }
                break;
                
            case 2:
                if (current_user < 0) {
                    printf("Please login first.\n");
                    break;
                }
                
                printf("Enter access bonus value: ");
                scanf("%u", &bonus);
                
                // Uses vulnerable access check
                if (check_access_level(current_user, bonus)) {
                    admin_panel();
                } else {
                    user_panel();
                }
                break;
                
            case 3:
                printf("Log viewing not implemented.\n");
                break;
                
            case 4:
                printf("Goodbye!\n");
                return 0;
                
            default:
                printf("Invalid choice.\n");
        }
    }
    
    return 0;
}
