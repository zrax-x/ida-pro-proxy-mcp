/*
 * Test3 - File Server with Complex Vulnerabilities
 * 
 * Vulnerabilities:
 * 1. [EASY] Command injection in backup_file() - system() with user input
 * 2. [MEDIUM] Path traversal in read_file() - no sanitization of "../"
 * 3. [HARD] Race condition (TOCTOU) in secure_delete() - check then use gap
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#define MAX_PATH 256
#define MAX_CONTENT 4096
#define SANDBOX_DIR "/tmp/fileserver"

// Simulated file database
typedef struct {
    char filename[64];
    char owner[32];
    int permissions;  // Unix-style: 0644, etc.
    int exists;
} FileEntry;

FileEntry file_db[32];
int file_count = 0;
char current_user[32] = "guest";

void init_filesystem() {
    // Create sandbox directory
    mkdir(SANDBOX_DIR, 0755);
    
    // Initialize some files
    strcpy(file_db[0].filename, "readme.txt");
    strcpy(file_db[0].owner, "admin");
    file_db[0].permissions = 0644;
    file_db[0].exists = 1;
    
    strcpy(file_db[1].filename, "secret.txt");
    strcpy(file_db[1].owner, "admin");
    file_db[1].permissions = 0600;
    file_db[1].exists = 1;
    
    strcpy(file_db[2].filename, "public.txt");
    strcpy(file_db[2].owner, "guest");
    file_db[2].permissions = 0666;
    file_db[2].exists = 1;
    
    file_count = 3;
    
    // Create actual files
    FILE *f;
    char path[MAX_PATH];
    
    snprintf(path, sizeof(path), "%s/readme.txt", SANDBOX_DIR);
    f = fopen(path, "w");
    if (f) { fprintf(f, "Welcome to the file server!\n"); fclose(f); }
    
    snprintf(path, sizeof(path), "%s/secret.txt", SANDBOX_DIR);
    f = fopen(path, "w");
    if (f) { fprintf(f, "SECRET: The password is hunter2\n"); fclose(f); }
    
    snprintf(path, sizeof(path), "%s/public.txt", SANDBOX_DIR);
    f = fopen(path, "w");
    if (f) { fprintf(f, "This is a public file.\n"); fclose(f); }
}

/*
 * VULNERABILITY 1 [EASY]: Command Injection
 * User-controlled filename passed directly to system()
 * Attacker can inject shell commands using ; | & etc.
 */
void backup_file(const char *filename) {
    char command[512];
    
    printf("Creating backup of %s...\n", filename);
    
    // VULN: Command injection - filename is not sanitized
    // Attacker can use: "file.txt; cat /etc/passwd" or "file.txt && rm -rf /"
    snprintf(command, sizeof(command), 
             "cp %s/%s %s/%s.bak 2>/dev/null", 
             SANDBOX_DIR, filename, SANDBOX_DIR, filename);
    
    system(command);  // VULN: Executes user-controlled command
    printf("Backup complete.\n");
}

/*
 * VULNERABILITY 2 [MEDIUM]: Path Traversal
 * No sanitization of directory traversal sequences
 * Attacker can read files outside sandbox using "../../../etc/passwd"
 */
void read_file(const char *filename) {
    char path[MAX_PATH];
    char content[MAX_CONTENT];
    FILE *f;
    
    // VULN: Path traversal - no check for ".." sequences
    // Attacker can escape sandbox: "../../../etc/passwd"
    snprintf(path, sizeof(path), "%s/%s", SANDBOX_DIR, filename);
    
    // No validation that path stays within SANDBOX_DIR!
    
    f = fopen(path, "r");
    if (!f) {
        printf("Cannot open file: %s\n", strerror(errno));
        return;
    }
    
    printf("\n=== Contents of %s ===\n", filename);
    while (fgets(content, sizeof(content), f)) {
        printf("%s", content);
    }
    printf("=== End of file ===\n\n");
    
    fclose(f);
}

/*
 * Helper: Check if user can access file
 */
int can_access(const char *filename, const char *user) {
    for (int i = 0; i < file_count; i++) {
        if (strcmp(file_db[i].filename, filename) == 0 && file_db[i].exists) {
            // Owner can always access
            if (strcmp(file_db[i].owner, user) == 0) {
                return 1;
            }
            // Check world-readable
            if (file_db[i].permissions & 0004) {
                return 1;
            }
            return 0;
        }
    }
    return 0;  // File not in database
}

/*
 * VULNERABILITY 3 [HARD]: TOCTOU Race Condition
 * Time-of-check to time-of-use vulnerability
 * Permission check and file operation are not atomic
 * Attacker can swap file between check and delete
 */
void secure_delete(const char *filename) {
    char path[MAX_PATH];
    struct stat st;
    
    snprintf(path, sizeof(path), "%s/%s", SANDBOX_DIR, filename);
    
    // Step 1: Check if file exists
    if (stat(path, &st) != 0) {
        printf("File does not exist.\n");
        return;
    }
    
    // Step 2: Check permissions (TOCTOU window starts here)
    // VULN: Race condition - file can be replaced between stat() and unlink()
    // Attacker can:
    // 1. Create symlink to target file
    // 2. Wait for stat() to pass
    // 3. Replace symlink with link to sensitive file
    // 4. unlink() deletes the sensitive file
    
    if (!can_access(filename, current_user)) {
        printf("Permission denied.\n");
        return;
    }
    
    printf("Performing secure delete...\n");
    
    // Simulate some processing delay (makes race easier to exploit)
    usleep(100000);  // 100ms delay - TOCTOU window
    
    // Step 3: Actually delete (TOCTOU window ends here)
    // By now, the file might have been replaced with a symlink to /etc/passwd
    if (unlink(path) == 0) {
        printf("File securely deleted.\n");
        
        // Update database
        for (int i = 0; i < file_count; i++) {
            if (strcmp(file_db[i].filename, filename) == 0) {
                file_db[i].exists = 0;
                break;
            }
        }
    } else {
        printf("Delete failed: %s\n", strerror(errno));
    }
}

void write_file(const char *filename, const char *content) {
    char path[MAX_PATH];
    FILE *f;
    
    // Basic path construction (still vulnerable to traversal)
    snprintf(path, sizeof(path), "%s/%s", SANDBOX_DIR, filename);
    
    f = fopen(path, "w");
    if (!f) {
        printf("Cannot create file: %s\n", strerror(errno));
        return;
    }
    
    fprintf(f, "%s", content);
    fclose(f);
    
    // Add to database if new
    int found = 0;
    for (int i = 0; i < file_count; i++) {
        if (strcmp(file_db[i].filename, filename) == 0) {
            file_db[i].exists = 1;
            found = 1;
            break;
        }
    }
    
    if (!found && file_count < 32) {
        strncpy(file_db[file_count].filename, filename, 63);
        strcpy(file_db[file_count].owner, current_user);
        file_db[file_count].permissions = 0644;
        file_db[file_count].exists = 1;
        file_count++;
    }
    
    printf("File written successfully.\n");
}

void list_files() {
    printf("\n=== File List ===\n");
    printf("%-20s %-10s %-6s\n", "Filename", "Owner", "Perms");
    printf("%-20s %-10s %-6s\n", "--------", "-----", "-----");
    
    for (int i = 0; i < file_count; i++) {
        if (file_db[i].exists) {
            printf("%-20s %-10s %04o\n", 
                   file_db[i].filename, 
                   file_db[i].owner,
                   file_db[i].permissions);
        }
    }
    printf("=================\n\n");
}

void print_menu() {
    printf("\n=== File Server [%s] ===\n", current_user);
    printf("1. List files\n");
    printf("2. Read file\n");
    printf("3. Write file\n");
    printf("4. Delete file\n");
    printf("5. Backup file\n");
    printf("6. Switch user\n");
    printf("7. Exit\n");
    printf("Choice: ");
}

int main() {
    int choice;
    char filename[128];
    char content[MAX_CONTENT];
    
    init_filesystem();
    printf("File Server v1.0\n");
    printf("Sandbox: %s\n", SANDBOX_DIR);
    printf("WARNING: This system contains intentional vulnerabilities for testing.\n\n");
    
    while (1) {
        print_menu();
        scanf("%d", &choice);
        getchar();  // consume newline
        
        switch (choice) {
            case 1:
                list_files();
                break;
                
            case 2:
                printf("Enter filename: ");
                fgets(filename, sizeof(filename), stdin);
                filename[strcspn(filename, "\n")] = 0;
                read_file(filename);
                break;
                
            case 3:
                printf("Enter filename: ");
                fgets(filename, sizeof(filename), stdin);
                filename[strcspn(filename, "\n")] = 0;
                printf("Enter content: ");
                fgets(content, sizeof(content), stdin);
                content[strcspn(content, "\n")] = 0;
                write_file(filename, content);
                break;
                
            case 4:
                printf("Enter filename: ");
                fgets(filename, sizeof(filename), stdin);
                filename[strcspn(filename, "\n")] = 0;
                secure_delete(filename);
                break;
                
            case 5:
                printf("Enter filename: ");
                fgets(filename, sizeof(filename), stdin);
                filename[strcspn(filename, "\n")] = 0;
                backup_file(filename);
                break;
                
            case 6:
                printf("Enter username: ");
                fgets(current_user, sizeof(current_user), stdin);
                current_user[strcspn(current_user, "\n")] = 0;
                printf("Switched to user: %s\n", current_user);
                break;
                
            case 7:
                printf("Goodbye!\n");
                return 0;
                
            default:
                printf("Invalid choice.\n");
        }
    }
    
    return 0;
}
