/*
 * Test2 - Note Manager with Heap Vulnerabilities
 * 
 * Vulnerabilities:
 * 1. [EASY] Heap buffer overflow in edit_note() - no bounds check on input
 * 2. [MEDIUM] Use-After-Free in view_note() - accessing freed memory
 * 3. [HARD] Double Free in delete_note() - subtle condition allows double free
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_NOTES 16
#define NOTE_SIZE 64

// Note structure
typedef struct {
    char *content;
    size_t size;
    int in_use;
    int marked_for_delete;
} Note;

Note notes[MAX_NOTES];
int last_deleted = -1;  // Track last deleted note for UAF

void init_notes() {
    for (int i = 0; i < MAX_NOTES; i++) {
        notes[i].content = NULL;
        notes[i].size = 0;
        notes[i].in_use = 0;
        notes[i].marked_for_delete = 0;
    }
}

int create_note(size_t size) {
    for (int i = 0; i < MAX_NOTES; i++) {
        if (!notes[i].in_use) {
            notes[i].content = (char *)malloc(size);
            if (!notes[i].content) {
                printf("Allocation failed!\n");
                return -1;
            }
            memset(notes[i].content, 0, size);
            notes[i].size = size;
            notes[i].in_use = 1;
            notes[i].marked_for_delete = 0;
            return i;
        }
    }
    printf("No free slots!\n");
    return -1;
}

/*
 * VULNERABILITY 1 [EASY]: Heap Buffer Overflow
 * No bounds checking when reading user input into note
 * User can write more than allocated size, corrupting heap metadata
 */
void edit_note(int idx) {
    if (idx < 0 || idx >= MAX_NOTES) {
        printf("Invalid index!\n");
        return;
    }
    
    if (!notes[idx].in_use) {
        printf("Note not in use!\n");
        return;
    }
    
    printf("Enter new content: ");
    // VULN: Heap overflow - reads unlimited input into fixed-size buffer
    // If user enters more than notes[idx].size bytes, heap corruption occurs
    scanf("%s", notes[idx].content);  // No length limit!
}

/*
 * VULNERABILITY 2 [MEDIUM]: Use-After-Free
 * Accessing content of a deleted note through last_deleted index
 * The freed memory may contain sensitive data or be reallocated
 */
void view_note(int idx) {
    if (idx < 0 || idx >= MAX_NOTES) {
        printf("Invalid index!\n");
        return;
    }
    
    // Special case: allow viewing "last deleted" note (UAF)
    if (idx == last_deleted && notes[idx].content != NULL) {
        // VULN: UAF - content was freed but pointer not nullified
        // This allows reading freed memory
        printf("Note %d (deleted): %s\n", idx, notes[idx].content);
        return;
    }
    
    if (!notes[idx].in_use) {
        printf("Note not in use!\n");
        return;
    }
    
    printf("Note %d: %s\n", idx, notes[idx].content);
}

/*
 * VULNERABILITY 3 [HARD]: Double Free
 * Subtle logic flaw: marked_for_delete flag allows freeing same memory twice
 * First delete marks it, second delete actually frees, third delete = double free
 */
void delete_note(int idx) {
    if (idx < 0 || idx >= MAX_NOTES) {
        printf("Invalid index!\n");
        return;
    }
    
    // VULN: Double free - complex logic allows freeing twice
    // If note is marked_for_delete but in_use is still set (race condition simulation)
    // the free can happen multiple times
    
    if (notes[idx].marked_for_delete) {
        // "Confirm" deletion - actually free
        if (notes[idx].content) {
            free(notes[idx].content);
            // BUG: Don't set content to NULL, allowing double free
            // notes[idx].content = NULL;  // This line is missing!
        }
        notes[idx].in_use = 0;
        notes[idx].marked_for_delete = 0;
        last_deleted = idx;
        printf("Note %d permanently deleted.\n", idx);
    } else if (notes[idx].in_use) {
        // First deletion - just mark
        notes[idx].marked_for_delete = 1;
        printf("Note %d marked for deletion. Delete again to confirm.\n", idx);
    } else {
        // Note not in use but might still have content pointer (UAF setup)
        if (notes[idx].content) {
            // VULN: This path allows double free if called after "permanent" delete
            free(notes[idx].content);
            printf("Cleaned up orphaned note %d.\n", idx);
        } else {
            printf("Note %d is empty.\n", idx);
        }
    }
}

void list_notes() {
    printf("\n=== Notes ===\n");
    for (int i = 0; i < MAX_NOTES; i++) {
        if (notes[i].in_use) {
            printf("[%d] Size: %zu, Marked: %s\n", 
                   i, notes[i].size, 
                   notes[i].marked_for_delete ? "YES" : "NO");
        }
    }
    printf("=============\n");
}

void print_menu() {
    printf("\n=== Note Manager ===\n");
    printf("1. Create note\n");
    printf("2. Edit note\n");
    printf("3. View note\n");
    printf("4. Delete note\n");
    printf("5. List notes\n");
    printf("6. Exit\n");
    printf("Choice: ");
}

int main() {
    int choice, idx;
    size_t size;
    
    init_notes();
    printf("Note Manager v1.0\n");
    printf("WARNING: This system contains intentional vulnerabilities for testing.\n\n");
    
    while (1) {
        print_menu();
        scanf("%d", &choice);
        
        switch (choice) {
            case 1:
                printf("Enter note size: ");
                scanf("%zu", &size);
                if (size > 0 && size <= 1024) {
                    idx = create_note(size);
                    if (idx >= 0) {
                        printf("Created note %d\n", idx);
                    }
                } else {
                    printf("Invalid size (1-1024).\n");
                }
                break;
                
            case 2:
                printf("Enter note index: ");
                scanf("%d", &idx);
                edit_note(idx);
                break;
                
            case 3:
                printf("Enter note index: ");
                scanf("%d", &idx);
                view_note(idx);
                break;
                
            case 4:
                printf("Enter note index: ");
                scanf("%d", &idx);
                delete_note(idx);
                break;
                
            case 5:
                list_notes();
                break;
                
            case 6:
                printf("Goodbye!\n");
                return 0;
                
            default:
                printf("Invalid choice.\n");
        }
    }
    
    return 0;
}
