# Makefile for vulnerable test samples
# Disables security features for easier exploitation testing

CC = gcc
# -g: debug symbols
# -fno-stack-protector: disable stack canaries
# -no-pie: disable ASLR for executable
# -z execstack: make stack executable (for shellcode testing)
CFLAGS = -g -Wall -fno-stack-protector -no-pie
LDFLAGS = -z execstack

TARGETS = test1 test2 test3

.PHONY: all clean info secure

# Default: build with vulnerabilities exploitable
all: $(TARGETS)

test1: test1.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

test2: test2.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

test3: test3.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

# Build with security features enabled (for comparison)
secure:
	$(CC) -g -Wall -fstack-protector-strong -pie -o test1_secure test1.c
	$(CC) -g -Wall -fstack-protector-strong -pie -o test2_secure test2.c
	$(CC) -g -Wall -fstack-protector-strong -pie -o test3_secure test3.c

clean:
	rm -f $(TARGETS) test1_secure test2_secure test3_secure
	rm -rf /tmp/fileserver

info:
	@echo "Vulnerable Test Samples"
	@echo "======================="
	@echo ""
	@echo "test1 - Authentication System"
	@echo "  [EASY]   Stack overflow in get_username()"
	@echo "  [MEDIUM] Format string in log_attempt()"
	@echo "  [HARD]   Integer overflow in check_access_level()"
	@echo ""
	@echo "test2 - Note Manager"
	@echo "  [EASY]   Heap overflow in edit_note()"
	@echo "  [MEDIUM] Use-After-Free in view_note()"
	@echo "  [HARD]   Double free in delete_note()"
	@echo ""
	@echo "test3 - File Server"
	@echo "  [EASY]   Command injection in backup_file()"
	@echo "  [MEDIUM] Path traversal in read_file()"
	@echo "  [HARD]   TOCTOU race in secure_delete()"
	@echo ""
	@file $(TARGETS) 2>/dev/null || echo "Run 'make all' to build."
