# Vulnerable Test Samples for IDA Pro Proxy MCP

This directory contains three intentionally vulnerable programs for security testing and vulnerability analysis demonstration.

⚠️ **WARNING**: These programs contain intentional security vulnerabilities. Do NOT use in production environments.

## Programs Overview

| Program | Theme | Vulnerabilities |
|---------|-------|-----------------|
| test1 | Authentication System | Stack overflow, Format string, Integer overflow |
| test2 | Note Manager | Heap overflow, UAF, Double free |
| test3 | File Server | Command injection, Path traversal, TOCTOU |

---

## test1 - Authentication System

### Vulnerabilities

#### 1. [EASY] Stack Buffer Overflow - `get_username()`
- **Type**: CWE-121 Stack-based Buffer Overflow
- **Location**: `get_username()` function
- **Cause**: Uses `gets()` with no bounds checking
- **Impact**: Overwrite return address, achieve code execution
- **Trigger**: Enter username longer than 64 bytes

#### 2. [MEDIUM] Format String - `log_attempt()`
- **Type**: CWE-134 Format String Vulnerability
- **Location**: `log_attempt()` function
- **Cause**: User input passed directly to `printf()`
- **Impact**: Read/write arbitrary memory using `%x`, `%n`
- **Trigger**: Login with username containing format specifiers

#### 3. [HARD] Integer Overflow - `check_access_level()`
- **Type**: CWE-190 Integer Overflow
- **Location**: `check_access_level()` function
- **Cause**: Arithmetic overflow in access calculation
- **Impact**: Bypass access control, gain admin privileges
- **Trigger**: Provide large bonus value to cause overflow

---

## test2 - Note Manager

### Vulnerabilities

#### 1. [EASY] Heap Buffer Overflow - `edit_note()`
- **Type**: CWE-122 Heap-based Buffer Overflow
- **Location**: `edit_note()` function
- **Cause**: `scanf("%s")` with no length limit
- **Impact**: Corrupt heap metadata, potential code execution
- **Trigger**: Edit note with content larger than allocated size

#### 2. [MEDIUM] Use-After-Free - `view_note()`
- **Type**: CWE-416 Use After Free
- **Location**: `view_note()` function
- **Cause**: Accessing freed memory through `last_deleted` index
- **Impact**: Information disclosure, potential code execution
- **Trigger**: View a deleted note using its index

#### 3. [HARD] Double Free - `delete_note()`
- **Type**: CWE-415 Double Free
- **Location**: `delete_note()` function
- **Cause**: Complex deletion logic doesn't null pointer after free
- **Impact**: Heap corruption, potential code execution
- **Trigger**: Delete same note multiple times through different code paths

---

## test3 - File Server

### Vulnerabilities

#### 1. [EASY] Command Injection - `backup_file()`
- **Type**: CWE-78 OS Command Injection
- **Location**: `backup_file()` function
- **Cause**: Unsanitized filename passed to `system()`
- **Impact**: Execute arbitrary shell commands
- **Trigger**: Backup file with name like `file.txt; cat /etc/passwd`

#### 2. [MEDIUM] Path Traversal - `read_file()`
- **Type**: CWE-22 Path Traversal
- **Location**: `read_file()` function
- **Cause**: No sanitization of `../` sequences
- **Impact**: Read arbitrary files outside sandbox
- **Trigger**: Read file `../../../etc/passwd`

#### 3. [HARD] TOCTOU Race Condition - `secure_delete()`
- **Type**: CWE-367 Time-of-check Time-of-use
- **Location**: `secure_delete()` function
- **Cause**: Gap between permission check and file deletion
- **Impact**: Delete files user shouldn't have access to
- **Trigger**: Race condition exploit during 100ms delay window

---

## Building

```bash
# Build all (with debug symbols, no stack protector for easier exploitation)
make all

# Or manually:
gcc -g -fno-stack-protector -z execstack -o test1 test1.c
gcc -g -fno-stack-protector -o test2 test2.c
gcc -g -fno-stack-protector -o test3 test3.c
```

## Usage with IDA Pro

These binaries are designed for:
1. Static analysis practice with IDA Pro
2. Vulnerability discovery training
3. Testing automated vulnerability detection tools
4. Demonstrating IDA Pro Proxy MCP capabilities

## Difficulty Levels

- **EASY**: Obvious vulnerability, direct user input to dangerous function
- **MEDIUM**: Requires understanding program state/flow
- **HARD**: Subtle logic flaws, requires deep analysis

## CWE References

- CWE-78: OS Command Injection
- CWE-121: Stack-based Buffer Overflow
- CWE-122: Heap-based Buffer Overflow
- CWE-134: Format String Vulnerability
- CWE-190: Integer Overflow
- CWE-22: Path Traversal
- CWE-367: TOCTOU Race Condition
- CWE-415: Double Free
- CWE-416: Use After Free
