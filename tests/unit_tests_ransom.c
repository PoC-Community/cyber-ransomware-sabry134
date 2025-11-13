#include <criterion/criterion.h>
#include <sodium.h>
#include <stdio.h>
#include <string.h>
#include "../sources/ransom.h"

#define TEST_PASSWORD "testpassword"
#define TEST_SALT_LEN 16
#define TEST_FILE "tests/testfile.txt"
#define ENCRYPTED_FILE "tests/testfile.txt.ransom"
#define DECRYPTED_FILE "tests/testfile.txt.decrypted"

unsigned char test_salt[TEST_SALT_LEN];

void create_test_file() {
    FILE *fp = fopen(TEST_FILE, "w");
    fputs("This is a test string.\nAnother line.\n", fp);
    fclose(fp);
}

void cleanup_test_files() {
    remove(TEST_FILE);
    remove(ENCRYPTED_FILE);
    remove(DECRYPTED_FILE);
}
