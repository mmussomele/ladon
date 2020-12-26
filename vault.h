#ifndef VAULT_H
#define VAULT_H

#include <stddef.h>
#include <stdint.h>

#define KEY_LENGTH 32 // 256 bit key
#define SALT_LENGTH 32 // 256 bit salt
#define IV_LENGTH 12 // 96 bit IV for AES-256-GCM
#define PBKDF2_ITERS 100000

// Passwords and their entry name are stored in fixed length buffers to allow
// for easy serialization. While limited, 256 characters should be plenty for
// most practical purposes.
#define MAX_ENTRY_FIELD_LENGTH 256

struct entry {
  char name[MAX_ENTRY_FIELD_LENGTH];
  char password[MAX_ENTRY_FIELD_LENGTH];
};

struct vault {
  char salt[SALT_LENGTH];
  uint32_t n;             // number of entries in password array
  struct entry entries[]; // password entries
};

struct enc_metadata {
  char iv[IV_LENGTH];
  size_t cipher_length;
};

struct enc_vault {
  struct enc_metadata meta;
  char ciphertext[];
};

// load_vault reads the vault data from path, decrypts it using master_passwd,
// and populates dst with the resulting data. It returns 0 on success and errno
// on failure.
int load_vault(struct vault *dst, const char *path, const char *master_passwd);

// write_vault encrypts dst using master_passwd, then writes the resulting
// cipher text to path. It returns 0 on success and errno on failure.
int write_vault(struct vault *dst, const char *path, const char *master_passwd);

// vault_size returns the number of bytes needed to hold the vault stored at
// path after decryption. If an error occurs, 0 is returned and errno can be
// checked for a more detailed reason.
size_t vault_size(const char *path);

#endif /* VAULT_H */
