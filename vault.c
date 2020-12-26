#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "vault.h"

size_t
enc_vault_size(const char *path)
{
  struct stat buf;
  if (stat(path, &buf)) {
    return 0;
  }
  return buf.st_size;
}

size_t
vault_size(const char *path)
{
  // The length of the vault is the file size without the metadata. Using AES
  // with GCM mean the ciphertext has the same length as the plaintext.
  return enc_vault_size(path) - sizeof(struct enc_metadata);
}

int
load_vault(struct vault *dst, const char *path, const char *master_passwd)
{
  size_t s = enc_vault_size(path);
  if (s == 0) {
    return errno;
  }

  struct enc_vault *ev = (struct enc_vault*) malloc(s);
  if (ev == NULL) {
    return errno;
  }

  int err = 0;
  FILE *f = fopen(path, "rb");
  if (f == NULL) {
    err = errno;
    goto free_mem;
  }

  size_t n = fread(ev, 1, s, f);
  if (n < s) {
    err = errno;
    goto close_and_free;
  }

  // for now, the vault is not encrypted, just copy directly into dst.
  memcpy(dst, ev->ciphertext, n-sizeof(struct enc_metadata));

close_and_free:
  fclose(f);
free_mem:
  free(ev);
  return err;
}

int
write_vault(struct vault *dst, const char *path, const char *master_passwd)
{
  // length of the resulting cipher text is the total size of the unencrypted
  // vault, which must be calculated due to the flexible length array holding
  // the passwords.
  size_t cipher_length = SALT_LENGTH + sizeof(uint32_t) + dst->n * sizeof(struct entry);

  // length of the encrypted vault, which is the cipher text plus the metadata.
  size_t enc_length = sizeof(struct enc_metadata) + cipher_length;
  struct enc_vault *ev = (struct enc_vault*) malloc(enc_length);
  if (ev == NULL) {
    return errno;
  }
  memcpy(ev->ciphertext, dst, cipher_length);

  int err = 0;
  FILE *f = fopen(path, "wb");
  if (f == NULL) {
    err = errno;
    goto free_mem;
  }

  size_t n = fwrite(ev, 1, enc_length, f);
  if (n < enc_length) {
    err = errno;
    goto close_and_free;
  }

close_and_free:
  fclose(f);
free_mem:
  free(ev);
  return err;
}
