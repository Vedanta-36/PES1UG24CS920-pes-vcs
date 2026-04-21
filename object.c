// object.c — Content-addressable object store
//
// Every piece of data (file contents, directory listings, commits) is stored
// as an "object" named by its SHA-256 hash. Objects are stored under
// .pes/objects/XX/YYYYYY... where XX is the first two hex characters of the
// hash (directory sharding).
//
// PROVIDED functions: compute_hash, object_path, object_exists, hash_to_hex, hex_to_hash
// TODO functions:     object_write, object_read

#include "pes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/evp.h>

// ─── PROVIDED ────────────────────────────────────────────────────────────────

void hash_to_hex(const ObjectID *id, char *hex_out) {
    for (int i = 0; i < HASH_SIZE; i++) {
        sprintf(hex_out + i * 2, "%02x", id->hash[i]);
    }
    hex_out[HASH_HEX_SIZE] = '\0';
}

int hex_to_hash(const char *hex, ObjectID *id_out) {
    if (strlen(hex) < HASH_HEX_SIZE) return -1;
    for (int i = 0; i < HASH_SIZE; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return -1;
        id_out->hash[i] = (uint8_t)byte;
    }
    return 0;
}

void compute_hash(const void *data, size_t len, ObjectID *id_out) {
    unsigned int hash_len;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, id_out->hash, &hash_len);
    EVP_MD_CTX_free(ctx);
}

// Get the filesystem path where an object should be stored.
// Format: .pes/objects/XX/YYYYYYYY...
// The first 2 hex chars form the shard directory; the rest is the filename.
void object_path(const ObjectID *id, char *path_out, size_t path_size) {
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id, hex);
    snprintf(path_out, path_size, "%s/%.2s/%s", OBJECTS_DIR, hex, hex + 2);
}

int object_exists(const ObjectID *id) {
    char path[512];
    object_path(id, path, sizeof(path));
    return access(path, F_OK) == 0;
}

// ─── TODO: Implement these ──────────────────────────────────────────────────

// Write an object to the store.
//
// Object format on disk:
//   "<type> <size>\0<data>"
//   where <type> is "blob", "tree", or "commit"
//   and <size> is the decimal string of the data length
//
// Steps:
//   1. Build the full object: header ("blob 16\0") + data
//   2. Compute SHA-256 hash of the FULL object (header + data)
//   3. Check if object already exists (deduplication) — if so, just return success
//   4. Create shard directory (.pes/objects/XX/) if it doesn't exist
//   5. Write to a temporary file in the same shard directory
//   6. fsync() the temporary file to ensure data reaches disk
//   7. rename() the temp file to the final path (atomic on POSIX)
//   8. Open and fsync() the shard directory to persist the rename
//   9. Store the computed hash in *id_out

// HINTS - Useful syscalls and functions for this phase:
//   - sprintf / snprintf : formatting the header string
//   - compute_hash       : hashing the combined header + data
//   - object_exists      : checking for deduplication
//   - mkdir              : creating the shard directory (use mode 0755)
//   - open, write, close : creating and writing to the temp file
//                          (Use O_CREAT | O_WRONLY | O_TRUNC, mode 0644)
//   - fsync              : flushing the file descriptor to disk
//   - rename             : atomically moving the temp file to the final path
//

//
// Returns 0 on success, -1 on error.
// The format stored on disk is:
// "blob 16\0<raw bytes>"   for blobs
// "tree 16\0<raw bytes>"   for trees
// "commit 43\0<raw bytes>" for commits

int object_write(const void *data, size_t len, ObjectType type, ObjectID *id_out) {
    // 1. Build header string: e.g. "blob 16"
    const char *type_str;
    if      (type == OBJ_BLOB)   type_str = "blob";
    else if (type == OBJ_TREE)   type_str = "tree";
    else                          type_str = "commit";

    char header[64];
    int header_len = snprintf(header, sizeof(header), "%s %zu", type_str, len);

    // 2. Build full object: header + '\0' + data
    size_t full_size = header_len + 1 + len;
    uint8_t *full = malloc(full_size);
    if (!full) return -1;
    memcpy(full, header, header_len);
    full[header_len] = '\0';
    memcpy(full + header_len + 1, data, len);

    // 3. Compute SHA-256 of full object using the PROVIDED compute_hash
    compute_hash(full, full_size, id_out);

    // 4. Check if object already exists (deduplication)
    if (object_exists(id_out)) {
        free(full);
        return 0;
    }

    // 5. Build directory and file paths using the PROVIDED object_path
    char file_path[512];
    object_path(id_out, file_path, sizeof(file_path));

    // Build just the shard directory path (first 2 hex chars)
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id_out, hex);
    char dir_path[512];
    snprintf(dir_path, sizeof(dir_path), "%s/%.2s", OBJECTS_DIR, hex);

    // 6. Create shard directory if needed
    mkdir(dir_path, 0755);

    // 7. Write to temp file first, then atomically rename
    char tmp_path[512];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", file_path);

    int fd = open(tmp_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) { free(full); return -1; }

    if (write(fd, full, full_size) != (ssize_t)full_size) {
        close(fd); free(full); return -1;
    }

    // 8. fsync the file to ensure data reaches disk
    fsync(fd);
    close(fd);
    free(full);

    // 9. Atomically rename temp → final path
    if (rename(tmp_path, file_path) != 0) return -1;

    // 10. fsync the shard directory to persist the rename
    int dir_fd = open(dir_path, O_RDONLY);
    if (dir_fd >= 0) {
        fsync(dir_fd);
        close(dir_fd);
    }

    return 0;
}

// Read an object from the store.
//
// Steps:
//   1. Build the file path from the hash using object_path()
//   2. Open and read the entire file
//   3. Parse the header to extract the type string and size
//   4. Verify integrity: recompute the SHA-256 of the file contents
//      and compare to the expected hash (from *id). Return -1 if mismatch.
//   5. Set *type_out to the parsed ObjectType
//   6. Allocate a buffer, copy the data portion (after the \0), set *data_out and *len_out
//
// HINTS - Useful syscalls and functions for this phase:
//   - object_path        : getting the target file path
//   - fopen, fread, fseek: reading the file into memory
//   - memchr             : safely finding the '\0' separating header and data
//   - strncmp            : parsing the type string ("blob", "tree", "commit")
//   - compute_hash       : re-hashing the read data for integrity verification
//   - memcmp             : comparing the computed hash against the requested hash
//   - malloc, memcpy     : allocating and returning the extracted data
//
// The caller is responsible for calling free(*data_out).
// Returns 0 on success, -1 on error (file not found, corrupt, etc.).

int object_read(const ObjectID *id, ObjectType *type_out,
                void **data_out, size_t *len_out) {
    // 1. Get file path using the PROVIDED object_path
    char file_path[512];
    object_path(id, file_path, sizeof(file_path));

    // 2. Open and read entire file into memory
    FILE *f = fopen(file_path, "rb");
    if (!f) return -1;

    fseek(f, 0, SEEK_END);
    size_t full_size = ftell(f);
    rewind(f);

    uint8_t *full = malloc(full_size);
    if (!full) { fclose(f); return -1; }
    fread(full, 1, full_size, f);
    fclose(f);

    // 3. Integrity check: recompute hash and compare to expected
    ObjectID computed;
    compute_hash(full, full_size, &computed);
    if (memcmp(computed.hash, id->hash, HASH_SIZE) != 0) {
        free(full);
        return -1;  // corrupted object
    }

    // 4. Find the '\0' separator between header and data
    uint8_t *null_pos = memchr(full, '\0', full_size);
    if (!null_pos) { free(full); return -1; }

    // 5. Parse type from header
    if      (strncmp((char*)full, "blob",   4) == 0) *type_out = OBJ_BLOB;
    else if (strncmp((char*)full, "tree",   4) == 0) *type_out = OBJ_TREE;
    else if (strncmp((char*)full, "commit", 6) == 0) *type_out = OBJ_COMMIT;
    else { free(full); return -1; }

    // 6. Parse size from header (the number after the space)
    char *space = strchr((char*)full, ' ');
    if (!space) { free(full); return -1; }
    *len_out = (size_t)atol(space + 1);

    // 7. Copy data portion (everything after the '\0') into output buffer
    *data_out = malloc(*len_out);
    if (!*data_out) { free(full); return -1; }
    memcpy(*data_out, null_pos + 1, *len_out);

    free(full);
    return 0;
}
