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

char *object_write(const uint8_t *data, size_t size, ObjectType type, char out_hex[65]) {
    // 1. Build the header string: e.g. "blob 16"
    const char *type_str;
    if (type == OBJ_BLOB)        type_str = "blob";
    else if (type == OBJ_TREE)   type_str = "tree";
    else                          type_str = "commit";

    char header[64];
    int header_len = snprintf(header, sizeof(header), "%s %zu", type_str, size);
    // header_len does NOT include the null terminator, but we need it in the object

    // 2. Build full object: header + '\0' + data
    size_t full_size = header_len + 1 + size;
    uint8_t *full = malloc(full_size);
    memcpy(full, header, header_len);
    full[header_len] = '\0';
    memcpy(full + header_len + 1, data, size);

    // 3. SHA-256 hash the full object
    uint8_t hash[32];
    sha256(full, full_size, hash);  // use whatever SHA256 function pes.h provides
    // convert hash bytes to hex string → out_hex (64 chars + null)
    for (int i = 0; i < 32; i++)
        sprintf(out_hex + i*2, "%02x", hash[i]);
    out_hex[64] = '\0';

    // 4. Build the path: .pes/objects/XX/YYY...
    // First 2 hex chars = subdirectory, remaining 62 = filename
    char dir_path[PATH_MAX], file_path[PATH_MAX];
    snprintf(dir_path, sizeof(dir_path), ".pes/objects/%.2s", out_hex);
    snprintf(file_path, sizeof(file_path), ".pes/objects/%.2s/%s", out_hex, out_hex + 2);

    // 5. If file already exists, skip writing (deduplication)
    if (access(file_path, F_OK) == 0) {
        free(full);
        return strdup(out_hex);
    }

    // 6. Create directory if needed
    mkdir(dir_path, 0755);  // ignore error if exists

    // 7. Write to a TEMP file first, then rename (atomic write)
    char tmp_path[PATH_MAX];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", file_path);
    FILE *f = fopen(tmp_path, "wb");
    fwrite(full, 1, full_size, f);
    fflush(f);
    fsync(fileno(f));
    fclose(f);
    rename(tmp_path, file_path);

    free(full);
    return strdup(out_hex);
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

uint8_t *object_read(const char *hex, ObjectType *out_type, size_t *out_size) {
    // 1. Build path from hex
    char file_path[PATH_MAX];
    snprintf(file_path, sizeof(file_path), ".pes/objects/%.2s/%s", hex, hex + 2);

    // 2. Read entire file into memory
    FILE *f = fopen(file_path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    size_t full_size = ftell(f);
    rewind(f);
    uint8_t *full = malloc(full_size);
    fread(full, 1, full_size, f);
    fclose(f);

    // 3. INTEGRITY CHECK: recompute SHA-256, compare to filename
    uint8_t hash[32]; char computed_hex[65];
    sha256(full, full_size, hash);
    for (int i = 0; i < 32; i++) sprintf(computed_hex + i*2, "%02x", hash[i]);
    computed_hex[64] = '\0';
    if (strcmp(computed_hex, hex) != 0) { free(full); return NULL; } // corrupted!

    // 4. Parse header: find the '\0' separator
    uint8_t *null_pos = memchr(full, '\0', full_size);
    if (!null_pos) { free(full); return NULL; }

    // 5. Parse type from header ("blob", "tree", "commit")
    if (strncmp((char*)full, "blob", 4) == 0)        *out_type = OBJ_BLOB;
    else if (strncmp((char*)full, "tree", 4) == 0)   *out_type = OBJ_TREE;
    else                                               *out_type = OBJ_COMMIT;

    // 6. Extract size from header
    *out_size = atoi(strchr((char*)full, ' ') + 1);

    // 7. Return a copy of just the data portion (after the '\0')
    uint8_t *data = malloc(*out_size);
    memcpy(data, null_pos + 1, *out_size);
    free(full);
    return data;
}
}
