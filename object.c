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
// Returns 0 on success, -1 on error.
int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out) {
    // ── Step 1: Determine the type string ────────────────────────────────────
    const char *type_str;
    if      (type == OBJ_BLOB)   type_str = "blob";
    else if (type == OBJ_TREE)   type_str = "tree";
    else if (type == OBJ_COMMIT) type_str = "commit";
    else return -1;  // unknown type

    // ── Step 2: Build the header e.g. "blob 13" ──────────────────────────────
    // Note: header_len does NOT count the '\0' — we add that manually below
    char header[64];
    int header_len = snprintf(header, sizeof(header), "%s %zu", type_str, len);
    if (header_len < 0) return -1;

    // ── Step 3: Combine header + '\0' + data into one contiguous buffer ──────
    // Layout: [header bytes][0x00][data bytes]
    size_t full_size = (size_t)header_len + 1 + len;
    uint8_t *full = malloc(full_size);
    if (!full) return -1;

    memcpy(full, header, (size_t)header_len);   // copy header (no null yet)
    full[header_len] = '\0';                     // the separating null byte
    memcpy(full + header_len + 1, data, len);    // copy raw data

    // ── Step 4: SHA-256 hash the FULL object (header + null + data) ──────────
    // compute_hash fills id_out->hash[32] for us
    compute_hash(full, full_size, id_out);

    // ── Step 5: Deduplication — if the object already exists, nothing to do ──
    if (object_exists(id_out)) {
        free(full);
        return 0;
    }

    // ── Step 6: Build the shard directory path and file path ─────────────────
    // object_path gives us: .pes/objects/XX/YYYYYY...
    // We need the directory part:  .pes/objects/XX
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id_out, hex);                    // full 64-char hex string

    char dir_path[512];
    snprintf(dir_path, sizeof(dir_path), "%s/%.2s", OBJECTS_DIR, hex);

    char file_path[512];
    object_path(id_out, file_path, sizeof(file_path));

    // ── Step 7: Create shard directory (ignore error if it already exists) ───
    mkdir(dir_path, 0755);

    // ── Step 8: Write to a temp file, then atomically rename ─────────────────
    // Temp file sits in the same shard directory to guarantee rename is atomic
    // (rename across filesystems is not atomic)
    char tmp_path[512];
    snprintf(tmp_path, sizeof(tmp_path), "%s/tmp_XXXXXX", dir_path);

    // Use mkstemp so the temp name is unique even under concurrent writers
    int fd = mkstemp(tmp_path);
    if (fd < 0) {
        free(full);
        return -1;
    }

    // Write the full object content
    ssize_t written = write(fd, full, full_size);
    if (written < 0 || (size_t)written != full_size) {
        close(fd);
        unlink(tmp_path);
        free(full);
        return -1;
    }

    // ── Step 9: fsync the file so data survives a crash before rename ─────────
    if (fsync(fd) != 0) {
        close(fd);
        unlink(tmp_path);
        free(full);
        return -1;
    }
    close(fd);
    free(full);

    // ── Step 10: Atomically rename temp → final path ──────────────────────────
    if (rename(tmp_path, file_path) != 0) {
        unlink(tmp_path);
        return -1;
    }

    // ── Step 11: fsync the shard directory to persist the rename on disk ──────
    int dir_fd = open(dir_path, O_RDONLY);
    if (dir_fd >= 0) {
        fsync(dir_fd);   // best-effort; ignore error
        close(dir_fd);
    }

    return 0;
}

// Read an object from the store.
//
// Returns 0 on success, -1 on error (file not found, corrupt, etc.).
// The caller is responsible for calling free(*data_out).
int object_read(const ObjectID *id, ObjectType *type_out, void **data_out, size_t *len_out) {
    // ── Step 1: Resolve the file path from the ObjectID ───────────────────────
    char file_path[512];
    object_path(id, file_path, sizeof(file_path));

    // ── Step 2: Open and read the entire file into memory ────────────────────
    FILE *f = fopen(file_path, "rb");
    if (!f) return -1;

    fseek(f, 0, SEEK_END);
    long file_size_signed = ftell(f);
    rewind(f);

    if (file_size_signed <= 0) {
        fclose(f);
        return -1;
    }
    size_t full_size = (size_t)file_size_signed;

    uint8_t *full = malloc(full_size);
    if (!full) {
        fclose(f);
        return -1;
    }

    if (fread(full, 1, full_size, f) != full_size) {
        fclose(f);
        free(full);
        return -1;
    }
    fclose(f);

    // ── Step 3: Integrity check ───────────────────────────────────────────────
    // Recompute the SHA-256 of what we read and compare byte-by-byte to the
    // hash in *id.  If they differ, the file is corrupted.
    ObjectID computed;
    compute_hash(full, full_size, &computed);
    if (memcmp(computed.hash, id->hash, HASH_SIZE) != 0) {
        free(full);
        return -1;  // hash mismatch — object is corrupted
    }

    // ── Step 4: Find the '\0' that separates the header from the data ─────────
    uint8_t *null_pos = memchr(full, '\0', full_size);
    if (!null_pos) {
        free(full);
        return -1;  // malformed object — no null separator
    }

    // ── Step 5: Parse the type string from the header ─────────────────────────
    // Header format: "blob 16"  or "tree 43"  or "commit 120"
    if      (strncmp((char *)full, "blob",   4) == 0) *type_out = OBJ_BLOB;
    else if (strncmp((char *)full, "tree",   4) == 0) *type_out = OBJ_TREE;
    else if (strncmp((char *)full, "commit", 6) == 0) *type_out = OBJ_COMMIT;
    else {
        free(full);
        return -1;  // unknown type string
    }

    // ── Step 6: Parse the data length from the header ─────────────────────────
    // The space-separated number after the type string
    char *space = strchr((char *)full, ' ');
    if (!space) {
        free(full);
        return -1;
    }
    *len_out = (size_t)atol(space + 1);

    // ── Step 7: Copy the data portion (everything after the '\0') ─────────────
    size_t data_offset = (size_t)(null_pos - full) + 1;  // byte index right after '\0'

    // Sanity check: does the claimed size match what's actually there?
    if (data_offset + *len_out > full_size) {
        free(full);
        return -1;  // size field is wrong / file is truncated
    }

    *data_out = malloc(*len_out);
    if (!*data_out) {
        free(full);
        return -1;
    }
    memcpy(*data_out, full + data_offset, *len_out);

    free(full);
    return 0;
}
