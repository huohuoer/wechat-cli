/*
 * find_all_keys_macos.c - macOS WeChat memory key scanner
 *
 * Scans WeChat process memory for SQLCipher encryption keys in the
 * x'<key_hex><salt_hex>' format used by WeChat 4.x on macOS.
 *
 * Prerequisites:
 *   - WeChat must be ad-hoc signed (or SIP disabled)
 *   - Must run as root (sudo)
 *
 * Build:
 *   cc -O2 -o find_all_keys_macos find_all_keys_macos.c -framework Foundation
 *
 * Usage:
 *   sudo ./find_all_keys_macos [pid]
 *   If pid is omitted, automatically finds WeChat PID.
 *
 * Output: JSON file at ./all_keys.json (compatible with decrypt_db.py)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <ftw.h>
#include <pwd.h>
#include <sys/stat.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>

#define MAX_KEYS 256
#define KEY_SIZE 32
#define SALT_SIZE 16
#define HEX_PATTERN_LEN 96  /* 64 hex (key) + 32 hex (salt) */
#define CHUNK_SIZE (2 * 1024 * 1024)
#define MAX_NAME_ADDRESSES 256
#define MAX_CONFIG_POINTERS 512
#define CONFIG_BLOB_MAX 1024

static const unsigned char CONFIG_CIPHER_NAME[] =
    "com.Tencent.WCDB.Config.Cipher";
#define CONFIG_CIPHER_NAME_LEN (sizeof(CONFIG_CIPHER_NAME) - 1)

/* The Config.Cipher value is stored as a short XOR-obfuscated blob in
 * WeChat 4.1.x.  This is the same compiler-generated mask used by the
 * Windows implementation; the runtime layout is shared by WCDB. */
static const unsigned char CONFIG_XOR_MASK[] = {
    0xd2, 0xc7, 0x44, 0x24, 0x58, 0x02, 0x00, 0x00,
    0x00, 0x48, 0x89, 0x44, 0x24, 0x50, 0x48, 0x8b,
    0x45, 0x00, 0x48, 0x84, 0x4c, 0x24, 0x48, 0x48,
    0x89, 0x44, 0x25, 0x40, 0x48, 0x58, 0x4c, 0x24,
};
#define CONFIG_XOR_MASK_LEN sizeof(CONFIG_XOR_MASK)

/* nftw callback state for collecting DB files */
#define MAX_DBS 256
static char g_db_salts[MAX_DBS][33];
static char g_db_names[MAX_DBS][256];
static int g_db_count = 0;

typedef struct {
    char key_hex[65];
    char salt_hex[33];
    char full_pragma[100];
} key_entry_t;

static uint64_t read_u64_le(const unsigned char *p) {
    uint64_t value = 0;
    for (int i = 7; i >= 0; i--)
        value = (value << 8) | p[i];
    return value;
}

static int is_probable_key(const char *key_hex) {
    unsigned char seen[256] = {0};
    int distinct = 0;
    for (int i = 0; i < 64; i++) {
        unsigned char c = (unsigned char)key_hex[i];
        if (!seen[c]) {
            seen[c] = 1;
            distinct++;
        }
    }
    return distinct >= 15;
}

static void lowercase_hex(char *value) {
    for (; *value; value++) {
        if (*value >= 'A' && *value <= 'F')
            *value = (char)(*value + ('a' - 'A'));
    }
}

static int known_salt(const char *salt_hex) {
    for (int i = 0; i < g_db_count; i++) {
        if (strcmp(g_db_salts[i], salt_hex) == 0)
            return 1;
    }
    return 0;
}

static void add_key(key_entry_t *keys, int *key_count,
                    const char *key_hex, const char *salt_hex) {
    if (*key_count >= MAX_KEYS || !is_probable_key(key_hex) ||
        !known_salt(salt_hex))
        return;

    for (int i = 0; i < *key_count; i++) {
        if (strcmp(keys[i].key_hex, key_hex) == 0 &&
            strcmp(keys[i].salt_hex, salt_hex) == 0)
            return;
    }

    strcpy(keys[*key_count].key_hex, key_hex);
    strcpy(keys[*key_count].salt_hex, salt_hex);
    snprintf(keys[*key_count].full_pragma,
             sizeof(keys[*key_count].full_pragma),
             "x'%s%s'", key_hex, salt_hex);
    (*key_count)++;
}

static int append_address(uint64_t *addresses, int *address_count,
                          uint64_t address) {
    for (int i = 0; i < *address_count; i++) {
        if (addresses[i] == address)
            return 0;
    }
    if (*address_count >= MAX_NAME_ADDRESSES)
        return 0;
    addresses[(*address_count)++] = address;
    return 1;
}

static int append_pointer(uint64_t *pointers, int *pointer_count,
                          uint64_t pointer) {
    for (int i = 0; i < *pointer_count; i++) {
        if (pointers[i] == pointer)
            return 0;
    }
    if (*pointer_count >= MAX_CONFIG_POINTERS)
        return 0;
    pointers[(*pointer_count)++] = pointer;
    return 1;
}

/* Forward declaration */
static int read_db_salt(const char *path, char *salt_hex_out);

static int nftw_collect_db(const char *fpath, const struct stat *sb,
                           int typeflag, struct FTW *ftwbuf) {
    (void)sb; (void)ftwbuf;
    if (typeflag != FTW_F) return 0;
    size_t len = strlen(fpath);
    if (len < 3 || strcmp(fpath + len - 3, ".db") != 0) return 0;
    if (g_db_count >= MAX_DBS) return 0;

    char salt[33];
    if (read_db_salt(fpath, salt) != 0) return 0;

    strcpy(g_db_salts[g_db_count], salt);
    /* Extract relative path from db_storage/ */
    const char *rel = strstr(fpath, "db_storage/");
    if (rel) rel += strlen("db_storage/");
    else {
        rel = strrchr(fpath, '/');
        rel = rel ? rel + 1 : fpath;
    }
    strncpy(g_db_names[g_db_count], rel, 255);
    g_db_names[g_db_count][255] = '\0';
    printf("  %s: salt=%s\n", g_db_names[g_db_count], salt);
    g_db_count++;
    return 0;
}

static int is_hex_char(unsigned char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

static pid_t find_wechat_pid(void) {
    FILE *fp = popen("pgrep -x WeChat", "r");
    if (!fp) return -1;
    char buf[64];
    pid_t pid = -1;
    if (fgets(buf, sizeof(buf), fp))
        pid = atoi(buf);
    pclose(fp);
    return pid;
}

/* Read DB salt (first 16 bytes) and return hex string */
static int read_db_salt(const char *path, char *salt_hex_out) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    unsigned char header[16];
    if (fread(header, 1, 16, f) != 16) { fclose(f); return -1; }
    fclose(f);
    /* Check if unencrypted */
    if (memcmp(header, "SQLite format 3", 15) == 0) return -1;
    for (int i = 0; i < 16; i++)
        sprintf(salt_hex_out + i * 2, "%02x", header[i]);
    salt_hex_out[32] = '\0';
    return 0;
}

/* Read directly into a caller-owned buffer.  This avoids retaining a Mach
 * VM allocation while inspecting a small object or Config.Cipher blob. */
static size_t read_task_memory(mach_port_t task, mach_vm_address_t address,
                               mach_vm_size_t size, unsigned char *buffer) {
    mach_vm_size_t copied = size;
    kern_return_t kr = mach_vm_read_overwrite(
        task, address, size, (mach_vm_address_t)buffer, &copied);
    return kr == KERN_SUCCESS ? (size_t)copied : 0;
}

static void scan_region_for_bytes(mach_port_t task, mach_vm_address_t address,
                                  mach_vm_size_t size,
                                  const unsigned char *needle, size_t needle_len,
                                  uint64_t *addresses, int *address_count) {
    if (!size || !needle_len || needle_len > 256)
        return;

    unsigned char *window = malloc(CHUNK_SIZE + needle_len);
    if (!window)
        return;

    unsigned char tail[255];
    size_t tail_len = 0;
    mach_vm_size_t offset = 0;
    while (offset < size) {
        mach_vm_size_t chunk_size = size - offset;
        if (chunk_size > CHUNK_SIZE)
            chunk_size = CHUNK_SIZE;

        vm_offset_t data = 0;
        mach_msg_type_number_t data_count = 0;
        kern_return_t kr = mach_vm_read(task, address + offset,
                                        chunk_size, &data, &data_count);
        if (kr != KERN_SUCCESS || data_count == 0) {
            tail_len = 0;
            offset += chunk_size;
            continue;
        }

        size_t data_len = (size_t)data_count;
        memcpy(window, tail, tail_len);
        memcpy(window + tail_len, (const void *)data, data_len);
        size_t window_len = tail_len + data_len;
        mach_vm_address_t window_address = address + offset - tail_len;

        for (size_t i = 0; i + needle_len <= window_len; i++) {
            if (memcmp(window + i, needle, needle_len) == 0)
                append_address(addresses, address_count, window_address + i);
        }

        tail_len = needle_len - 1;
        if (tail_len > window_len)
            tail_len = window_len;
        memcpy(tail, window + window_len - tail_len, tail_len);
        mach_vm_deallocate(mach_task_self(), data, data_count);
        offset += chunk_size;
    }

    free(window);
}

static int find_name_address(const uint64_t *addresses, int address_count,
                             uint64_t value) {
    for (int i = 0; i < address_count; i++) {
        if (addresses[i] == value)
            return 1;
    }
    return 0;
}

static void decode_config_blob(const unsigned char *blob, size_t blob_len,
                               key_entry_t *keys, int *key_count,
                               int *candidate_count) {
    if (!blob || blob_len == 0 || blob_len > CONFIG_BLOB_MAX)
        return;

    unsigned char decoded[CONFIG_BLOB_MAX];
    for (size_t i = 0; i < blob_len; i++)
        decoded[i] = blob[i] ^ CONFIG_XOR_MASK[i % CONFIG_XOR_MASK_LEN];

    for (size_t i = 0; i + 2 < blob_len; i++) {
        if (decoded[i] != 'x' || decoded[i + 1] != '\'')
            continue;

        size_t run_len = 0;
        while (i + 2 + run_len < blob_len &&
               is_hex_char(decoded[i + 2 + run_len]) && run_len <= 192)
            run_len++;
        if (run_len < 64 || run_len > 192 ||
            i + 2 + run_len >= blob_len ||
            decoded[i + 2 + run_len] != '\'')
            continue;

        size_t last_start = run_len - 64;
        for (size_t start = 0; start <= last_start; start += 32) {
            char key_hex[65];
            memcpy(key_hex, decoded + i + 2 + start, 64);
            key_hex[64] = '\0';
            lowercase_hex(key_hex);
            if (!is_probable_key(key_hex))
                continue;

            (*candidate_count)++;
            if (start + 96 > run_len)
                continue;

            char salt_hex[33];
            memcpy(salt_hex, decoded + i + 2 + start + 64, 32);
            salt_hex[32] = '\0';
            lowercase_hex(salt_hex);
            add_key(keys, key_count, key_hex, salt_hex);
        }

        /* Include a non-32-byte-aligned trailing window as the Windows
         * implementation does. */
        if (last_start % 32 != 0) {
            char key_hex[65];
            memcpy(key_hex, decoded + i + 2 + last_start, 64);
            key_hex[64] = '\0';
            lowercase_hex(key_hex);
            if (is_probable_key(key_hex)) {
                (*candidate_count)++;
                if (last_start + 96 <= run_len) {
                    char salt_hex[33];
                    memcpy(salt_hex, decoded + i + 2 + last_start + 64, 32);
                    salt_hex[32] = '\0';
                    lowercase_hex(salt_hex);
                    add_key(keys, key_count, key_hex, salt_hex);
                }
            }
        }
    }
}

static void process_config_reference(
    mach_port_t task, uint64_t pair_address, uint64_t name_address,
    key_entry_t *keys, int *key_count, uint64_t *seen_config_pointers,
    int *seen_config_pointer_count, int *candidate_count) {
    if (pair_address < 0x10)
        return;

    unsigned char node[0x50];
    if (read_task_memory(task, pair_address - 0x10, sizeof(node), node) < 0x40)
        return;

    if (read_u64_le(node + 0x10) != name_address ||
        read_u64_le(node + 0x18) != CONFIG_CIPHER_NAME_LEN)
        return;

    uint64_t config_pointer = read_u64_le(node + 0x28);
    if (config_pointer < 0x10000 || config_pointer >= 0x0000800000000000ULL)
        return;
    if (!append_pointer(seen_config_pointers, seen_config_pointer_count,
                        config_pointer))
        return;

    /* WCDB's Config object contains the std::string/blob at +0x88. */
    unsigned char config_value[0x28];
    if (read_task_memory(task, config_pointer + 0x88,
                         sizeof(config_value), config_value) < 0x18)
        return;

    uint64_t data_pointer = read_u64_le(config_value + 0x08);
    uint64_t data_length = read_u64_le(config_value + 0x10);
    if (data_pointer < 0x10000 || data_pointer >= 0x0000800000000000ULL ||
        data_length == 0 || data_length > CONFIG_BLOB_MAX)
        return;

    unsigned char blob[CONFIG_BLOB_MAX];
    if (read_task_memory(task, data_pointer, data_length, blob) != data_length)
        return;
    decode_config_blob(blob, (size_t)data_length, keys, key_count,
                       candidate_count);
}

static void scan_region_for_config_references(
    mach_port_t task, mach_vm_address_t address, mach_vm_size_t size,
    const uint64_t *name_addresses, int name_address_count,
    key_entry_t *keys, int *key_count, uint64_t *seen_config_pointers,
    int *seen_config_pointer_count, int *candidate_count) {
    unsigned char *window = malloc(CHUNK_SIZE + 16);
    if (!window)
        return;

    unsigned char tail[15];
    size_t tail_len = 0;
    mach_vm_size_t offset = 0;
    while (offset < size) {
        mach_vm_size_t chunk_size = size - offset;
        if (chunk_size > CHUNK_SIZE)
            chunk_size = CHUNK_SIZE;

        vm_offset_t data = 0;
        mach_msg_type_number_t data_count = 0;
        kern_return_t kr = mach_vm_read(task, address + offset,
                                        chunk_size, &data, &data_count);
        if (kr != KERN_SUCCESS || data_count == 0) {
            tail_len = 0;
            offset += chunk_size;
            continue;
        }

        size_t data_len = (size_t)data_count;
        memcpy(window, tail, tail_len);
        memcpy(window + tail_len, (const void *)data, data_len);
        size_t window_len = tail_len + data_len;
        mach_vm_address_t window_address = address + offset - tail_len;

        for (size_t i = 0; i + 16 <= window_len; i++) {
            uint64_t name_address = read_u64_le(window + i);
            if (read_u64_le(window + i + 8) != CONFIG_CIPHER_NAME_LEN ||
                !find_name_address(name_addresses, name_address_count,
                                   name_address))
                continue;
            process_config_reference(
                task, window_address + i, name_address, keys, key_count,
                seen_config_pointers, seen_config_pointer_count,
                candidate_count);
        }

        tail_len = data_len < sizeof(tail) ? data_len : sizeof(tail);
        memcpy(tail, window + window_len - tail_len, tail_len);
        mach_vm_deallocate(mach_task_self(), data, data_count);
        offset += chunk_size;
    }

    free(window);
}

int main(int argc, char *argv[]) {
    pid_t pid;
    if (argc >= 2)
        pid = atoi(argv[1]);
    else
        pid = find_wechat_pid();

    if (pid <= 0) {
        fprintf(stderr, "WeChat not running or invalid PID\n");
        return 1;
    }

    printf("============================================================\n");
    printf("  macOS WeChat Memory Key Scanner (C version)\n");
    printf("============================================================\n");
    printf("WeChat PID: %d\n", pid);

    /* Get task port */
    mach_port_t task;
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "task_for_pid failed: %d\n", kr);
        fprintf(stderr, "Make sure: (1) running as root, (2) WeChat is ad-hoc signed\n");
        return 1;
    }
    printf("Got task port: %u\n", task);

    /* Resolve real user's HOME (sudo may change HOME to /var/root) */
    const char *home = getenv("HOME");
    const char *sudo_user = getenv("SUDO_USER");
    if (sudo_user) {
        struct passwd *pw = getpwnam(sudo_user);
        if (pw && pw->pw_dir)
            home = pw->pw_dir;
    }
    if (!home) home = "/root";
    printf("User home: %s\n", home);

    /* Collect DB salts by recursively walking db_storage directories.
     * Note: POSIX glob() does not support ** recursive matching on macOS,
     * so we use nftw() to walk the directory tree instead. */
    printf("\nScanning for DB files...\n");
    char db_base_dir[512];
    snprintf(db_base_dir, sizeof(db_base_dir),
        "%s/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files",
        home);

    /* Walk each account's db_storage directory */
    DIR *xdir = opendir(db_base_dir);
    if (xdir) {
        struct dirent *ent;
        while ((ent = readdir(xdir)) != NULL) {
            if (ent->d_name[0] == '.') continue;
            char storage_path[768];
            snprintf(storage_path, sizeof(storage_path),
                "%s/%s/db_storage", db_base_dir, ent->d_name);
            struct stat st;
            if (stat(storage_path, &st) == 0 && S_ISDIR(st.st_mode)) {
                nftw(storage_path, nftw_collect_db, 20, FTW_PHYS);
            }
        }
        closedir(xdir);
    }
    printf("Found %d encrypted DBs\n", g_db_count);

    /* Find the Config.Cipher name in all readable mappings.  The name is
     * usually in a read-only image segment, while the object that references
     * it lives in the heap, so only searching writable mappings misses it. */
    uint64_t name_addresses[MAX_NAME_ADDRESSES];
    int name_address_count = 0;
    mach_vm_address_t name_scan_addr = 0;
    while (1) {
        mach_vm_size_t size = 0;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t obj_name;

        kr = mach_vm_region(task, &name_scan_addr, &size,
                            VM_REGION_BASIC_INFO_64,
                            (vm_region_info_t)&info, &info_count, &obj_name);
        if (kr != KERN_SUCCESS) break;
        if (size == 0) { name_scan_addr++; continue; }
        if (info.protection & VM_PROT_READ) {
            scan_region_for_bytes(task, name_scan_addr, size,
                                  CONFIG_CIPHER_NAME, CONFIG_CIPHER_NAME_LEN,
                                  name_addresses, &name_address_count);
        }
        name_scan_addr += size;
    }
    printf("\nConfig.Cipher name matches: %d\n", name_address_count);

    /* Scan memory for x' patterns */
    printf("\nScanning memory for keys...\n");
    key_entry_t keys[MAX_KEYS];
    int key_count = 0;
    size_t total_scanned = 0;
    int region_count = 0;

    mach_vm_address_t addr = 0;
    while (1) {
        mach_vm_size_t size = 0;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t obj_name;

        kr = mach_vm_region(task, &addr, &size, VM_REGION_BASIC_INFO_64,
                           (vm_region_info_t)&info, &info_count, &obj_name);
        if (kr != KERN_SUCCESS) break;
        if (size == 0) { addr++; continue; }  /* guard against infinite loop */

        if ((info.protection & (VM_PROT_READ | VM_PROT_WRITE)) ==
            (VM_PROT_READ | VM_PROT_WRITE)) {
            region_count++;

            mach_vm_address_t ca = addr;
            while (ca < addr + size) {
                mach_vm_size_t cs = addr + size - ca;
                if (cs > CHUNK_SIZE) cs = CHUNK_SIZE;

                vm_offset_t data;
                mach_msg_type_number_t dc;
                kr = mach_vm_read(task, ca, cs, &data, &dc);
                if (kr == KERN_SUCCESS) {
                    unsigned char *buf = (unsigned char *)data;
                    total_scanned += dc;

                    for (size_t i = 0; i + HEX_PATTERN_LEN + 3 < dc; i++) {
                        if (buf[i] == 'x' && buf[i + 1] == '\'') {
                            /* Check if followed by 96 hex chars and closing ' */
                            int valid = 1;
                            for (int j = 0; j < HEX_PATTERN_LEN; j++) {
                                if (!is_hex_char(buf[i + 2 + j])) { valid = 0; break; }
                            }
                            if (!valid) continue;
                            if (buf[i + 2 + HEX_PATTERN_LEN] != '\'') continue;

                            /* Extract key and salt hex */
                            char key_hex[65], salt_hex[33];
                            memcpy(key_hex, buf + i + 2, 64);
                            key_hex[64] = '\0';
                            memcpy(salt_hex, buf + i + 2 + 64, 32);
                            salt_hex[32] = '\0';

                            lowercase_hex(key_hex);
                            lowercase_hex(salt_hex);
                            add_key(keys, &key_count, key_hex, salt_hex);
                        }
                    }
                    mach_vm_deallocate(mach_task_self(), data, dc);
                }
                /* Advance with overlap to catch patterns spanning chunk boundaries.
                 * Pattern is x'<96 hex chars>' = 99 bytes total. */
                if (cs > HEX_PATTERN_LEN + 3)
                    ca += cs - (HEX_PATTERN_LEN + 3);
                else
                    ca += cs;
            }
        }
        addr += size;
    }

    /* WeChat 4.1.x keeps the key material in XOR-obfuscated Config.Cipher
     * blobs instead of an easily searchable x'<key><salt>' literal.  Locate
     * references to the name and decode each associated blob. */
    int config_candidate_count = 0;
    int config_region_count = 0;
    uint64_t seen_config_pointers[MAX_CONFIG_POINTERS];
    int seen_config_pointer_count = 0;
    if (name_address_count > 0) {
        mach_vm_address_t config_scan_addr = 0;
        while (1) {
            mach_vm_size_t size = 0;
            vm_region_basic_info_data_64_t info;
            mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT_64;
            mach_port_t obj_name;

            kr = mach_vm_region(task, &config_scan_addr, &size,
                                VM_REGION_BASIC_INFO_64,
                                (vm_region_info_t)&info, &info_count,
                                &obj_name);
            if (kr != KERN_SUCCESS) break;
            if (size == 0) { config_scan_addr++; continue; }
            if (info.protection & VM_PROT_READ) {
                config_region_count++;
                scan_region_for_config_references(
                    task, config_scan_addr, size, name_addresses,
                    name_address_count, keys, &key_count,
                    seen_config_pointers, &seen_config_pointer_count,
                    &config_candidate_count);
            }
            config_scan_addr += size;
        }
    }
    if (config_candidate_count > 0) {
        printf("Config.Cipher regions: %d, blobs: %d, candidates: %d, keys: %d\n",
               config_region_count, seen_config_pointer_count,
               config_candidate_count, key_count);
    }

    printf("\nScan complete: %zuMB scanned, %d regions, %d unique keys\n",
           total_scanned / 1024 / 1024, region_count, key_count);

    /* Match keys to DBs */
    printf("\n%-25s %-66s %s\n", "Database", "Key", "Salt");
    printf("%-25s %-66s %s\n",
        "-------------------------",
        "------------------------------------------------------------------",
        "--------------------------------");

    int matched = 0;
    for (int i = 0; i < key_count; i++) {
        const char *db = NULL;
        for (int j = 0; j < g_db_count; j++) {
            if (strcmp(keys[i].salt_hex, g_db_salts[j]) == 0) {
                db = g_db_names[j];
                matched++;
                break;
            }
        }
        printf("%-25s %-66s %s\n",
            db ? db : "(unknown)",
            keys[i].key_hex,
            keys[i].salt_hex);
    }
    printf("\nMatched %d/%d keys to known DBs\n", matched, key_count);

    /* Save JSON: { "rel/path.db": { "enc_key": "hex", "salt": "hex" }, ... }
     * Uses forward slashes (native macOS paths, valid JSON without escaping).
     */
    const char *out_path = "all_keys.json";
    FILE *fp = fopen(out_path, "w");
    if (fp) {
        fprintf(fp, "{\n");
        int first = 1;
        for (int i = 0; i < key_count; i++) {
            const char *db = NULL;
            for (int j = 0; j < g_db_count; j++) {
                if (strcmp(keys[i].salt_hex, g_db_salts[j]) == 0) {
                    db = g_db_names[j];
                    break;
                }
            }
            if (!db) continue;
            fprintf(fp, "%s  \"%s\": {\"enc_key\": \"%s\", \"salt\": \"%s\"}",
                first ? "" : ",\n", db, keys[i].key_hex, keys[i].salt_hex);
            first = 0;
        }
        fprintf(fp, "\n}\n");
        fclose(fp);
        printf("Saved to %s\n", out_path);
    }

    return 0;
}
