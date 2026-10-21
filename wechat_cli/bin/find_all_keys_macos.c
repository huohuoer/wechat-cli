/*
 * Copyright 2026 wechat4mac contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * 移植自 wechat4mac/native/macos/memory_probe.c（Apache-2.0）。
 * 修改：新增版本化诊断、匿名 FD 校验、SIGPIPE 处理及缓冲区清零。
 * 来源声明：wechat4mac；Copyright 2026 wechat4mac contributors。
 * Portions of the database decryption and query implementation are derived from
 * fanyuantaier/wechatauto-replica:
 * https://github.com/fanyuantaier/wechatauto-replica
 *
 * That upstream project is distributed under the Apache License, Version 2.0.
 * The derived portions have been substantially modified for macOS, including the
 * process-memory interface, key validation, permission boundaries, and safe local
 * file handling.
 *
 * WeChat and related names and marks are trademarks of their respective owners.
 * This project is independent and is not affiliated with or endorsed by Tencent
 * or WeChat.
 *
 * 默认仅统计 WCDB Cipher 对象引用链；候选只在显式模式经匿名管道发送。
 * 不读取数据库、不写文件、不打印密钥、不修改目标内存或系统权限。
 */
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define READ_CHUNK (4U * 1024U * 1024U)
#define MAX_NEEDLES 64U
#define MAX_PAIR_REFS 4096U
#define OBJECT_SCAN_SIZE 0x200U
#define MAX_REFERENCED_BLOB 16384U
#define MAX_CANDIDATES 256U

static const unsigned char NEEDLE[] = "com.Tencent.WCDB.Config.Cipher";
static const unsigned char CONFIG_XOR_MASK[] = {
    0xd2, 0xc7, 0x44, 0x24, 0x58, 0x02, 0x00, 0x00,
    0x00, 0x48, 0x89, 0x44, 0x24, 0x50, 0x48, 0x8b,
    0x45, 0x00, 0x48, 0x84, 0x4c, 0x24, 0x48, 0x48,
    0x89, 0x44, 0x25, 0x40, 0x48, 0x58, 0x4c, 0x24,
};

typedef struct {
    const unsigned char *bytes;
    size_t length;
} Pattern;

typedef struct {
    mach_vm_address_t *saved;
    size_t saved_capacity;
    size_t saved_count;
    size_t total_count;
} Hits;

typedef struct {
    unsigned char values[MAX_CANDIDATES][32];
    size_t count;
} CandidateSet;

typedef struct {
    size_t regions_scanned;
    size_t read_failures;
    int complete;
} ScanStats;

static void secure_bzero(void *value, size_t length) {
    volatile unsigned char *cursor = (volatile unsigned char *)value;
    while (length-- > 0) *cursor++ = 0;
}

static int parse_number(const char *text, long minimum, long *out) {
    char *end = NULL;
    errno = 0;
    long value = strtol(text, &end, 10);
    if (!text[0] || errno || !end || *end != '\0' || value < minimum || value > INT32_MAX) {
        return 0;
    }
    *out = value;
    return 1;
}

static int private_candidate_fd(int fd) {
    struct stat info;
    if (fd < 3 || fcntl(fd, F_GETFD) == -1 || fstat(fd, &info) != 0) return 0;
    if ((fcntl(fd, F_GETFL) & O_ACCMODE) == O_RDONLY) return 0;
    if (S_ISFIFO(info.st_mode)) {
        /* 命名 FIFO 有链接，匿名 pipe 没有；拒绝写磁盘上的命名通道。 */
        return info.st_nlink == 0;
    }
    if (S_ISSOCK(info.st_mode)) {
        struct sockaddr_un local = {0}, peer = {0};
        socklen_t local_length = sizeof(local), peer_length = sizeof(peer);
        if (getsockname(fd, (struct sockaddr *)&local, &local_length) != 0
            || getpeername(fd, (struct sockaddr *)&peer, &peer_length) != 0
            || local.sun_family != AF_UNIX || peer.sun_family != AF_UNIX
            || local_length > sizeof(local) || peer_length > sizeof(peer)) return 0;
        /* Darwin 可返回全长的空地址，不能只按地址头长度判断匿名性。 */
        for (size_t i = 0; i < sizeof(local.sun_path); ++i) {
            if (local.sun_path[i] || peer.sun_path[i]) return 0;
        }
        return 1;
    }
    return 0;
}

static void record_hit(Hits *hits, mach_vm_address_t address) {
    ++hits->total_count;
    if (hits->saved_count < hits->saved_capacity) {
        hits->saved[hits->saved_count++] = address;
    }
}

static void scan_buffer(
    const unsigned char *buf, size_t len, mach_vm_address_t base,
    mach_vm_address_t minimum_address, const Pattern *patterns,
    size_t pattern_count, Hits *hits
) {
    for (size_t p = 0; p < pattern_count; ++p) {
        const size_t pattern_len = patterns[p].length;
        if (pattern_len == 0 || len < pattern_len) continue;
        for (size_t i = 0; i + pattern_len <= len; ++i) {
            if (base + i < minimum_address) continue;
            if (memcmp(buf + i, patterns[p].bytes, pattern_len) == 0) {
                record_hit(hits, base + i);
            }
        }
    }
}

static kern_return_t scan_task(
    mach_port_t task, const Pattern *patterns, size_t pattern_count,
    size_t max_pattern_len, Hits *hits, ScanStats *stats
) {
    const size_t overlap = max_pattern_len > 0 ? max_pattern_len - 1 : 0;
    unsigned char *buffer = malloc(READ_CHUNK + overlap);
    if (!buffer) return KERN_RESOURCE_SHORTAGE;
    mach_vm_address_t address = 0;
    kern_return_t final_kr = KERN_SUCCESS;
    stats->complete = 0;
    while (1) {
        mach_vm_size_t region_size = 0;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t object_name = MACH_PORT_NULL;
        kern_return_t kr = mach_vm_region(
            task, &address, &region_size, VM_REGION_BASIC_INFO_64,
            (vm_region_info_t)&info, &info_count, &object_name
        );
        if (object_name != MACH_PORT_NULL) {
            mach_port_deallocate(mach_task_self(), object_name);
        }
        if (kr != KERN_SUCCESS) {
            if (kr == KERN_INVALID_ADDRESS) stats->complete = 1;
            else final_kr = kr;
            break;
        }
        mach_vm_address_t region_start = address;
        mach_vm_address_t region_end = region_start + region_size;
        if (region_end <= region_start) {
            final_kr = KERN_INVALID_ADDRESS;
            break;
        }
        ++stats->regions_scanned;
        if ((info.protection & VM_PROT_READ) != 0) {
            for (mach_vm_address_t cursor = region_start; cursor < region_end;) {
                mach_vm_address_t read_start = cursor;
                if (cursor > region_start && cursor - region_start >= overlap) read_start -= overlap;
                mach_vm_size_t remaining = region_end - read_start;
                mach_vm_size_t request = READ_CHUNK + (cursor > region_start ? overlap : 0);
                if (request > remaining) request = remaining;
                mach_vm_size_t actual = 0;
                kern_return_t read_kr = mach_vm_read_overwrite(
                    task, read_start, request, (mach_vm_address_t)buffer, &actual
                );
                if (read_kr == KERN_SUCCESS && actual > 0) {
                    scan_buffer(buffer, (size_t)actual, read_start, cursor, patterns, pattern_count, hits);
                } else {
                    ++stats->read_failures;
                }
                mach_vm_size_t step = READ_CHUNK;
                if (step > region_end - cursor) step = region_end - cursor;
                if (step == 0) break;
                cursor += step;
            }
        }
        address = region_end;
    }
    secure_bzero(buffer, READ_CHUNK + overlap);
    free(buffer);
    return final_kr;
}

static int read_exact(mach_port_t task, mach_vm_address_t address, void *out, mach_vm_size_t size) {
    mach_vm_size_t actual = 0;
    kern_return_t kr = mach_vm_read_overwrite(task, address, size, (mach_vm_address_t)out, &actual);
    return kr == KERN_SUCCESS && actual == size;
}

static uint64_t read_u64(const unsigned char *bytes) {
    uint64_t value = 0;
    memcpy(&value, bytes, sizeof(value));
    return value;
}

static int plausible_pointer(uint64_t value) {
    return value >= 0x10000ULL && value < 0x800000000000ULL;
}

static int add_unique_u64(uint64_t *values, size_t *count, size_t capacity, uint64_t value) {
    for (size_t i = 0; i < *count; ++i) {
        if (values[i] == value) return 0;
    }
    if (*count >= capacity) return 0;
    values[(*count)++] = value;
    return 1;
}

static size_t count_hex_literals(const unsigned char *decoded, size_t length) {
    size_t count = 0;
    for (size_t i = 0; i + 67 <= length; ++i) {
        if ((decoded[i] != 'x' && decoded[i] != 'X') || decoded[i + 1] != '\'') continue;
        size_t j = i + 2;
        while (j < length && isxdigit((unsigned char)decoded[j])) ++j;
        size_t run = j - (i + 2);
        if (j < length && decoded[j] == '\'' && run >= 64 && (run % 2) == 0) {
            ++count;
            i = j;
        }
    }
    return count;
}

static int hex_nibble(unsigned char ch) {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

static int probable_key(const unsigned char key[32]) {
    int seen[256] = {0};
    size_t distinct = 0;
    for (size_t i = 0; i < 32; ++i) {
        if (!seen[key[i]]) {
            seen[key[i]] = 1;
            ++distinct;
        }
    }
    return distinct >= 15;
}

static void add_candidate(CandidateSet *set, const unsigned char key[32]) {
    if (!probable_key(key)) return;
    for (size_t i = 0; i < set->count; ++i) {
        if (memcmp(set->values[i], key, 32) == 0) return;
    }
    if (set->count < MAX_CANDIDATES) memcpy(set->values[set->count++], key, 32);
}

static void add_hex_window(const unsigned char *hex, size_t run_length, size_t start, CandidateSet *set) {
    if (start + 64 > run_length) return;
    unsigned char key[32];
    for (size_t i = 0; i < 32; ++i) {
        int high = hex_nibble(hex[start + i * 2]);
        int low = hex_nibble(hex[start + i * 2 + 1]);
        if (high < 0 || low < 0) {
            secure_bzero(key, sizeof(key));
            return;
        }
        key[i] = (unsigned char)((high << 4) | low);
    }
    add_candidate(set, key);
    secure_bzero(key, sizeof(key));
}

static void collect_hex_candidates(const unsigned char *decoded, size_t length, CandidateSet *set) {
    for (size_t i = 0; i + 67 <= length; ++i) {
        if ((decoded[i] != 'x' && decoded[i] != 'X') || decoded[i + 1] != '\'') continue;
        size_t start = i + 2;
        size_t j = start;
        while (j < length && isxdigit((unsigned char)decoded[j])) ++j;
        size_t run = j - start;
        if (j >= length || decoded[j] != '\'' || run < 64 || (run % 2) != 0) continue;
        add_hex_window(decoded + start, run, 0, set);
        if (run > 96) {
            for (size_t off = 0; off + 64 <= run; off += 32) {
                add_hex_window(decoded + start, run, off, set);
            }
            add_hex_window(decoded + start, run, run - 64, set);
        }
        i = j;
    }
}

static int write_all(int fd, const unsigned char *data, size_t length) {
    size_t written = 0;
    while (written < length) {
        ssize_t n = write(fd, data + written, length - written);
        if (n > 0) {
            written += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR) continue;
        return 0;
    }
    return 1;
}

int main(int argc, char **argv) {
    long pid_value = 0, fd_value = -1;
    int extract_mode = 0;
    if (argc == 3 && strcmp(argv[1], "--pid") == 0) {
        if (!parse_number(argv[2], 1, &pid_value)) pid_value = 0;
    } else if (argc == 6 && strcmp(argv[1], "--extract-candidates") == 0
               && strcmp(argv[2], "--pid") == 0 && strcmp(argv[4], "--candidate-fd") == 0) {
        extract_mode = 1;
        if (!parse_number(argv[3], 1, &pid_value) || !parse_number(argv[5], 3, &fd_value)) pid_value = 0;
    }
    int candidate_fd = (int)fd_value;
    pid_t pid = (pid_t)pid_value;
    if (pid <= 0 || (extract_mode && !private_candidate_fd(candidate_fd))) {
        fputs("{\"protocol\":1,\"pid\":0,\"kr\":21}\n", stdout);
        return 21;
    }
    signal(SIGPIPE, SIG_IGN);
    mach_port_t task = MACH_PORT_NULL;
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
    if (kr != KERN_SUCCESS || task == MACH_PORT_NULL) {
        if (task != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), task);
        printf("{\"protocol\":1,\"pid\":%d,\"task_port\":false,\"kr\":%d,"
               "\"needle_hits\":0,\"pair_refs\":0,\"candidate_nodes\":0}\n", pid, kr);
        return 27;
    }
    mach_vm_address_t needle_addresses[MAX_NEEDLES] = {0};
    Hits needle_hits = {needle_addresses, MAX_NEEDLES, 0, 0};
    ScanStats needle_scan = {0, 0, 0};
    Pattern needle_pattern = {NEEDLE, sizeof(NEEDLE) - 1};
    kr = scan_task(task, &needle_pattern, 1, needle_pattern.length, &needle_hits, &needle_scan);
    if (kr != KERN_SUCCESS || !needle_scan.complete) {
        mach_port_deallocate(mach_task_self(), task);
        printf("{\"protocol\":1,\"pid\":%d,\"kr\":23}\n", pid);
        return 23;
    }
    unsigned char pair_bytes[MAX_NEEDLES][16];
    Pattern pair_patterns[MAX_NEEDLES];
    for (size_t i = 0; i < needle_hits.saved_count; ++i) {
        uint64_t address = needle_hits.saved[i];
        uint64_t length = sizeof(NEEDLE) - 1;
        memcpy(pair_bytes[i], &address, sizeof(address));
        memcpy(pair_bytes[i] + 8, &length, sizeof(length));
        pair_patterns[i].bytes = pair_bytes[i];
        pair_patterns[i].length = sizeof(pair_bytes[i]);
    }
    mach_vm_address_t pair_addresses[MAX_PAIR_REFS] = {0};
    Hits pair_hits = {pair_addresses, MAX_PAIR_REFS, 0, 0};
    ScanStats pair_scan = {0, 0, 1};
    if (needle_hits.saved_count > 0) {
        kr = scan_task(task, pair_patterns, needle_hits.saved_count, sizeof(pair_bytes[0]), &pair_hits, &pair_scan);
        if (kr != KERN_SUCCESS || !pair_scan.complete) {
            mach_port_deallocate(mach_task_self(), task);
            printf("{\"protocol\":1,\"pid\":%d,\"kr\":23}\n", pid);
            return 23;
        }
    }
    size_t candidate_nodes = 0;
    uint64_t config_ptrs[MAX_PAIR_REFS] = {0};
    size_t config_ptr_count = 0;
    for (size_t i = 0; i < pair_hits.saved_count; ++i) {
        if (pair_hits.saved[i] < 0x10) continue;
        unsigned char node[0x50];
        if (!read_exact(task, pair_hits.saved[i] - 0x10, node, sizeof(node))) continue;
        uint64_t needle_address = read_u64(node + 0x10);
        uint64_t needle_length = read_u64(node + 0x18);
        uint64_t config_ptr = read_u64(node + 0x28);
        secure_bzero(node, sizeof(node));
        int known_needle = 0;
        for (size_t n = 0; n < needle_hits.saved_count; ++n) {
            if (needle_address == needle_hits.saved[n]) { known_needle = 1; break; }
        }
        if (!known_needle || needle_length != sizeof(NEEDLE) - 1 || !plausible_pointer(config_ptr)) continue;
        ++candidate_nodes;
        add_unique_u64(config_ptrs, &config_ptr_count, MAX_PAIR_REFS, config_ptr);
    }
    size_t referenced_blobs = 0, plain_hex_literals = 0, xor_hex_literals = 0;
    CandidateSet candidates = {{{0}}, 0};
    unsigned char object[OBJECT_SCAN_SIZE];
    unsigned char blob[MAX_REFERENCED_BLOB];
    unsigned char decoded[MAX_REFERENCED_BLOB];
    for (size_t c = 0; c < config_ptr_count; ++c) {
        if (!read_exact(task, config_ptrs[c], object, sizeof(object))) continue;
        plain_hex_literals += count_hex_literals(object, sizeof(object));
        if (extract_mode) collect_hex_candidates(object, sizeof(object), &candidates);
        for (size_t phase = 0; phase < sizeof(CONFIG_XOR_MASK); ++phase) {
            for (size_t j = 0; j < sizeof(object); ++j) {
                decoded[j] = object[j] ^ CONFIG_XOR_MASK[(j + phase) % sizeof(CONFIG_XOR_MASK)];
            }
            xor_hex_literals += count_hex_literals(decoded, sizeof(object));
            if (extract_mode) collect_hex_candidates(decoded, sizeof(object), &candidates);
        }
        for (size_t off = 0; off + 16 <= sizeof(object); off += 8) {
            uint64_t data_ptr = read_u64(object + off);
            uint64_t data_len = read_u64(object + off + 8);
            if (!plausible_pointer(data_ptr) || data_len == 0 || data_len > MAX_REFERENCED_BLOB) continue;
            if (!read_exact(task, data_ptr, blob, data_len)) continue;
            ++referenced_blobs;
            plain_hex_literals += count_hex_literals(blob, (size_t)data_len);
            if (extract_mode) collect_hex_candidates(blob, (size_t)data_len, &candidates);
            for (size_t phase = 0; phase < sizeof(CONFIG_XOR_MASK); ++phase) {
                for (size_t j = 0; j < data_len; ++j) {
                    decoded[j] = blob[j] ^ CONFIG_XOR_MASK[(j + phase) % sizeof(CONFIG_XOR_MASK)];
                }
                xor_hex_literals += count_hex_literals(decoded, (size_t)data_len);
                if (extract_mode) collect_hex_candidates(decoded, (size_t)data_len, &candidates);
            }
        }
    }
    mach_port_deallocate(mach_task_self(), task);
    int candidate_write_ok = 1;
    if (extract_mode) {
        candidate_write_ok = write_all(candidate_fd, (const unsigned char *)candidates.values, candidates.count * 32);
        close(candidate_fd);
    }
    printf(
        "{\"protocol\":1,\"pid\":%d,\"task_port\":true,\"kr\":0,"
        "\"needle_hits\":%zu,\"pair_refs\":%zu,\"candidate_nodes\":%zu,"
        "\"unique_config_ptrs\":%zu,\"referenced_blobs\":%zu,"
        "\"plain_hex_literals\":%zu,\"xor_hex_literals\":%zu,"
        "\"scan_complete\":true,\"regions_scanned\":%zu,\"read_failures\":%zu,"
        "\"candidate_channel\":%s,\"candidate_count\":%zu,\"candidate_write_ok\":%s}\n",
        pid, needle_hits.total_count, pair_hits.total_count, candidate_nodes,
        config_ptr_count, referenced_blobs, plain_hex_literals, xor_hex_literals,
        needle_scan.regions_scanned + pair_scan.regions_scanned,
        needle_scan.read_failures + pair_scan.read_failures,
        extract_mode ? "true" : "false", extract_mode ? candidates.count : 0,
        candidate_write_ok ? "true" : "false"
    );
    secure_bzero(&candidates, sizeof(candidates));
    secure_bzero(object, sizeof(object));
    secure_bzero(blob, sizeof(blob));
    secure_bzero(decoded, sizeof(decoded));
    return candidate_write_ok ? 0 : 23;
}
