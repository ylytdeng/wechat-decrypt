/*
 * find_image_key.c — WeChat V2 image key continuous scanner (macOS)
 *
 * Discovers all unique V2 encryption patterns from the image cache,
 * then continuously scans WeChat process memory to find AES keys.
 * User just keeps browsing images in WeChat — the scanner catches
 * keys as they transiently appear in memory.
 *
 * Uses multi-block CCCrypt: one key setup decrypts ALL unsolved
 * patterns in a single call (~1.5 min per full scan with 20 patterns).
 *
 * Build:
 *   cc -O3 -o find_image_key find_image_key.c -framework Security
 *
 * Usage:
 *   sudo ./find_image_key              # auto-discover from config.json
 *   sudo ./find_image_key <image_dir>  # explicit image directory
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <time.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <unistd.h>
#include <CommonCrypto/CommonCryptor.h>

#define MAX_PATH    4096
#define MAX_PATTERNS 8192
#define V2_MAGIC    "\x07\x08V2\x08\x07"
#define V2_MAGIC_LEN 6
#define REGION_MAX  (200 * 1024 * 1024)
#define DEEP_PRIORITY_MAX 10  /* byte-by-byte scan for top N unsolved patterns */

/* ---- Strict image magic detection (16 bytes available from decrypted block) ---- */
static int is_image_magic(const unsigned char *pt) {
    if (pt[0] == 0xFF && pt[1] == 0xD8 && pt[2] == 0xFF &&
        pt[3] >= 0xC0 && pt[3] != 0xFF) {
        /* JFIF: verify "JF" at offset 6 */
        if (pt[3] == 0xE0) return (pt[6] == 'J' && pt[7] == 'F');
        /* EXIF: verify "Ex" at offset 6 */
        if (pt[3] == 0xE1) return (pt[6] == 'E' && pt[7] == 'x');
        /* Other markers: verify length field is sane (big-endian, 2..32767) */
        uint16_t len = ((uint16_t)pt[4] << 8) | pt[5];
        return (len >= 2 && len < 0x8000);
    }
    /* PNG: full 8-byte signature */
    if (pt[0]==0x89 && pt[1]==0x50 && pt[2]==0x4E && pt[3]==0x47 &&
        pt[4]==0x0D && pt[5]==0x0A && pt[6]==0x1A && pt[7]==0x0A) return 1;
    /* GIF: "GIF89a" or "GIF87a" */
    if (pt[0]=='G' && pt[1]=='I' && pt[2]=='F' && pt[3]=='8' &&
        (pt[4]=='9' || pt[4]=='7') && pt[5]=='a') return 1;
    /* WebP: "RIFF....WEBP" */
    if (pt[0]=='R' && pt[1]=='I' && pt[2]=='F' && pt[3]=='F' &&
        pt[8]=='W' && pt[9]=='E' && pt[10]=='B' && pt[11]=='P') return 1;
    return 0;
}

/* ---- Pattern tracking ---- */
typedef struct {
    unsigned char ct[16];           /* CT block 0 (first 16 encrypted bytes) */
    unsigned char key[16];          /* found AES key */
    int           solved;
    int           file_count;       /* how many .dat files use this pattern */
    char          sample_path[MAX_PATH];
} pattern_t;

static pattern_t patterns[MAX_PATTERNS];
static int       npatterns = 0;
static int       total_v2_files = 0;

/* ---- Rejected key blacklist (false positives) ---- */
#define MAX_REJECTED 256
static unsigned char rejected_keys[MAX_REJECTED][16];
static int n_rejected = 0;

static int is_rejected(const unsigned char *key) {
    for (int i = 0; i < n_rejected; i++)
        if (memcmp(rejected_keys[i], key, 16) == 0) return 1;
    return 0;
}
static void add_rejected(const unsigned char *key) {
    if (n_rejected < MAX_REJECTED && !is_rejected(key)) {
        memcpy(rejected_keys[n_rejected], key, 16);
        n_rejected++;
    }
}

/* ---- Global scan mode ---- */
static int g_deep_mode = 0;

/* ---- Graceful shutdown ---- */
static volatile sig_atomic_t stop_flag = 0;
static void sigint_handler(int sig) { (void)sig; stop_flag = 1; }

/* ---- Utility ---- */
static void bytes2hex(const unsigned char *d, int n, char *out) {
    for (int i = 0; i < n; i++) sprintf(out + i*2, "%02x", d[i]);
    out[n*2] = '\0';
}
static int hex2bytes(const char *h, unsigned char *o, int max) {
    int n = 0;
    while (n < max) {
        if (!h[0] || !h[1]) return 0;
        if (!((h[0] >= '0' && h[0] <= '9') || (h[0] >= 'a' && h[0] <= 'f') ||
              (h[0] >= 'A' && h[0] <= 'F'))) return 0;
        if (!((h[1] >= '0' && h[1] <= '9') || (h[1] >= 'a' && h[1] <= 'f') ||
              (h[1] >= 'A' && h[1] <= 'F'))) return 0;

        unsigned int b = 0;
        if (sscanf(h, "%2x", &b) != 1) return 0;
        o[n++] = (unsigned char)b; h += 2;
    }
    return n;
}

/* Minimal JSON string extractor */
static int json_get_string(const char *json, const char *key,
                           char *val, int maxlen) {
    char pat[256];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(json, pat);
    if (!p) return 0;
    p = strchr(p + strlen(pat), '"');
    if (!p) return 0;
    p++;
    const char *end = strchr(p, '"');
    if (!end || (int)(end - p) >= maxlen) return 0;
    memcpy(val, p, end - p);
    val[end - p] = '\0';
    return 1;
}

/* ---- Pattern discovery ---- */
static int find_pattern_index(const unsigned char *ct) {
    for (int i = 0; i < npatterns; i++)
        if (memcmp(patterns[i].ct, ct, 16) == 0) return i;
    return -1;
}

static void discover_dir(const char *dir) {
    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *ent;
    while ((ent = readdir(d))) {
        if (ent->d_name[0] == '.') continue;
        char path[MAX_PATH];
        snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name);
        struct stat st;
        if (lstat(path, &st) != 0) continue;
        if (S_ISLNK(st.st_mode)) continue;
        if (S_ISDIR(st.st_mode)) {
            discover_dir(path);
            continue;
        }
        if (!S_ISREG(st.st_mode)) continue;
        size_t nlen = strlen(ent->d_name);
        if (nlen < 5 || strcmp(ent->d_name + nlen - 4, ".dat") != 0) continue;

        FILE *f = fopen(path, "rb");
        if (!f) continue;
        unsigned char hdr[31];
        size_t rd = fread(hdr, 1, 31, f);
        fclose(f);
        if (rd < 31 || memcmp(hdr, V2_MAGIC, V2_MAGIC_LEN) != 0) continue;

        unsigned char *ct = hdr + 15;
        total_v2_files++;
        int idx = find_pattern_index(ct);
        if (idx >= 0) {
            patterns[idx].file_count++;
        } else if (npatterns < MAX_PATTERNS) {
            memcpy(patterns[npatterns].ct, ct, 16);
            patterns[npatterns].file_count = 1;
            patterns[npatterns].solved = 0;
            strncpy(patterns[npatterns].sample_path, path,
                    sizeof(patterns[npatterns].sample_path) - 1);
            patterns[npatterns].sample_path[sizeof(patterns[npatterns].sample_path) - 1] = '\0';
            npatterns++;
        }
    }
    closedir(d);
}

/* Sort patterns by file_count descending */
static int cmp_patterns(const void *a, const void *b) {
    return ((pattern_t*)b)->file_count - ((pattern_t*)a)->file_count;
}

/* ---- Process discovery ---- */
static int get_wechat_pids(pid_t *pids, int max) {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
    size_t sz = 0;
    if (sysctl(mib, 4, NULL, &sz, NULL, 0) != KERN_SUCCESS || sz == 0)
        return 0;

    size_t alloc_sz = sz + (sz >> 2);
    struct kinfo_proc *procs = malloc(alloc_sz);
    if (!procs) return 0;

    if (sysctl(mib, 4, procs, &alloc_sz, NULL, 0) != KERN_SUCCESS) {
        free(procs);
        return 0;
    }

    int n = (int)(alloc_sz / sizeof(struct kinfo_proc)), cnt = 0;
    for (int i = 0; i < n && cnt < max; i++)
        if (strstr(procs[i].kp_proc.p_comm, "WeChat"))
            pids[cnt++] = procs[i].kp_proc.p_pid;
    free(procs);
    return cnt;
}

/* ---- Verification: decrypt sample file, validate JPEG marker chain ---- */

/* Validate JPEG structure: check marker chain (SOI → markers → SOS/EOI) */
static int verify_jpeg_chain(const unsigned char *data, size_t len) {
    if (len < 4 || data[0] != 0xFF || data[1] != 0xD8) return 0;
    size_t pos = 2;
    int markers = 0;
    while (pos + 4 <= len) {
        if (data[pos] != 0xFF) return markers >= 2;
        unsigned char m = data[pos + 1];
        /* Skip fill bytes (FF FF...) */
        if (m == 0xFF) { pos++; continue; }
        if (m == 0x00) return 0; /* stuffed byte outside scan = invalid */
        if (m == 0xD9) return markers >= 1; /* EOI */
        if (m == 0xDA) return markers >= 1; /* SOS = scan data follows */
        if (m < 0xC0) return 0;
        uint16_t mlen = ((uint16_t)data[pos+2] << 8) | data[pos+3];
        if (mlen < 2) return 0;
        pos += 2 + mlen;
        markers++;
    }
    /* Ran out of data (first marker spans past AES region): accept if >= 1 valid marker */
    return markers >= 1;
}

/* Validate PNG: 8-byte sig + IHDR chunk */
static int verify_png_chain(const unsigned char *data, size_t len) {
    static const unsigned char sig[8] = {0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A};
    if (len < 24 || memcmp(data, sig, 8) != 0) return 0;
    /* IHDR chunk at offset 8: length(4) + "IHDR"(4) + data(13) + CRC(4) */
    return (data[12]=='I' && data[13]=='H' && data[14]=='D' && data[15]=='R');
}

static int verify_key(int pat_idx) {
    pattern_t *p = &patterns[pat_idx];
    FILE *f = fopen(p->sample_path, "rb");
    if (!f) return 1; /* can't verify, assume ok */

    unsigned char hdr[15];
    if (fread(hdr, 1, 15, f) != 15) { fclose(f); return 1; }
    uint32_t aes_size;
    memcpy(&aes_size, hdr + 6, 4);
    /* PKCS7: extra padding block when aes_size is 16-byte aligned */
    uint32_t ct_size = (aes_size % 16 == 0)
        ? aes_size + 16
        : ((aes_size + 15) / 16) * 16;
    if (ct_size > 10 * 1024 * 1024) { fclose(f); return 1; }

    unsigned char *ct = malloc(ct_size);
    size_t rd = fread(ct, 1, ct_size, f);
    fclose(f);
    if (rd < ct_size) { free(ct); return 1; }

    unsigned char *pt = malloc(ct_size);
    size_t moved;
    CCCryptorStatus st = CCCrypt(kCCDecrypt, kCCAlgorithmAES128,
        kCCOptionECBMode, p->key, 16, NULL,
        ct, ct_size, pt, ct_size, &moved);
    free(ct);

    if (st != kCCSuccess || moved < 16) { free(pt); return 0; }

    /* Deep validation based on image type */
    int ok = 0;
    if (pt[0] == 0xFF && pt[1] == 0xD8)
        ok = verify_jpeg_chain(pt, moved);
    else if (pt[0] == 0x89 && pt[1] == 0x50)
        ok = verify_png_chain(pt, moved);
    else if (pt[0] == 'G' && pt[1] == 'I' && pt[2] == 'F')
        ok = (moved >= 6 && pt[3] == '8' && (pt[4]=='9'||pt[4]=='7') && pt[5]=='a');
    else if (pt[0] == 'R' && pt[1] == 'I')
        ok = (moved >= 12 && pt[8]=='W' && pt[9]=='E' && pt[10]=='B' && pt[11]=='P');

    free(pt);
    return ok;
}

/* ---- Memory scanning ---- */

/*
 * Multi-block scan: for each candidate key, decrypt ALL unsolved
 * CT blocks in one CCCrypt call (ECB processes blocks independently).
 */
static int g_task_fail_warned = 0;

static int scan_pid(pid_t pid) {
    mach_port_t task;
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
    if (kr != KERN_SUCCESS) {
        if (!g_task_fail_warned) {
            g_task_fail_warned = 1;
            fprintf(stderr,
                "  WARNING: task_for_pid(%d) failed (kr=%d).\n"
                "  Cannot read WeChat memory. Checklist:\n"
                "    1. Run with sudo\n"
                "    2. Enable Developer Mode: Settings > Privacy & Security > Developer Mode\n"
                "    3. Grant Terminal Full Disk Access: Settings > Privacy & Security > Full Disk Access\n"
                "    4. If still failing, try: sudo DevToolsSecurity -enable\n"
                "    5. Last resort: disable SIP (boot to Recovery, run: csrutil disable)\n",
                pid, kr);
        }
        return 0;
    }

    /* Build batch CT buffer for unsolved patterns */
    int unsolved_idx[MAX_PATTERNS];
    int n_unsolved = 0;
    for (int i = 0; i < npatterns; i++)
        if (!patterns[i].solved) unsolved_idx[n_unsolved++] = i;
    if (n_unsolved == 0) {
        mach_port_deallocate(mach_task_self(), task);
        return 0;
    }

    unsigned char *batch_ct = malloc(n_unsolved * 16);
    unsigned char *batch_pt = malloc(n_unsolved * 16);
    if (!batch_ct || !batch_pt) {
        free(batch_ct);
        free(batch_pt);
        mach_port_deallocate(mach_task_self(), task);
        return 0;
    }
    for (int i = 0; i < n_unsolved; i++)
        memcpy(batch_ct + i*16, patterns[unsolved_idx[i]].ct, 16);

    mach_vm_address_t addr = 0;
    mach_vm_size_t rsize;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t count;
    mach_port_t obj = MACH_PORT_NULL;

    long regions = 0, found_this_pid = 0;
    long long total_bytes = 0, tests = 0;

    while (!stop_flag) {
        count = VM_REGION_BASIC_INFO_COUNT_64;
        kr = mach_vm_region(task, &addr, &rsize, VM_REGION_BASIC_INFO_64,
                            (vm_region_info_t)&info, &count, &obj);
        if (kr != KERN_SUCCESS) break;
        regions++;
        if (obj != MACH_PORT_NULL) {
            mach_port_deallocate(mach_task_self(), obj);
            obj = MACH_PORT_NULL;
        }

        if ((info.protection & VM_PROT_READ) && rsize > 0 && rsize < REGION_MAX) {
            vm_offset_t data;
            mach_msg_type_number_t data_cnt;
            kr = mach_vm_read(task, addr, rsize, &data, &data_cnt);
            if (kr == KERN_SUCCESS) {
                unsigned char *buf = (unsigned char *)data;
                total_bytes += data_cnt;

                /* Method 1: every 16-byte aligned position (raw binary keys) */
                for (mach_msg_type_number_t j = 0;
                     j + 16 <= data_cnt && !stop_flag; j += 16) {
                    tests++;
                    size_t moved;
                    CCCryptorStatus st = CCCrypt(
                        kCCDecrypt, kCCAlgorithmAES128, kCCOptionECBMode,
                        buf + j, 16, NULL,
                        batch_ct, n_unsolved * 16,
                        batch_pt, n_unsolved * 16, &moved);
                    if (st != kCCSuccess) continue;

                    for (int p = 0; p < n_unsolved; p++) {
                        if (is_image_magic(batch_pt + p*16)) {
                            if (is_rejected(buf + j)) continue;
                            int idx = unsolved_idx[p];
                            memcpy(patterns[idx].key, buf + j, 16);
                            patterns[idx].solved = 1;

                            char kh[33]; bytes2hex(buf + j, 16, kh);
                            char ch[33]; bytes2hex(patterns[idx].ct, 16, ch);
                            printf("\n  *** FOUND KEY: %s ***\n", kh);
                            printf("      Pattern: %s (%d files)\n",
                                   ch, patterns[idx].file_count);
                            printf("      PID %d, addr=0x%llx+0x%x\n",
                                   pid, addr, j);

                            /* Cross-check: does this key solve OTHER patterns? */
                            for (int q = 0; q < n_unsolved; q++) {
                                if (q == p || patterns[unsolved_idx[q]].solved)
                                    continue;
                                unsigned char tpt[16];
                                size_t tm;
                                CCCrypt(kCCDecrypt, kCCAlgorithmAES128,
                                    kCCOptionECBMode, buf + j, 16, NULL,
                                    patterns[unsolved_idx[q]].ct, 16,
                                    tpt, 16, &tm);
                                if (is_image_magic(tpt)) {
                                    int qi = unsolved_idx[q];
                                    memcpy(patterns[qi].key, buf + j, 16);
                                    patterns[qi].solved = 1;
                                    char qch[33];
                                    bytes2hex(patterns[qi].ct, 16, qch);
                                    printf("      Also solves: %s (%d files)\n",
                                           qch, patterns[qi].file_count);
                                }
                            }

                            found_this_pid++;
                            /* Rebuild batch for remaining unsolved */
                            n_unsolved = 0;
                            for (int i = 0; i < npatterns; i++)
                                if (!patterns[i].solved)
                                    unsolved_idx[n_unsolved++] = i;
                            for (int i = 0; i < n_unsolved; i++)
                                memcpy(batch_ct + i*16,
                                       patterns[unsolved_idx[i]].ct, 16);
                            if (n_unsolved == 0) goto done;
                            break; /* restart block check with new batch */
                        }
                    }
                }

                /* Method 2: hex string [0-9a-f]{16+} at unaligned positions.
                 * WeChat may store the AES key as a hex-encoded ASCII string
                 * in memory (e.g. "cfcd208495d565ef" = 16 ASCII bytes).
                 * We use the raw ASCII bytes directly as the 16-byte AES key,
                 * since the key is arbitrary bytes and the hex representation
                 * itself is 16 bytes for a 64-bit key half. */
                int run = 0, run_start = 0;
                for (mach_msg_type_number_t j = 0;
                     j <= data_cnt && !stop_flag; j++) {
                    int is_hex = (j < data_cnt) &&
                        ((buf[j]>='a' && buf[j]<='f') ||
                         (buf[j]>='0' && buf[j]<='9'));
                    if (is_hex) {
                        if (!run) run_start = j;
                        run++;
                    } else {
                        if (run >= 16) {
                            for (int k = run_start; k+16 <= run_start+run; k++) {
                                if (k % 16 == 0) continue; /* already tested */
                                tests++;
                                size_t moved;
                                CCCrypt(kCCDecrypt, kCCAlgorithmAES128,
                                    kCCOptionECBMode, buf+k, 16, NULL,
                                    batch_ct, n_unsolved*16,
                                    batch_pt, n_unsolved*16, &moved);
                                for (int p = 0; p < n_unsolved; p++) {
                                    if (is_image_magic(batch_pt + p*16)) {
                                        if (is_rejected(buf+k)) continue;
                                        int idx = unsolved_idx[p];
                                        memcpy(patterns[idx].key, buf+k, 16);
                                        patterns[idx].solved = 1;
                                        char kh[33]; bytes2hex(buf+k, 16, kh);
                                        char ch[33];
                                        bytes2hex(patterns[idx].ct, 16, ch);
                                        printf("\n  *** FOUND KEY: %s ***\n", kh);
                                        printf("      Pattern: %s (%d files)\n",
                                               ch, patterns[idx].file_count);
                                        printf("      ASCII context: %.32s\n",
                                               buf + run_start);
                                        found_this_pid++;
                                        /* Rebuild */
                                        n_unsolved = 0;
                                        for (int i = 0; i < npatterns; i++)
                                            if (!patterns[i].solved)
                                                unsolved_idx[n_unsolved++] = i;
                                        for (int i = 0; i < n_unsolved; i++)
                                            memcpy(batch_ct + i*16,
                                                patterns[unsolved_idx[i]].ct, 16);
                                        if (n_unsolved == 0) goto done;
                                        break;
                                    }
                                }
                            }
                        }
                        run = 0;
                    }
                }

                /* Method 3 (deep mode): byte-by-byte scan for top priority patterns */
                if (g_deep_mode && n_unsolved > 0) {
                    /* Build priority batch: top N unsolved by file_count */
                    int prio_idx[DEEP_PRIORITY_MAX];
                    int n_prio = 0;
                    for (int i = 0; i < n_unsolved && n_prio < DEEP_PRIORITY_MAX; i++) {
                        int pi = unsolved_idx[i];
                        if (patterns[pi].file_count >= 10)
                            prio_idx[n_prio++] = pi;
                    }
                    if (n_prio > 0) {
                        unsigned char prio_ct[DEEP_PRIORITY_MAX * 16];
                        unsigned char prio_pt[DEEP_PRIORITY_MAX * 16];
                        for (int i = 0; i < n_prio; i++)
                            memcpy(prio_ct + i*16, patterns[prio_idx[i]].ct, 16);

                        for (mach_msg_type_number_t j = 0;
                             j + 16 <= data_cnt && !stop_flag; j++) {
                            if (j % 16 == 0) continue; /* already tested in Method 1 */
                            tests++;
                            size_t moved;
                            CCCryptorStatus st = CCCrypt(
                                kCCDecrypt, kCCAlgorithmAES128, kCCOptionECBMode,
                                buf + j, 16, NULL,
                                prio_ct, n_prio * 16,
                                prio_pt, n_prio * 16, &moved);
                            if (st != kCCSuccess) continue;

                            for (int p = 0; p < n_prio; p++) {
                                if (!is_image_magic(prio_pt + p*16)) continue;
                                if (is_rejected(buf + j)) continue;
                                int idx = prio_idx[p];
                                if (patterns[idx].solved) continue;
                                memcpy(patterns[idx].key, buf + j, 16);
                                patterns[idx].solved = 1;

                                char kh[33]; bytes2hex(buf + j, 16, kh);
                                char ch[33]; bytes2hex(patterns[idx].ct, 16, ch);
                                printf("\n  *** FOUND KEY (deep): %s ***\n", kh);
                                printf("      Pattern: %s (%d files)\n",
                                       ch, patterns[idx].file_count);
                                printf("      PID %d, addr=0x%llx+0x%x (unaligned)\n",
                                       pid, addr, j);
                                found_this_pid++;

                                /* Cross-check against all unsolved */
                                for (int q = 0; q < n_unsolved; q++) {
                                    int qi = unsolved_idx[q];
                                    if (qi == idx || patterns[qi].solved) continue;
                                    unsigned char tpt[16];
                                    size_t tm;
                                    CCCrypt(kCCDecrypt, kCCAlgorithmAES128,
                                        kCCOptionECBMode, buf + j, 16, NULL,
                                        patterns[qi].ct, 16, tpt, 16, &tm);
                                    if (is_image_magic(tpt)) {
                                        memcpy(patterns[qi].key, buf + j, 16);
                                        patterns[qi].solved = 1;
                                        char qch[33];
                                        bytes2hex(patterns[qi].ct, 16, qch);
                                        printf("      Also solves: %s (%d files)\n",
                                               qch, patterns[qi].file_count);
                                    }
                                }

                                /* Rebuild main batch */
                                n_unsolved = 0;
                                for (int i = 0; i < npatterns; i++)
                                    if (!patterns[i].solved)
                                        unsolved_idx[n_unsolved++] = i;
                                for (int i = 0; i < n_unsolved; i++)
                                    memcpy(batch_ct + i*16,
                                        patterns[unsolved_idx[i]].ct, 16);
                                /* Rebuild priority batch */
                                n_prio = 0;
                                for (int i = 0; i < n_unsolved && n_prio < DEEP_PRIORITY_MAX; i++) {
                                    int pi2 = unsolved_idx[i];
                                    if (patterns[pi2].file_count >= 10)
                                        prio_idx[n_prio++] = pi2;
                                }
                                for (int i = 0; i < n_prio; i++)
                                    memcpy(prio_ct + i*16, patterns[prio_idx[i]].ct, 16);
                                if (n_unsolved == 0) goto done;
                                break;
                            }
                        }
                    }
                }

                done:
                mach_vm_deallocate(mach_task_self(), data, data_cnt);
                if (n_unsolved == 0) break;
            }
        }
        addr += rsize;
        if (regions % 500 == 0) {
            printf("  [%ld regions, %lld MB, %lld tests]\r",
                   regions, total_bytes/(1024*1024), tests);
            fflush(stdout);
        }
    }

    printf("  PID %d: %ld regions, %lld MB, %lld tests, %ld keys found     \n",
           pid, regions, total_bytes/(1024*1024), tests, found_this_pid);

    free(batch_ct);
    free(batch_pt);
    mach_port_deallocate(mach_task_self(), task);
    return (int)found_this_pid;
}

/* ---- Save results ---- */
static void save_keys(const char *dir) {
    char path[MAX_PATH];
    snprintf(path, sizeof(path), "%s/image_keys.json", dir);

    int solved = 0;
    for (int i = 0; i < npatterns; i++)
        if (patterns[i].solved) solved++;
    if (solved == 0) return;

    FILE *f = fopen(path, "w");
    if (!f) { fprintf(stderr, "Cannot write %s\n", path); return; }

    fprintf(f, "{\n");
    int first = 1;
    for (int i = 0; i < npatterns; i++) {
        if (!patterns[i].solved) continue;
        char ct_hex[33], key_hex[33];
        bytes2hex(patterns[i].ct, 16, ct_hex);
        bytes2hex(patterns[i].key, 16, key_hex);
        fprintf(f, "%s    \"%s\": \"%s\"",
                first ? "" : ",\n", ct_hex, key_hex);
        first = 0;
    }
    fprintf(f, "\n}\n");
    fclose(f);
    printf("\nSaved %d keys to %s\n", solved, path);
}

/* ---- Load existing keys from image_keys.json ---- */
static int load_keys(const char *dir) {
    char path[MAX_PATH];
    snprintf(path, sizeof(path), "%s/image_keys.json", dir);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    if (sz <= 0) { fclose(f); return 0; }
    fseek(f, 0, SEEK_SET);
    char *json = malloc((size_t)sz + 1);
    if (!json) { fclose(f); return 0; }
    size_t rd = fread(json, 1, (size_t)sz, f);
    if (rd != (size_t)sz) {
        free(json);
        fclose(f);
        return 0;
    }
    fclose(f);
    json[rd] = '\0';

    int loaded = 0;
    /* Parse "ct_hex": "key_hex" pairs */
    const char *p = json;
    while ((p = strchr(p, '"')) != NULL) {
        p++;
        const char *ct_end = strchr(p, '"');
        if (!ct_end || ct_end - p != 32) { p = ct_end ? ct_end + 1 : p; continue; }
        char ct_str[33]; memcpy(ct_str, p, 32); ct_str[32] = '\0';
        unsigned char ct[16];
        if (hex2bytes(ct_str, ct, 16) != 16) { p = ct_end + 1; continue; }

        p = ct_end + 1;
        p = strchr(p, '"');
        if (!p) break;
        p++;
        const char *key_end = strchr(p, '"');
        if (!key_end || key_end - p != 32) { p = key_end ? key_end + 1 : p; continue; }
        char key_str[33]; memcpy(key_str, p, 32); key_str[32] = '\0';
        unsigned char key[16];
        if (hex2bytes(key_str, key, 16) != 16) { p = key_end + 1; continue; }

        /* Match to pattern */
        for (int i = 0; i < npatterns; i++) {
            if (!patterns[i].solved && memcmp(patterns[i].ct, ct, 16) == 0) {
                memcpy(patterns[i].key, key, 16);
                patterns[i].solved = 1;
                loaded++;
                break;
            }
        }
        p = key_end + 1;
    }
    free(json);
    return loaded;
}

/* ---- Main ---- */
int main(int argc, char *argv[]) {
    signal(SIGINT, sigint_handler);

    printf("=== WeChat V2 Image Key Scanner ===\n\n");
    if (getuid() != 0) {
        fprintf(stderr, "ERROR: Run with sudo!\n"); return 1;
    }

    /* Determine image directory */
    char image_dir[MAX_PATH] = "";
    char exe_dir[MAX_PATH] = ".";
    int deep_mode = 0;
    const char *last_slash = strrchr(argv[0], '/');
    if (last_slash) {
        int len = (int)(last_slash - argv[0]);
        snprintf(exe_dir, sizeof(exe_dir), "%.*s", len, argv[0]);
    }

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--deep") == 0)
            deep_mode = 1;
        else if (image_dir[0] == '\0') {
            strncpy(image_dir, argv[i], sizeof(image_dir) - 1);
            image_dir[sizeof(image_dir) - 1] = '\0';
        }
    }

    if (image_dir[0] == '\0') {
        /* Read config.json */
        char cfg_path[MAX_PATH];
        snprintf(cfg_path, sizeof(cfg_path), "%s/config.json", exe_dir);
        FILE *cf = fopen(cfg_path, "r");
        if (cf) {
            fseek(cf, 0, SEEK_END);
            long sz = ftell(cf);
            if (sz <= 0) { fclose(cf); return 1; }
            fseek(cf, 0, SEEK_SET);
            char *json = malloc((size_t)sz + 1);
            if (!json) { fclose(cf); return 1; }
            size_t rd = fread(json, 1, (size_t)sz, cf);
            if (rd != (size_t)sz) {
                free(json);
                fclose(cf);
                return 1;
            }
            json[rd] = '\0';
            fclose(cf);
            char db_dir[MAX_PATH];
            if (json_get_string(json, "db_dir", db_dir, sizeof(db_dir))) {
                char *s = strrchr(db_dir, '/');
                if (!s) s = strrchr(db_dir, '\\');
                if (s) {
                    int plen = (int)(s - db_dir);
                    snprintf(image_dir, sizeof(image_dir),
                             "%.*s/msg", plen, db_dir);
                }
            }
            free(json);
        }
    }

    /* Auto-detect: scan ~/Library/Containers/com.tencent.xinWeChat */
    if (image_dir[0] == '\0') {
        const char *home = getenv("HOME");
        if (!home) home = "/Users";
        char base[MAX_PATH];
        snprintf(base, sizeof(base),
                 "%s/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files",
                 home);
        DIR *d = opendir(base);
        if (d) {
            struct dirent *ent;
            while ((ent = readdir(d))) {
                if (ent->d_name[0] == '.') continue;
                char candidate[MAX_PATH];
                snprintf(candidate, sizeof(candidate), "%s/%s/msg", base, ent->d_name);
                struct stat st;
                if (stat(candidate, &st) == 0 && S_ISDIR(st.st_mode)) {
                    strncpy(image_dir, candidate, sizeof(image_dir) - 1);
                    printf("Auto-detected image directory:\n  %s\n\n", image_dir);
                    break;
                }
            }
            closedir(d);
        }
    }

    if (image_dir[0] == '\0') {
        fprintf(stderr, "ERROR: Cannot determine image directory.\n");
        fprintf(stderr, "Tried:\n");
        fprintf(stderr, "  1. Command line argument\n");
        fprintf(stderr, "  2. config.json db_dir\n");
        fprintf(stderr, "  3. Auto-detect ~/Library/Containers/com.tencent.xinWeChat/...\n\n");
        fprintf(stderr, "Usage: sudo %s [--deep] [image_dir]\n", argv[0]);
        fprintf(stderr, "  image_dir: path to .../xwechat_files/<wxid>/msg\n");
        return 1;
    }

    /* Phase 1: Discover patterns */
    printf("Discovering encryption patterns in:\n  %s\n\n", image_dir);
    discover_dir(image_dir);
    if (npatterns == 0) {
        fprintf(stderr, "No V2 .dat files found!\n"); return 1;
    }
    qsort(patterns, npatterns, sizeof(pattern_t), cmp_patterns);

    int total_covered = 0;
    printf("Found %d patterns across %d V2 files:\n", npatterns, total_v2_files);
    for (int i = 0; i < npatterns; i++) {
        char ch[33]; bytes2hex(patterns[i].ct, 16, ch);
        printf("  #%-2d %s  (%d files)\n", i+1, ch, patterns[i].file_count);
        total_covered += patterns[i].file_count;
    }
    if (total_covered < total_v2_files)
        printf("  ... and %d files in overflow patterns\n",
               total_v2_files - total_covered);

    /* Load previously found keys */
    int preloaded = load_keys(exe_dir);
    if (preloaded > 0)
        printf("\nLoaded %d existing keys from image_keys.json\n", preloaded);

    if (deep_mode) {
        g_deep_mode = 1;
        printf("\n*** DEEP MODE: byte-by-byte scan for top %d unsolved patterns ***\n",
               DEEP_PRIORITY_MAX);
    }

    /* Phase 2: Continuous scanning */
    printf("\nScanning WeChat memory — keep browsing images! (Ctrl+C to stop)\n");
    int round = 0;
    while (!stop_flag) {
        int unsolved = 0;
        for (int i = 0; i < npatterns; i++)
            if (!patterns[i].solved) unsolved++;
        if (unsolved == 0) break;

        round++;
        pid_t pids[64];
        int npids = get_wechat_pids(pids, 64);
        if (npids == 0) {
            printf("  No WeChat processes found, waiting...\n");
            sleep(3);
            continue;
        }

        printf("\n--- Round %d: %d unsolved / %d total, %d PIDs ---\n",
               round, unsolved, npatterns, npids);

        int found_round = 0;
        for (int i = 0; i < npids && !stop_flag; i++) {
            found_round += scan_pid(pids[i]);
        }

        unsolved = 0;
        int solved_files = 0;
        for (int i = 0; i < npatterns; i++) {
            if (patterns[i].solved) solved_files += patterns[i].file_count;
            else unsolved++;
        }

        if (found_round > 0) {
            printf("\n  Progress: %d/%d patterns solved (%d/%d files)\n",
                   npatterns - unsolved, npatterns,
                   solved_files, total_v2_files);
            /* Verify newly found keys */
            for (int i = 0; i < npatterns; i++) {
                if (patterns[i].solved && !verify_key(i)) {
                    char kh[33]; bytes2hex(patterns[i].key, 16, kh);
                    printf("  REJECTED: %s (failed verification)\n", kh);
                    add_rejected(patterns[i].key);
                    patterns[i].solved = 0;
                    memset(patterns[i].key, 0, 16);
                }
            }
            /* Save after each find */
            save_keys(exe_dir);
        }

        if (unsolved > 0 && !stop_flag) {
            printf("  Keep browsing images in different chats...\n");
            sleep(1);
        }
    }

    /* Phase 3: Summary */
    save_keys(exe_dir);

    int solved = 0, solved_files = 0;
    for (int i = 0; i < npatterns; i++) {
        if (patterns[i].solved) {
            solved++;
            solved_files += patterns[i].file_count;
        }
    }

    printf("\n==================================================\n");
    if (solved == npatterns) {
        printf("ALL %d patterns solved! (%d files)\n", npatterns, total_v2_files);
    } else {
        printf("%d/%d patterns solved (%d/%d files)\n",
               solved, npatterns, solved_files, total_v2_files);
        printf("Unsolved:\n");
        for (int i = 0; i < npatterns; i++) {
            if (patterns[i].solved) continue;
            char ch[33]; bytes2hex(patterns[i].ct, 16, ch);
            printf("  %s (%d files)\n", ch, patterns[i].file_count);
        }
    }

    /* Count unique keys */
    int unique_keys = 0;
    for (int i = 0; i < npatterns; i++) {
        if (!patterns[i].solved) continue;
        int dup = 0;
        for (int j = 0; j < i; j++)
            if (patterns[j].solved &&
                memcmp(patterns[i].key, patterns[j].key, 16) == 0) { dup = 1; break; }
        if (!dup) unique_keys++;
    }
    printf("%d unique key(s) found.\n", unique_keys);
    printf("==================================================\n");

    return (solved > 0) ? 0 : 1;
}
