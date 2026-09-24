#include "game_overrides.h"
#include "ps2_runtime.h"
#include "ps2_stubs.h"
#include "ps2_syscalls.h"
#include <cctype>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

namespace
{
    // Remember last file requested via sceCdLayerSearchFile@0x385CE0 so sceCdRead@0x467940 can open correct host file.
    static std::string g_lastCdFile = "GAMEDATA.WAD";
    static std::mutex g_lastCdFileMutex;

    // ---- PWF inner FS parsing (GAMEDATA.WAD) ----
    // Header dump: 50 57 46 20 00 80 4F 80 02 00 00 00 E3 1B 00 00 00 00 00 19 00 08 ... (LE: magic 0x20574650, 0x804F8000, 2, 7139, 0x19000000, 0x800)
    // WADCRC.BIN is 7139*4 CRC32. Table at offset 32 appears compressed/encrypted (no plaintext TIM2/MIDWAY/ELF, 26 PWFs inside). Real offsets not monotonic in raw dump.
    // We keep a lazy once_flag parser that validates header and builds a best-effort inner file offset table. If table cannot be decoded, fallback is header+table+innerIdx*sector.
    static std::once_flag g_pwfOnce;
    static uint32_t g_pwfNumFiles = 0;
    static uint32_t g_pwfHeaderSize = 32;
    static bool g_pwfValid = false;
    static std::vector<uint32_t> g_pwfOffsets;
    static std::vector<uint32_t> g_pwfSizes;

    static void initPwfTableOnce()
    {
        std::call_once(g_pwfOnce, []() {
            const char *candidates[] = {
                "game_data/GAMEDATA.WAD",
                "C:\\Projects\\shaolin-monks-recomp\\game_data\\GAMEDATA.WAD",
                nullptr
            };
            for (int ci = 0; candidates[ci] != nullptr; ++ci) {
                FILE *f = std::fopen(candidates[ci], "rb");
                if (!f) continue;
                uint8_t hdr[32] = {};
                size_t got = std::fread(hdr, 1, 32, f);
                if (got < 32) { std::fclose(f); continue; }
                // Check magic "PWF "
                if (hdr[0] != 0x50 || hdr[1] != 0x57 || hdr[2] != 0x46 || hdr[3] != 0x20) { std::fclose(f); continue; }
                uint32_t numFiles = (uint32_t)hdr[12] | ((uint32_t)hdr[13] << 8) | ((uint32_t)hdr[14] << 16) | ((uint32_t)hdr[15] << 24);
                if (numFiles == 0 || numFiles > 20000) { std::fclose(f); continue; }
                g_pwfNumFiles = numFiles; // expect 7139
                g_pwfHeaderSize = 32;
                // Try to read table at offset 32. The dump shows at 32: 1c 00 80 f5 ... not monotonic offsets, likely compressed.
                // Attempt to interpret as array of 7139 * 8-byte entries (offset, size) LE. Validate if offsets look plausible.
                // If not plausible, we keep fallback linear scheme header+index*sector.
                std::fseek(f, 0, SEEK_END);
                long fsize = std::ftell(f);
                std::fseek(f, 32, SEEK_SET);
                const size_t stride = 8;
                g_pwfOffsets.assign(numFiles, 0);
                g_pwfSizes.assign(numFiles, 0);
                bool plausible = true;
                for (uint32_t i = 0; i < numFiles; ++i) {
                    uint8_t ent[8] = {};
                    if (std::fread(ent, 1, 8, f) != 8) { plausible = false; break; }
                    uint32_t off = (uint32_t)ent[0] | ((uint32_t)ent[1] << 8) | ((uint32_t)ent[2] << 16) | ((uint32_t)ent[3] << 24);
                    uint32_t sz  = (uint32_t)ent[4] | ((uint32_t)ent[5] << 8) | ((uint32_t)ent[6] << 16) | ((uint32_t)ent[7] << 24);
                    // Heuristic: offset should be within file and size < 10MB and offset+size <= fsize if valid
                    if (off > (uint32_t)fsize || sz > 10*1024*1024 || (sz != 0 && off + sz > (uint32_t)fsize)) {
                        // Mark as implausible; we still store but will fallback
                        // Check BE interpretation as alternative
                        uint32_t offBe = (uint32_t)ent[3] | ((uint32_t)ent[2] << 8) | ((uint32_t)ent[1] << 16) | ((uint32_t)ent[0] << 24);
                        uint32_t szBe  = (uint32_t)ent[7] | ((uint32_t)ent[6] << 8) | ((uint32_t)ent[5] << 16) | ((uint32_t)ent[4] << 24);
                        if (offBe < (uint32_t)fsize && szBe < 10*1024*1024 && offBe + szBe <= (uint32_t)fsize) {
                            off = offBe; sz = szBe;
                        } else {
                            plausible = false;
                            // keep raw but will not use for inner offset (fallback)
                        }
                    }
                    g_pwfOffsets[i] = off;
                    g_pwfSizes[i] = sz;
                }
                std::fclose(f);
                g_pwfValid = true;
                // If table not plausible (our dump shows first entry off 0xf580001c ~ 4GB LE not plausible), keep numFiles but force fallback linear.
                if (!plausible) {
                    // Keep offsets but caller will ignore if off >= fsize or sz==0, fallback to header+index*2048
                }
                break;
            }
        });
    }

    // filelist.dir has 15 entries (manifest, not LBN index). WADCRC.BIN is 7139 x CRC32 (at GAMEDATA.WAD+0x3 == 7139).
    // PWF header at GAMEDATA.WAD+0x0 ("PWF ") + 7139 entries suggests inner WAD filesystem, but CD LSN 0x540000
    // via sceCdLayerSearchFile bypass is synthetic (10.5 GiB). We map LSN to deterministic file index so sceCdRead
    // can open the correct host WAD at offset 0 (or lsn*2048 if plausible). See wiki §9 Phase 2.
    static uint32_t getFileIndexForName(const std::string &normName)
    {
        // normName is already normalized: upper/lower preserved but \ -> / and ;1 stripped, cdrom0: stripped.
        // Compare case-insensitive against filelist.dir order.
        std::string lower = normName;
        for (auto &c : lower) c = (char)std::tolower((unsigned char)c);
        if (lower == "wadcrc.bin") return 0;
        if (lower == "gamedata.wad") return 1;
        if (lower == "gamedata.wae") return 2;
        if (lower == "gamedata.waf") return 3;
        if (lower == "gamedata.wag") return 4;
        if (lower == "gamedata.wah") return 5;
        if (lower == "gamedata.wai") return 6;
        if (lower == "gamedata.waj") return 7;
        if (lower == "front/movies/midway.sfd") return 8;
        if (lower == "front/movies/opening.sfd") return 9;
        if (lower == "front/movies/end006.sfd") return 10;
        if (lower == "front/movies/end011.sfd") return 11;
        if (lower == "front/movies/final.sfd") return 12;
        if (lower == "front/movies/blitz.sfd") return 13;
        if (lower == "front/movies/gauntlet.sfd") return 14;
        // SYSTEM.CNF BOOT2 = cdrom0:\SLUS_210.87;1 is host ELF, not WAD. Map to 0xFFFF sentinel if needed.
        if (lower == "slus_210.87") return 0x5A5Au;
        // Fallback: hash to small index, keep deterministic but avoid colliding with 0..14
        uint32_t h = 0;
        for (unsigned char c : lower) h = h * 31u + c;
        return 15u + (h % 1000u);
    }

    void applyShaolinMonksOverrides(PS2Runtime &runtime)
    {
        // 0x385d80: counted delay loop inside sceCdLayerSearchFile@0x385CE0
        // (label_385d80: addiu $v0,$v0,-1; bne $v0,$v1,label_385d80 with eeCheckpointDue).
        // Entry alias g_ps2RecompiledFunctionTable[661344]=sub_00385CE0 // 0x385d80
        // makes it callable directly. Bypass the loop — return to caller.
        // Use safe wrapper per Stripped Walkthrough §7 (pc guard).
        runtime.registerFunction(0x00385D80u,
            [](uint8_t *rdram, R5900Context *ctx, PS2Runtime *rt)
            {
                const uint32_t entryPc = ctx->pc;
                ps2_stubs::ret0(rdram, ctx, rt);
                if (ctx->pc == entryPc)
                {
                    ctx->pc = getRegU32(ctx, 31);
                }
            });
        // 0x385de0: second counted delay loop in same function
        // (label_385de0: addiu $v0,$v0,-1; bne ...). Same bypass.
        runtime.registerFunction(0x00385DE0u,
            [](uint8_t *rdram, R5900Context *ctx, PS2Runtime *rt)
            {
                const uint32_t entryPc = ctx->pc;
                ps2_stubs::ret0(rdram, ctx, rt);
                if (ctx->pc == entryPc)
                {
                    ctx->pc = getRegU32(ctx, 31);
                }
            });
        // 0x385e40: third delay loop (label_385e40: slti $v0,$a1,0x100; ... bne)
        // This one is reached via the $a1 < 0x100 check; also bypass.
        runtime.registerFunction(0x00385E40u,
            [](uint8_t *rdram, R5900Context *ctx, PS2Runtime *rt)
            {
                const uint32_t entryPc = ctx->pc;
                ps2_stubs::ret0(rdram, ctx, rt);
                if (ctx->pc == entryPc)
                {
                    ctx->pc = getRegU32(ctx, 31);
                }
            });
        // 0x385ce0: whole-function bypass for sceCdLayerSearchFile@0x385CE0.
        // The outer 0x385da0->0x385db4->0x385dbc->0x385de0->0x385da0 retry loop
        // polls sceSifBindRpc (0x4834E0) + flags -0x2070(s4)/0x24(s0). Bypassing
        // inner delays alone didn't help (Cycle 3). Walkthrough §6 triage:
        // Cycle 4 ret0 gave GS idx=3 but tick 97→7 (caller took error branch at
        // 0x385d30 bne / 0x385d4c bnez). Now try ret1 (success).
        runtime.registerFunction(0x00385CE0u,
            [](uint8_t *rdram, R5900Context *ctx, PS2Runtime *rt)
            {
                const uint32_t entryPc = ctx->pc;
                // Try to set sceCdlFILE at a1 (s2) for file name at a0 (s3).
                // a0 = char* name, a1 = sceCdlFILE* out
                uint32_t namePtr = getRegU32(ctx, 4);
                uint32_t filePtr = getRegU32(ctx, 5);
                std::string reqName = "GAMEDATA.WAD";
                if (namePtr != 0)
                {
                    uint8_t *nameHost = getMemPtr(rdram, namePtr);
                    if (nameHost)
                    {
                        char tmp[64] = {};
                        std::strncpy(tmp, reinterpret_cast<char*>(nameHost), 60);
                        if (tmp[0] != '\0')
                        {
                            reqName = tmp;
                            // Normalize: strip "cdrom0:\\" prefix, ;1 suffix, and \\ -> /
                            if (reqName.rfind("cdrom0:", 0) == 0) reqName = reqName.substr(7);
                            if (!reqName.empty() && reqName[0] == '\\') reqName = reqName.substr(1);
                            auto sc = reqName.find(';');
                            if (sc != std::string::npos) reqName = reqName.substr(0, sc);
                            for (auto &c : reqName) if (c == '\\') c = '/';
                            {
                                std::lock_guard<std::mutex> lk(g_lastCdFileMutex);
                                g_lastCdFile = reqName;
                            }
                        }
                    }
                }
                if (filePtr != 0)
                {
                    uint8_t *fileHost = getMemPtr(rdram, filePtr);
                    if (fileHost)
                    {
                        std::memset(fileHost, 0, 32);
                        uint32_t *lsnOut = reinterpret_cast<uint32_t*>(fileHost);
                        uint32_t *sizeOut = reinterpret_cast<uint32_t*>(fileHost + 4);
                        // Deterministic file index -> LSN mapping. filelist.dir is manifest only; WADCRC.BIN is
                        // 7139 CRCs for inner PWF filesystem (GAMEDATA.WAD header PWF magic, u32[3]=7139). CD LSN
                        // 0x540000*2048=10.5 GiB is synthetic garbage. Map to index so sceCdRead can open correct host file.
                        std::string curFile;
                        {
                            std::lock_guard<std::mutex> lk(g_lastCdFileMutex);
                            curFile = g_lastCdFile;
                        }
                        uint32_t fileIdx = getFileIndexForName(curFile);
                        // Use index as LSN for GAMEDATA.WA* series; for non-WAD fall back to 0x1000 + index to keep offset 0 triage plausible
                        uint32_t lsn = fileIdx;
                        // Keep GAMEDATA.WAD at LSN 0 for zero-offset fast path; others at 1..7 also near zero (plausible < file size check in sceCdRead will fallback to 0 anyway)
                        // For files > 15, use 0x1000 base to avoid colliding with real small offsets.
                        if (fileIdx >= 15u) lsn = 0x00001000u + (fileIdx % 0x1000u);
                        *lsnOut = lsn;
                        // Try to get real file size for requested file
                        std::string hostPath;
                        {
                            std::lock_guard<std::mutex> lk(g_lastCdFileMutex);
                            hostPath = std::string("game_data/") + g_lastCdFile;
                        }
                        FILE *f = std::fopen(hostPath.c_str(), "rb");
                        uint32_t fsize = 407222272u;
                        if (f) { std::fseek(f,0,SEEK_END); long s=std::ftell(f); if(s>0) fsize=(uint32_t)s; std::fclose(f); }
                        else
                        {
                            // Fallback: try absolute path
                            std::string absPath = std::string("C:\\Projects\\shaolin-monks-recomp\\game_data\\") + curFile;
                            FILE *f2 = std::fopen(absPath.c_str(), "rb");
                            if (f2) { std::fseek(f2,0,SEEK_END); long s=std::ftell(f2); if(s>0) fsize=(uint32_t)s; std::fclose(f2); }
                        }
                        *sizeOut = fsize;
                        std::memcpy(fileHost + 8, g_lastCdFile.c_str(), std::min<size_t>(16, g_lastCdFile.size()));
                    }
                }
                ps2_stubs::ret1(rdram, ctx, rt);
                if (ctx->pc == entryPc)
                {
                    ctx->pc = getRegU32(ctx, 31);
                }
            });
        // 0x467940: sceCdRead@0x00467940 — Cycle 5 blocker LBN 0x540000 sectors 2
        // dest a2=0x75c540 at pc=0x420020. Uses g_lastCdFile + PWF inner FS index for true WAD+innerOffset.
        // filelist.dir 15 entries manifest; WADCRC.BIN 7139 CRCs; GAMEDATA.WAD header PWF at 0x00 (50 57 46 20, 0x804F8000, 2, 7139, 0x19000000, 0x800).
        // Inner table at 32 appears compressed (no TIM2/MIDWAY/ELF strings, 26 PWFs), so raw entry parsing fallback to header+index*sector.
        // LSN 0..14 -> outer WAD index via idxMap at offset 0; LSN >=0x1000 low 12 bits -> inner file index for GAMEDATA.WAD at innerOffset.
        runtime.registerFunction(0x00467940u,
            [](uint8_t *rdram, R5900Context *ctx, PS2Runtime *rt)
            {
                const uint32_t entryPc = ctx->pc;
                const uint32_t lsn = getRegU32(ctx, 4); // a0
                const uint32_t sectors = getRegU32(ctx, 5); // a1
                const uint32_t dest = getRegU32(ctx, 6); // a2
                bool handled = false;
                initPwfTableOnce();
                if (dest != 0 && sectors != 0 && sectors < 0x1000)
                {
                    uint8_t *host = getMemPtr(rdram, dest);
                    if (host)
                    {
                        std::string lastFile;
                        {
                            std::lock_guard<std::mutex> lk(g_lastCdFileMutex);
                            lastFile = g_lastCdFile;
                        }
                        std::string idxFile;
                        if (lsn <= 14u)
                        {
                            static const char* idxMap[15] = {
                                "WADCRC.BIN","GAMEDATA.WAD","GAMEDATA.WAE","GAMEDATA.WAF","GAMEDATA.WAG",
                                "GAMEDATA.WAH","GAMEDATA.WAI","GAMEDATA.WAJ",
                                "FRONT/MOVIES/MIDWAY.SFD","FRONT/MOVIES/OPENING.SFD","FRONT/MOVIES/END006.SFD",
                                "FRONT/MOVIES/END011.SFD","FRONT/MOVIES/FINAL.SFD","FRONT/MOVIES/BLITZ.SFD","FRONT/MOVIES/GAUNTLET.SFD"
                            };
                            if (lsn < 15u) idxFile = idxMap[lsn];
                        }
                        std::string cand1 = std::string("game_data/") + lastFile;
                        std::string cand2 = std::string("C:\\Projects\\shaolin-monks-recomp\\game_data\\") + lastFile;
                        std::string cand3 = idxFile.empty() ? std::string() : std::string("game_data/") + idxFile;
                        std::string cand4 = idxFile.empty() ? std::string() : std::string("C:\\Projects\\shaolin-monks-recomp\\game_data\\") + idxFile;
                        const char *candidates[] = {
                            cand1.c_str(),
                            cand2.c_str(),
                            cand3.empty() ? nullptr : cand3.c_str(),
                            cand4.empty() ? nullptr : cand4.c_str(),
                            "game_data/GAMEDATA.WAD",
                            "C:\\Projects\\shaolin-monks-recomp\\game_data\\GAMEDATA.WAD",
                            nullptr
                        };
                        bool readOk = false;
                        // Compute inner file index for PWF case: lsn >=0x1000 is hashed file (getFileIndexForName gave hash), low 12 bits as inner index.
                        // For true inner FS, lsn = 0x1000 + (hash%0x1000) -> innerIdx = (lsn - 0x1000) % g_pwfNumFiles if g_pwfValid.
                        // Also handle direct inner idx when lsn is large plausible offset not in 0..14.
                        uint32_t innerIdx = 0;
                        bool isInner = false;
                        if (g_pwfValid && g_pwfNumFiles > 0) {
                            if (lsn >= 0x1000u && lsn < 0x1000u + 0x1000u) {
                                innerIdx = (lsn - 0x1000u) % g_pwfNumFiles;
                                isInner = true;
                            } else if (lsn > 14u && lsn < 0x1000u) {
                                // Direct inner index for testing (e.g., lsn=123 -> inner 123)
                                if (lsn < g_pwfNumFiles) { innerIdx = lsn; isInner = true; }
                            }
                        }
                        for (int ci = 0; candidates[ci] != nullptr; ++ci)
                        {
                            FILE *f = std::fopen(candidates[ci], "rb");
                            if (!f) continue;
                            std::fseek(f, 0, SEEK_END);
                            long fsize = std::ftell(f);
                            size_t want = sectors * 2048u;
                            size_t off = 0;
                            if (lsn <= 14u)
                            {
                                off = 0;
                            }
                            else if (isInner)
                            {
                                // True LBN->WAD+innerOffset: use PWF table if valid entry, else fallback to header+table+innerIdx*sector
                                bool useTable = false;
                                if (g_pwfValid && innerIdx < g_pwfOffsets.size() && innerIdx < g_pwfSizes.size()) {
                                    uint32_t tblOff = g_pwfOffsets[innerIdx];
                                    uint32_t tblSz = g_pwfSizes[innerIdx];
                                    if (tblOff != 0 && tblOff < (uint32_t)fsize && tblSz != 0 && (size_t)tblOff + want <= (size_t)fsize) {
                                        off = tblOff;
                                        useTable = true;
                                    }
                                }
                                if (!useTable) {
                                    // Fallback: inner file 0 at header+table size, linear sector alignment. Table at 32 with 7139*8 ~57112 bytes if compressed fallback.
                                    size_t tableBytes = (size_t)g_pwfNumFiles * 8u;
                                    size_t base = (size_t)g_pwfHeaderSize + tableBytes;
                                    // If base beyond file, use header only
                                    if (base >= (size_t)fsize) base = g_pwfHeaderSize;
                                    size_t innerOff = base + (size_t)innerIdx * 2048u;
                                    // Clamp to file size
                                    if (innerOff < (size_t)fsize && innerOff + want <= (size_t)fsize) off = innerOff;
                                    else if (innerOff < (size_t)fsize) off = innerOff;
                                    else off = 0; // fallback
                                    // If still beyond, try lsn*2048 as last resort
                                    if (off == 0) {
                                        size_t lsnOff = (size_t)lsn * 2048u;
                                        if ((long)lsnOff < fsize && (long)(lsnOff + want) <= fsize) off = lsnOff;
                                    }
                                }
                            }
                            else
                            {
                                size_t lsnOff = (size_t)lsn * 2048u;
                                if ((long)lsnOff < fsize && (long)(lsnOff + want) <= fsize)
                                {
                                    off = lsnOff;
                                }
                                else
                                {
                                    off = 0;
                                }
                            }
                            std::fseek(f, (long)off, SEEK_SET);
                            size_t toRead = want;
                            if ((long)(off + toRead) > fsize) toRead = (size_t)(fsize - (long)off);
                            size_t got = std::fread(host, 1, toRead, f);
                            std::fclose(f);
                            if (got > 0)
                            {
                                if (got < want) std::memset(host + got, 0, want - got);
                                readOk = true;
                                handled = true;
                                break;
                            }
                        }
                        if (!readOk)
                        {
                            std::memset(host, 0, sectors * 2048u);
                            handled = true;
                        }
                    }
                }
                (void)lsn;
                (void)handled;
                ps2_stubs::ret1(rdram, ctx, rt);
                if (ctx->pc == entryPc)
                {
                    ctx->pc = getRegU32(ctx, 31);
                }
            });
        // 0x24cdc0/0x24cdd4: CD-read poll loop epilogue in sub_0024CDC0
        // Cycle 6 ret0 at 0x24cdd4 looped (ra==pc), Cycle 7 whole-function at
        // 0x24cdc0 made ticks disappear (no 0x24cdd4 after 3000). Revert to
        // minimal: handle sceGsSyncV@0x206030 (jal at 0x24cdcc) which this
        // function calls. The poll loop likely waits for vsync.
        // Keep only sceCdRead@0x467940 triage; remove 0x24cdd4/0x24cdc0
        // overrides that suppressed ticks. Instead, stub sceGsSyncV.
        runtime.registerFunction(0x00206030u,
            [](uint8_t *rdram, R5900Context *ctx, PS2Runtime *rt)
            {
                const uint32_t entryPc = ctx->pc;
                ps2_stubs::ret1(rdram, ctx, rt);
                if (ctx->pc == entryPc)
                {
                    ctx->pc = getRegU32(ctx, 31);
                }
            });
        // Keep SifBindRpc triage via TOML ret1@0x4834E0 (see game.toml).
    }
}

PS2_REGISTER_GAME_OVERRIDE(
    "shaolin-monks-us",
    "SLUS_210.87",
    0x0011C070u,
    0u,
    applyShaolinMonksOverrides);
