#include "game_overrides.h"
#include "ps2_runtime.h"
#include "ps2_stubs.h"
#include "ps2_syscalls.h"
#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

// =====================================================================================
// Shaolin Monks (SLUS_210.87) game overrides.
//
// History (see PROGRESS.md / AGENTS.md): early boot hung inside sceCdLayerSearchFile
// (0x385CE0) and a vsync wait (sceGsSyncV @ 0x206030). Those were bypassed with ret1
// triage so the game reaches its main loop. BUT diagnosis (2026-09-25) found the game
// never renders anything (gsw=0, magenta framebuffer): the CD I/O stubs fed it
// offset-0 / zero-filled data, so the consumer at 0x463EBC skips its 48-entry graphics
// state init loop (it validates data at guest 0x75c540) and the render pipeline never
// initialises.
//
// FIX: a coherent Virtual CD filesystem (VCD). The 15 on-disc files (filelist.dir order)
// are laid out contiguously in a synthetic LSN space. sceCdLayerSearchFile returns a
// file's base LSN + real size; sceCdRead maps ANY lsn back to (file, byteOffset) and
// reads the real bytes from the extracted host file under game_data/. This means the
// game gets correct data at correct offsets, including when it seeks by adding a sector
// offset to the base LSN it got from the search call.
//
// Concise logging ([vcd] lines) is emitted (throttled) so CD traffic is visible instead
// of suppressed — prior cycles flew blind here.
// =====================================================================================

namespace
{
    // Last file requested via sceCdLayerSearchFile — kept for diagnostics only now.
    static std::string g_lastCdFile = "GAMEDATA.WAD";
    static std::mutex g_lastCdFileMutex;

    // ---- Shared host I/O helpers ----
    static FILE *openHostFile(const std::string &relPath)
    {
        std::string cand1 = std::string("game_data/") + relPath;
        FILE *f = std::fopen(cand1.c_str(), "rb");
        if (f) return f;
        std::string cand2 = std::string("C:\\Projects\\shaolin-monks-recomp\\game_data\\") + relPath;
        return std::fopen(cand2.c_str(), "rb");
    }

    static bool getHostFileSize(const std::string &relPath, uint32_t &outSize)
    {
        FILE *f = openHostFile(relPath);
        if (!f) return false;
        std::fseek(f, 0, SEEK_END);
        long s = std::ftell(f);
        std::fclose(f);
        if (s <= 0) return false;
        outSize = static_cast<uint32_t>(s);
        return true;
    }

    static bool readHostFileAt(const std::string &relPath, size_t offset, uint8_t *dest, size_t want, size_t &outGot)
    {
        FILE *f = openHostFile(relPath);
        if (!f) return false;
        std::fseek(f, 0, SEEK_END);
        long fileSize = std::ftell(f);
        if (fileSize <= 0 || offset >= static_cast<size_t>(fileSize)) { std::fclose(f); return false; }
        size_t toRead = want;
        if (offset + toRead > static_cast<size_t>(fileSize)) toRead = static_cast<size_t>(fileSize) - offset;
        std::fseek(f, static_cast<long>(offset), SEEK_SET);
        outGot = std::fread(dest, 1, toRead, f);
        std::fclose(f);
        return outGot > 0;
    }

    // ---- Virtual CD filesystem (VCD) ----
    // filelist.dir order. Host files under game_data/ (Windows FS is case-insensitive,
    // so FRONT/MOVIES/*.SFD resolves to the extracted Front/Movies/*.sfd).
    static const char *const kVcdFiles[15] = {
        "WADCRC.BIN", "GAMEDATA.WAD", "GAMEDATA.WAE", "GAMEDATA.WAF", "GAMEDATA.WAG",
        "GAMEDATA.WAH", "GAMEDATA.WAI", "GAMEDATA.WAJ",
        "FRONT/MOVIES/MIDWAY.SFD", "FRONT/MOVIES/OPENING.SFD", "FRONT/MOVIES/END006.SFD",
        "FRONT/MOVIES/END011.SFD", "FRONT/MOVIES/FINAL.SFD", "FRONT/MOVIES/BLITZ.SFD",
        "FRONT/MOVIES/GAUNTLET.SFD"};

    struct VcdEntry
    {
        const char *name = nullptr;
        uint32_t baseLsn = 0;
        uint32_t sizeBytes = 0;
        uint32_t sectors = 0; // ceil(sizeBytes / 2048)
    };

    static std::once_flag g_vcdOnce;
    static std::vector<VcdEntry> g_vcd;

    // GAMEDATA.WAD's retail disc base LBN is hardcoded in the game: at 0x41FF5C
    // `lui $s3, 0x54` -> $s3 = 0x540000, which is passed to sceCdRead. So the game reads
    // GAMEDATA.WAD data at disc LBN 0x540000 + innerSectorOffset. We anchor the VCD there
    // so sceCdRead(0x540000 + n) maps to GAMEDATA.WAD[n * 2048].
    static constexpr uint32_t kGamedataBaseLsn = 0x540000u; // index 1 (GAMEDATA.WAD)

    static void initVcdOnce()
    {
        std::call_once(g_vcdOnce, []() {
            uint32_t sizes[15] = {0};
            uint32_t secs[15] = {0};
            for (int i = 0; i < 15; ++i)
            {
                getHostFileSize(kVcdFiles[i], sizes[i]); // 0 if missing
                secs[i] = (sizes[i] + 2047u) / 2048u;
            }

            uint32_t base[15] = {0};
            base[1] = kGamedataBaseLsn;                                   // GAMEDATA.WAD anchored
            uint32_t wadcrcSecs = (secs[0] > 0u ? secs[0] : 1u);         // WADCRC.BIN just before it
            base[0] = (kGamedataBaseLsn > wadcrcSecs) ? (kGamedataBaseLsn - wadcrcSecs) : 0u;
            uint32_t lsn = kGamedataBaseLsn + (secs[1] > 0u ? secs[1] : 1u);
            for (int i = 2; i < 15; ++i)                                  // WAE..WAJ, SFDs after it
            {
                base[i] = lsn;
                lsn += (secs[i] > 0u ? secs[i] : 1u);
            }

            g_vcd.reserve(15);
            for (int i = 0; i < 15; ++i)
            {
                VcdEntry e;
                e.name = kVcdFiles[i];
                e.baseLsn = base[i];
                e.sizeBytes = sizes[i];
                e.sectors = secs[i];
                g_vcd.push_back(e);
                std::printf("[vcd] map %-26s lsn=%u..%u size=%u\n", e.name, e.baseLsn,
                            e.baseLsn + (secs[i] > 0u ? secs[i] : 1u) - 1u, e.sizeBytes);
            }
            std::fflush(stdout);
        });
    }

    static const VcdEntry *vcdFindByLsn(uint32_t lsn)
    {
        for (const auto &e : g_vcd)
            if (e.sectors > 0u && lsn >= e.baseLsn && lsn < e.baseLsn + e.sectors)
                return &e;
        return nullptr;
    }

    static const VcdEntry *vcdFindByName(const std::string &norm)
    {
        std::string want = norm;
        for (auto &c : want) c = static_cast<char>(std::tolower((unsigned char)c));
        for (const auto &e : g_vcd)
        {
            std::string en = e.name;
            for (auto &c : en) c = static_cast<char>(std::tolower((unsigned char)c));
            if (en == want) return &e;
        }
        return nullptr;
    }

    // Normalize a guest path: strip "cdrom0:" / leading '\\' / ";1" version; '\\' -> '/'.
    static std::string normalizeGuestPath(const char *raw)
    {
        std::string s = raw ? raw : "";
        if (s.rfind("cdrom0:", 0) == 0) s = s.substr(7);
        if (s.rfind("host:", 0) == 0) s = s.substr(5);
        if (!s.empty() && (s[0] == '\\' || s[0] == '/')) s = s.substr(1);
        auto sc = s.find(';');
        if (sc != std::string::npos) s = s.substr(0, sc);
        for (auto &c : s) if (c == '\\') c = '/';
        return s;
    }

    static std::atomic<uint32_t> g_cdReadLogCount{0};
    static constexpr uint32_t kCdReadLogCap = 200u; // throttle read logging

    void applyShaolinMonksOverrides(PS2Runtime &runtime)
    {
        // --- inner counted delay loops inside sceCdLayerSearchFile: bypass (return to caller) ---
        auto bypassDelay = [](uint8_t *rdram, R5900Context *ctx, PS2Runtime *rt) {
            const uint32_t entryPc = ctx->pc;
            ps2_stubs::ret0(rdram, ctx, rt);
            if (ctx->pc == entryPc) ctx->pc = getRegU32(ctx, 31);
        };
        runtime.registerFunction(0x00385D80u, bypassDelay);
        runtime.registerFunction(0x00385DE0u, bypassDelay);
        runtime.registerFunction(0x00385E40u, bypassDelay);

        // --- sceCdLayerSearchFile @ 0x385CE0: resolve name -> VCD entry, fill sceCdlFILE, ret1 ---
        // sceCdlFILE layout: { u32 lsn; u32 size; char name[16]; u8 date[8]; }  (a0=name, a1=out).
        runtime.registerFunction(0x00385CE0u,
            [](uint8_t *rdram, R5900Context *ctx, PS2Runtime *rt)
            {
                const uint32_t entryPc = ctx->pc;
                initVcdOnce();

                const uint32_t namePtr = getRegU32(ctx, 4); // a0
                const uint32_t filePtr = getRegU32(ctx, 5); // a1

                std::string reqName = "GAMEDATA.WAD";
                if (namePtr != 0)
                {
                    if (uint8_t *nameHost = getMemPtr(rdram, namePtr))
                    {
                        char tmp[80] = {};
                        std::strncpy(tmp, reinterpret_cast<char *>(nameHost), 79);
                        if (tmp[0] != '\0') reqName = normalizeGuestPath(tmp);
                    }
                }

                const VcdEntry *e = vcdFindByName(reqName);
                if (!e && !g_vcd.empty()) e = &g_vcd[1]; // default to GAMEDATA.WAD
                const uint32_t lsn = e ? e->baseLsn : 16u;
                const uint32_t size = e ? e->sizeBytes : 0u;

                if (filePtr != 0)
                {
                    if (uint8_t *fileHost = getMemPtr(rdram, filePtr))
                    {
                        std::memset(fileHost, 0, 32);
                        std::memcpy(fileHost + 0, &lsn, 4);
                        std::memcpy(fileHost + 4, &size, 4);
                        // name field at +8 (char name[16]); date[8] follows at +24.
                        std::string base = reqName;
                        auto slash = base.find_last_of('/');
                        if (slash != std::string::npos) base = base.substr(slash + 1);
                        std::memcpy(fileHost + 8, base.c_str(), std::min<size_t>(15, base.size()));
                    }
                }

                {
                    std::lock_guard<std::mutex> lk(g_lastCdFileMutex);
                    g_lastCdFile = reqName;
                }
                std::printf("[vcd] search '%s' -> %s lsn=%u size=%u\n", reqName.c_str(),
                            e ? e->name : "(none)", lsn, size);
                std::fflush(stdout);

                ps2_stubs::ret1(rdram, ctx, rt);
                if (ctx->pc == entryPc) ctx->pc = getRegU32(ctx, 31);
            });

        // --- sceCdRead @ 0x467940: map lsn -> (file, offset), read real bytes, ret1 ---
        runtime.registerFunction(0x00467940u,
            [](uint8_t *rdram, R5900Context *ctx, PS2Runtime *rt)
            {
                const uint32_t entryPc = ctx->pc;
                initVcdOnce();

                const uint32_t lsn = getRegU32(ctx, 4);     // a0
                const uint32_t sectors = getRegU32(ctx, 5); // a1
                const uint32_t dest = getRegU32(ctx, 6);    // a2

                bool ok = false;
                uint32_t got = 0;
                const VcdEntry *e = nullptr;
                size_t off = 0;

                if (dest != 0 && sectors != 0 && sectors < 0x1000u)
                {
                    if (uint8_t *host = getMemPtr(rdram, dest))
                    {
                        e = vcdFindByLsn(lsn);
                        if (e)
                        {
                            off = static_cast<size_t>(lsn - e->baseLsn) * 2048u;
                            const size_t want = static_cast<size_t>(sectors) * 2048u;
                            size_t g = 0;
                            if (readHostFileAt(e->name, off, host, want, g))
                            {
                                got = static_cast<uint32_t>(g);
                                if (g < want) std::memset(host + g, 0, want - g);
                                ok = true;
                            }
                        }
                        if (!ok) std::memset(host, 0, static_cast<size_t>(sectors) * 2048u);
                    }
                }

                const uint32_t n = g_cdReadLogCount.fetch_add(1);
                if (n < kCdReadLogCap)
                {
                    std::printf("[vcd] read lsn=%u sectors=%u dest=0x%x -> %s off=%zu got=%u%s\n",
                                lsn, sectors, dest, e ? e->name : "(unmapped)", off, got,
                                ok ? "" : " [ZERO-FILL]");
                    std::fflush(stdout);
                }

                ps2_stubs::ret1(rdram, ctx, rt);
                if (ctx->pc == entryPc) ctx->pc = getRegU32(ctx, 31);
            });

        // --- sceGsSyncV @ 0x206030: ret1 unlocks the vsync wait at 0x2313b0 (Cycle 8) ---
        runtime.registerFunction(0x00206030u,
            [](uint8_t *rdram, R5900Context *ctx, PS2Runtime *rt)
            {
                const uint32_t entryPc = ctx->pc;
                ps2_stubs::ret1(rdram, ctx, rt);
                if (ctx->pc == entryPc) ctx->pc = getRegU32(ctx, 31);
            });

        // SifBindRpc triage stays via TOML ret1@0x4834E0 (see game.toml).
    }
}

PS2_REGISTER_GAME_OVERRIDE(
    "shaolin-monks-us",
    "SLUS_210.87",
    0x0011C070u,
    0u,
    applyShaolinMonksOverrides);
