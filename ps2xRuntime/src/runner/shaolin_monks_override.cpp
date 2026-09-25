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
#include <unordered_map>
#include <vector>

// =====================================================================================
// Shaolin Monks (SLUS_210.87) game overrides.
//
// A PCSX2 reference trace (2026-09-25) proved the earlier VCD approach was wrong: the
// real game reads its retail disc's ISO9660 filesystem (LSN 16 = PVD, then directories)
// and then real file data at true LSNs (67131, 203038, ...). Our old bypass fabricated
// LSN 0x540000 (5.5M, past the end of the 1.7M-sector disc) and stalled the game.
//
// FIX: back the CD calls with the real disc image (sm.iso, 1,706,768 sectors):
//   - sceCdLayerSearchFile @0x385CE0: resolve the requested path against sm.iso's real
//     ISO9660 filesystem and fill sceCdlFILE {lsn, size} with the TRUE on-disc LSN.
//   - sceCdRead @0x467940: serve sectors straight from sm.iso at lsn*2048.
// This makes every read hit the correct disc data, exactly like real hardware.
// =====================================================================================

namespace
{
    // ---- locate the retail disc image ----
    static FILE *openIso()
    {
        static const char *const cands[] = {
            "sm.iso",
            "C:\\Projects\\shaolin-monks-recomp\\sm.iso",
        };
        for (const char *c : cands)
        {
            if (FILE *f = std::fopen(c, "rb"))
                return f;
        }
        return nullptr;
    }

    static bool isoReadSectors(uint32_t lsn, uint32_t sectors, uint8_t *dst)
    {
        FILE *f = openIso();
        if (!f)
            return false;
        if (std::fseek(f, static_cast<long long>(lsn) * 2048ll, SEEK_SET) != 0)
        {
            std::fclose(f);
            return false;
        }
        const size_t want = static_cast<size_t>(sectors) * 2048u;
        const size_t got = std::fread(dst, 1, want, f);
        std::fclose(f);
        if (got == 0)
            return false;
        if (got < want)
            std::memset(dst + got, 0, want - got);
        return true;
    }

    static uint32_t le32(const uint8_t *p)
    {
        return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
               (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
    }

    // ---- minimal ISO9660 path -> (lsn, size) lookup against sm.iso ----
    // Path is already normalized ("FRONT/MOVIES/MIDWAY.SFD", no cdrom0:/;1). Case-insensitive.
    static std::mutex g_isoMutex;
    static std::unordered_map<std::string, std::pair<uint32_t, uint32_t>> g_isoCache;

    static bool ieq(const std::string &a, const std::string &b)
    {
        if (a.size() != b.size())
            return false;
        for (size_t i = 0; i < a.size(); ++i)
            if (std::tolower((unsigned char)a[i]) != std::tolower((unsigned char)b[i]))
                return false;
        return true;
    }

    static bool isoLookup(const std::string &normPath, uint32_t &outLsn, uint32_t &outSize)
    {
        {
            std::lock_guard<std::mutex> lk(g_isoMutex);
            auto it = g_isoCache.find(normPath);
            if (it != g_isoCache.end())
            {
                outLsn = it->second.first;
                outSize = it->second.second;
                return true;
            }
        }

        FILE *f = openIso();
        if (!f)
            return false;
        auto readSec = [&](uint32_t lsn, uint8_t *buf) -> bool {
            if (std::fseek(f, static_cast<long long>(lsn) * 2048ll, SEEK_SET) != 0)
                return false;
            return std::fread(buf, 1, 2048, f) == 2048;
        };

        uint8_t pvd[2048];
        bool ok = false;
        uint32_t foundLsn = 0, foundSize = 0;
        if (readSec(16, pvd) && pvd[0] == 1 && std::memcmp(pvd + 1, "CD001", 5) == 0)
        {
            // Root directory record lives at PVD+156; extent LBA @+2 (LE), data length @+10 (LE).
            uint32_t dirLba = le32(pvd + 156 + 2);
            uint32_t dirSize = le32(pvd + 156 + 10);

            // Split the normalized path into components.
            std::vector<std::string> parts;
            {
                std::string cur;
                for (char c : normPath)
                {
                    if (c == '/')
                    {
                        if (!cur.empty()) parts.push_back(cur);
                        cur.clear();
                    }
                    else
                        cur.push_back(c);
                }
                if (!cur.empty()) parts.push_back(cur);
            }

            bool pathOk = !parts.empty();
            for (size_t pi = 0; pi < parts.size() && pathOk; ++pi)
            {
                const bool isLast = (pi + 1 == parts.size());
                const uint32_t secCount = (dirSize + 2047u) / 2048u;
                std::vector<uint8_t> dir(static_cast<size_t>(secCount) * 2048u, 0);
                for (uint32_t s = 0; s < secCount; ++s)
                {
                    if (!readSec(dirLba + s, dir.data() + static_cast<size_t>(s) * 2048u))
                    {
                        pathOk = false;
                        break;
                    }
                }
                if (!pathOk)
                    break;

                bool matched = false;
                uint32_t off = 0;
                while (off < dirSize)
                {
                    const uint8_t recLen = dir[off];
                    if (recLen == 0)
                    {
                        // Directory records do not span sector boundaries; skip padding.
                        off = ((off / 2048u) + 1u) * 2048u;
                        continue;
                    }
                    const uint32_t recLba = le32(&dir[off + 2]);
                    const uint32_t recSize = le32(&dir[off + 10]);
                    const uint8_t flags = dir[off + 25];
                    const uint8_t nameLen = dir[off + 32];
                    // Skip "." (0x00) and ".." (0x01) special entries.
                    if (!(nameLen == 1 && (dir[off + 33] == 0x00 || dir[off + 33] == 0x01)))
                    {
                        std::string name(reinterpret_cast<char *>(&dir[off + 33]), nameLen);
                        auto sc = name.find(';');
                        if (sc != std::string::npos)
                            name = name.substr(0, sc);
                        if (ieq(name, parts[pi]))
                        {
                            const bool isDir = (flags & 0x02) != 0;
                            if (isLast && !isDir)
                            {
                                foundLsn = recLba;
                                foundSize = recSize;
                                ok = true;
                                matched = true;
                                break;
                            }
                            if (!isLast && isDir)
                            {
                                dirLba = recLba;
                                dirSize = recSize;
                                matched = true;
                                break;
                            }
                        }
                    }
                    off += recLen;
                }
                if (!matched)
                {
                    pathOk = false;
                    break;
                }
            }
        }
        std::fclose(f);

        if (ok)
        {
            std::lock_guard<std::mutex> lk(g_isoMutex);
            g_isoCache[normPath] = {foundLsn, foundSize};
            outLsn = foundLsn;
            outSize = foundSize;
        }
        return ok;
    }

    // Normalize a guest path: strip "cdrom0:" / "host:" / leading slash / ";1" version; '\\' -> '/'.
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
    static constexpr uint32_t kCdReadLogCap = 200u;

    void applyShaolinMonksOverrides(PS2Runtime &runtime)
    {
        // Inner counted delay loops inside sceCdLayerSearchFile: harmless safety bypass
        // (never reached now that 0x385CE0 returns at entry, but kept in case of direct entry).
        auto bypassDelay = [](uint8_t *rdram, R5900Context *ctx, PS2Runtime *rt) {
            const uint32_t entryPc = ctx->pc;
            ps2_stubs::ret0(rdram, ctx, rt);
            if (ctx->pc == entryPc) ctx->pc = getRegU32(ctx, 31);
        };
        runtime.registerFunction(0x00385D80u, bypassDelay);
        runtime.registerFunction(0x00385DE0u, bypassDelay);
        runtime.registerFunction(0x00385E40u, bypassDelay);

        // sceCdLayerSearchFile @0x385CE0: real ISO9660 lookup against sm.iso.
        // Verified from game code: a0(s3)=sceCdlFILE* out (written at +32/+35), a1(s2)=name
        // (byte-loaded at 0x385e20). sceCdlFILE: { u32 lsn; u32 size; char name[16]; u8 date[8]; }
        runtime.registerFunction(0x00385CE0u,
            [](uint8_t *rdram, R5900Context *ctx, PS2Runtime *rt)
            {
                const uint32_t entryPc = ctx->pc;
                const uint32_t filePtr = getRegU32(ctx, 4); // a0 = sceCdlFILE* out
                const uint32_t namePtr = getRegU32(ctx, 5); // a1 = const char* name

                std::string reqName;
                if (namePtr != 0)
                {
                    if (uint8_t *nameHost = getMemPtr(rdram, namePtr))
                    {
                        char tmp[96] = {};
                        std::strncpy(tmp, reinterpret_cast<char *>(nameHost), 95);
                        reqName = normalizeGuestPath(tmp);
                    }
                }

                uint32_t lsn = 0, size = 0;
                const bool found = !reqName.empty() && isoLookup(reqName, lsn, size);

                if (found && filePtr != 0)
                {
                    if (uint8_t *fileHost = getMemPtr(rdram, filePtr))
                    {
                        std::memset(fileHost, 0, 32);
                        std::memcpy(fileHost + 0, &lsn, 4);
                        std::memcpy(fileHost + 4, &size, 4);
                        std::string base = reqName;
                        auto slash = base.find_last_of('/');
                        if (slash != std::string::npos) base = base.substr(slash + 1);
                        std::memcpy(fileHost + 8, base.c_str(), std::min<size_t>(15, base.size()));
                    }
                }

                std::printf("[iso] search '%s' -> %s lsn=%u size=%u\n", reqName.c_str(),
                            found ? "FOUND" : "MISS", lsn, size);
                std::fflush(stdout);

                if (found)
                    ps2_stubs::ret1(rdram, ctx, rt);
                else
                    ps2_stubs::ret0(rdram, ctx, rt);
                if (ctx->pc == entryPc) ctx->pc = getRegU32(ctx, 31);
            });

        // sceCdRead @0x467940: serve sectors straight from sm.iso at lsn*2048.
        runtime.registerFunction(0x00467940u,
            [](uint8_t *rdram, R5900Context *ctx, PS2Runtime *rt)
            {
                const uint32_t entryPc = ctx->pc;
                const uint32_t lsn = getRegU32(ctx, 4);
                const uint32_t sectors = getRegU32(ctx, 5);
                const uint32_t dest = getRegU32(ctx, 6);

                bool ok = false;
                if (dest != 0 && sectors != 0 && sectors < 0x1000u)
                {
                    if (uint8_t *host = getMemPtr(rdram, dest))
                        ok = isoReadSectors(lsn, sectors, host);
                }

                const uint32_t n = g_cdReadLogCount.fetch_add(1);
                if (n < kCdReadLogCap)
                {
                    std::printf("[iso] read lsn=%u sectors=%u dest=0x%x -> %s\n",
                                lsn, sectors, dest, ok ? "ok" : "FAIL");
                    std::fflush(stdout);
                }

                ps2_stubs::ret1(rdram, ctx, rt);
                if (ctx->pc == entryPc) ctx->pc = getRegU32(ctx, 31);
            });

        // sceGsSyncV @0x206030: ret1 unlocks the vsync wait at 0x2313b0 (see history).
        runtime.registerFunction(0x00206030u,
            [](uint8_t *rdram, R5900Context *ctx, PS2Runtime *rt)
            {
                const uint32_t entryPc = ctx->pc;
                ps2_stubs::ret1(rdram, ctx, rt);
                if (ctx->pc == entryPc) ctx->pc = getRegU32(ctx, 31);
            });
    }
}

PS2_REGISTER_GAME_OVERRIDE(
    "shaolin-monks-us",
    "SLUS_210.87",
    0x0011C070u,
    0u,
    applyShaolinMonksOverrides);
