#include "game_overrides.h"
#include "ps2_runtime.h"
#include "ps2_stubs.h"
#include "ps2_syscalls.h"
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>

namespace
{
    // Remember last file requested via sceCdLayerSearchFile@0x385CE0 so sceCdRead@0x467940 can open correct host file.
    static std::string g_lastCdFile = "GAMEDATA.WAD";
    static std::mutex g_lastCdFileMutex;

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
                        // Use LSN 0 for offset 0 triage; sceCdRead will ignore LSN and read at 0 via g_lastCdFile
                        *lsnOut = 0x00001000u;
                        // Try to get real file size for requested file
                        std::string hostPath;
                        {
                            std::lock_guard<std::mutex> lk(g_lastCdFileMutex);
                            hostPath = std::string("game_data/") + g_lastCdFile;
                        }
                        FILE *f = std::fopen(hostPath.c_str(), "rb");
                        uint32_t fsize = 407222272u;
                        if (f) { std::fseek(f,0,SEEK_END); long s=std::ftell(f); if(s>0) fsize=(uint32_t)s; std::fclose(f); }
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
        // dest a2=0x75c540 at pc=0x420020. Use g_lastCdFile from 0x385CE0 if available.
        runtime.registerFunction(0x00467940u,
            [](uint8_t *rdram, R5900Context *ctx, PS2Runtime *rt)
            {
                const uint32_t entryPc = ctx->pc;
                const uint32_t lsn = getRegU32(ctx, 4); // a0
                const uint32_t sectors = getRegU32(ctx, 5); // a1
                const uint32_t dest = getRegU32(ctx, 6); // a2
                bool handled = false;
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
                        // Build candidate list: last requested file first, then fallbacks
                        std::string cand1 = std::string("game_data/") + lastFile;
                        std::string cand2 = std::string("C:\\Projects\\shaolin-monks-recomp\\game_data\\") + lastFile;
                        const char *candidates[] = {
                            cand1.c_str(),
                            cand2.c_str(),
                            "game_data/GAMEDATA.WAD",
                            "C:\\Projects\\shaolin-monks-recomp\\game_data\\GAMEDATA.WAD",
                            nullptr
                        };
                        bool readOk = false;
                        // Use LSN as byte offset if plausible (< file size), else offset 0
                        for (int ci = 0; candidates[ci] != nullptr; ++ci)
                        {
                            FILE *f = std::fopen(candidates[ci], "rb");
                            if (!f) continue;
                            std::fseek(f, 0, SEEK_END);
                            long fsize = std::ftell(f);
                            size_t want = sectors * 2048u;
                            size_t lsnOff = (size_t)lsn * 2048u;
                            size_t off = 0;
                            if ((long)lsnOff < fsize && (long)(lsnOff + want) <= fsize)
                            {
                                off = lsnOff; // plausible direct LSN offset
                            }
                            else
                            {
                                off = 0; // triage fallback
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
