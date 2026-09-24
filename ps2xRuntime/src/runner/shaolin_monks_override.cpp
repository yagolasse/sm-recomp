#include "game_overrides.h"
#include "ps2_runtime.h"
#include "ps2_stubs.h"
#include "ps2_syscalls.h"
#include <cstdio>
#include <cstring>
#include <mutex>

namespace
{
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
                if (filePtr != 0)
                {
                    uint8_t *fileHost = getMemPtr(rdram, filePtr);
                    if (fileHost)
                    {
                        // Zero the struct first (32 bytes typical for sceCdlFILE)
                        std::memset(fileHost, 0, 32);
                        // Set lsn and size to plausible values for GAMEDATA.WAD
                        // Use a small LSN that maps to host file offset 0 via our sceCdRead handler
                        // (sceCdRead handler will read from WAD at offset 0 regardless of LSN, so any LSN works for now)
                        // Write lsn at 0, size at 4, copy name at 8
                        uint32_t *lsnOut = reinterpret_cast<uint32_t*>(fileHost);
                        uint32_t *sizeOut = reinterpret_cast<uint32_t*>(fileHost + 4);
                        *lsnOut = 0x00100000u; // synthetic, will be handled by sceCdRead as offset 0
                        *sizeOut = 407222272u; // GAMEDATA.WAD size
                        if (namePtr != 0)
                        {
                            uint8_t *nameHost = getMemPtr(rdram, namePtr);
                            if (nameHost)
                            {
                                // Copy up to 16 chars of requested name for debugging
                                char tmp[32] = {};
                                std::strncpy(tmp, reinterpret_cast<char*>(nameHost), 30);
                                std::memcpy(fileHost + 8, tmp, 16);
                            }
                        }
                    }
                }
                ps2_stubs::ret1(rdram, ctx, rt);
                if (ctx->pc == entryPc)
                {
                    ctx->pc = getRegU32(ctx, 31);
                }
            });
        // 0x467940: sceCdRead@0x00467940 — Cycle 5 blocker LBN 0x540000 sectors 2
        // dest a2=0x75c540 at pc=0x420020. Try host WAD mapping before zero-fill triage.
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
                        // Try host WAD file at game_data/GAMEDATA.WAD (first WAD).
                        // LBN 0x540000 is beyond single WAD size (10 GiB vs 400 MB),
                        // so LBN is likely not direct byte offset; use filelist.dir
                        // mapping or just read from WAD at offset 0 for triage.
                        // For Cycle 11: attempt to read from GAMEDATA.WAD at offset 0,
                        // fallback to zero-fill. This proves file I/O path works.
                        static std::once_flag s_logOnce;
                        std::call_once(s_logOnce, [&]() {
                            (void)rt;
                            // Log once to run_log for debugging (ps2_log if enabled)
                        });
                        // Attempt host read: open game_data/GAMEDATA.WAD and read sectors*2048 at offset 0
                        // (real LBN->file mapping via filelist.dir would be next step).
                        const char *candidates[] = {
                            "game_data/GAMEDATA.WAD",
                            "C:\\Projects\\shaolin-monks-recomp\\game_data\\GAMEDATA.WAD",
                            nullptr
                        };
                        bool readOk = false;
                        for (int ci = 0; candidates[ci] != nullptr; ++ci)
                        {
                            FILE *f = std::fopen(candidates[ci], "rb");
                            if (!f) continue;
                            std::fseek(f, 0, SEEK_END);
                            long fsize = std::ftell(f);
                            std::fseek(f, 0, SEEK_SET);
                            size_t want = sectors * 2048u;
                            // Clamp to file size, read at offset 0 for now (real LBN mapping TODO)
                            size_t toRead = want;
                            if ((long)toRead > fsize) toRead = (size_t)fsize;
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
                            // Fallback triage: zero-fill
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
