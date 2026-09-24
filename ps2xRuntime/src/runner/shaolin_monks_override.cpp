#include "game_overrides.h"
#include "ps2_runtime.h"
#include "ps2_stubs.h"
#include "ps2_syscalls.h"

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
                ps2_stubs::ret1(rdram, ctx, rt);
                if (ctx->pc == entryPc)
                {
                    ctx->pc = getRegU32(ctx, 31);
                }
            });
        // 0x467940: sceCdRead@0x00467940 — Cycle 5 blocker LBN 0x540000 sectors 2
        // dest a2=0x75c540 at pc=0x420020. Runtime's CD.cpp needs a CD image;
        // triage: zero-fill dest and return 1 (success) per Walkthrough §6.
        runtime.registerFunction(0x00467940u,
            [](uint8_t *rdram, R5900Context *ctx, PS2Runtime *rt)
            {
                const uint32_t entryPc = ctx->pc;
                const uint32_t dest = getRegU32(ctx, 6); // a2
                const uint32_t sectors = getRegU32(ctx, 5); // a1
                if (dest != 0 && sectors != 0 && sectors < 0x1000)
                {
                    uint8_t *host = getMemPtr(rdram, dest);
                    if (host)
                    {
                        // Zero-fill 2048*sectors for triage; real data would come from GAMEDATA.WAD LBN mapping.
                        std::memset(host, 0, sectors * 2048u);
                    }
                }
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
