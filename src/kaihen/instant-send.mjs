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
    // (entry20 kept for reference; the own-entry copy needs no staging)
    const slots = arenaSlots(context);
    const info = arenaAlloc(context, 0x2000, "is-info");
    buildCmif(slots.pkt, {cmd: 0,
        input: [1, 3, 0, 0, 0, 0, 0, 0].concat(u64Bytes(BigInt(title))),
        b: [{addr: info + 32n, size: 0x1a4}]});

    // The reference copies ITS OWN pid-initialized, promoted root through
    // its inspection domain (app/domain.cjs openDomain: fresh fsp-srv ->
    // cmd1+{pid:true} init -> ConvertToDomain; domain-copy then copies the
    // OWN object). Borrowing the LOADER's object instead binds the copy to
    // the Loader's process — every pid-touching command (init, code-open)
    // mismatches the requester and the server kills the session (runs
    // 48-61). The borrow was the fatal substitute all along: copy our own
    // entry, no borrow, no restore.
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
        await khLog("IS1 copy-own rc=" + hex(copyRc) +
            " handle=" + hex(copyHandle));
        if (copyHandle) {
            // Our inspection domain was never pid-initialized (the
            // reference's openDomain sends cmd1+{pid:true} BEFORE
            // ConvertToDomain) — so the copy inherits no binding. Init the
            // copy for real: cmd 1, u64(0), pid descriptor. On our OWN
            // root this binds the session to us (run61's kill was the
            // Loader-object binding mismatch).
            buildCmif(slots.pkt2, {cmd: 1, input: u64Bytes(0n), pid: true});
            const init = bareSendTransport(copyHandle, slots.pkt2);
            let initR = "-";
            if (init === 0) initR = hex(cmifReply(slots.pkt2).result);
            // The reference's working code-open (5T5Brx launch record,
            // steps[].request) is a TYPE 6 RequestWithContext: w0=6|counts,
            // B-descriptor, 4-word context {token 0x00X00001, pid, 0, 0},
            // then SFCI + version(1) + cmd + input. Type 4 code-opens kill
            // the session; the SDK speaks WithContext natively.
            const pkt = slots.pkt;
            for (let i = 0n; i < 0x100n; i += 8n)
                runtime.write64(pkt + i, 0n);
            runtime.write32(pkt, BigInt((0x6 | (1 << 24)) >>> 0));   // type 6, 1 B
            runtime.write32(pkt + 4n, 0x10n);                          // 16 words
            const infoAddr = BigInt(info);
            runtime.write32(pkt + 8n, 0x1a4n);                         // B size
            runtime.write32(pkt + 12n,
                BigInt(Number(infoAddr & 0xffffffffn)));
            const bflags = (((infoAddr >> 32n) & 0xfn) << 28n) |
                (((infoAddr >> 36n) & 7n) << 2n);                      // mode 0
            runtime.write32(pkt + 16n, BigInt(Number(bflags)));
            runtime.write32(pkt + 0x20n, 0x00200001n);                 // context token
            runtime.write32(pkt + 0x24n, 9n);                          // pid 9
            runtime.write32(pkt + 0x28n, 0n);
            runtime.write32(pkt + 0x2cn, 0n);
            runtime.write32(pkt + 0x30n, 0x49434653n);                 // SFCI
            runtime.write32(pkt + 0x34n, 1n);                          // version
            runtime.write32(pkt + 0x38n, 0n);                          // cmd 0
            runtime.write32(pkt + 0x3cn, 0n);
            runtime.write32(pkt + 0x40n, 0x0301n);                     // attrs 1, storage 3
            runtime.write32(pkt + 0x44n, 0n);
            runtime.write64(pkt + 0x48n, BigInt(title));
            const t2 = bareSendTransport(copyHandle, pkt);
            let d2 = "-", parsed = null;
            if (t2 !== 0) {
                d2 = hex(Number(sendIPC(copyHandle, pkt)) >>> 0);
            } else parsed = cmifReply(pkt);
            await khLog("IS2 init=" + hex(init) + "/" + initR +
                " code-open(t6)=" + hex(t2) + " disp=" + d2 +
                (parsed ? " result=" + hex(parsed.result) +
                    " moves=" + (parsed.moves ? parsed.moves.length : 0) : ""));
            if (parsed && parsed.result === 0 && parsed.moves &&
                    parsed.moves.length) {
                context.instantCodeFs = track(context, parsed.moves[0],
                    "is-codefs");
                await khLog("IS3 ***CODE FS OPEN*** handle=" +
                    hex(context.instantCodeFs));
            }
        }
    } finally {
        // No borrow was taken — nothing to restore.
    }
    // Retain the copied root when the code-open lived (the reference keeps
    // its copied roots for later code-opens); close only the dead ones.
    if (copyHandle && !context.instantCodeFs)
        try { runtime.closeHandle(copyHandle); }
        catch (error) { /* dead */ }
    return {ok: true};
}
