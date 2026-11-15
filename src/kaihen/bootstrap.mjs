// kaiHEN port — the bootstrap NRO: 432-byte argument block (start-hen.cjs
// layout), the image build (bootstrap.bin + Civ7 trywait adapter), launch on
// a raw thread through the RO frontend, and the startup-record readback.

import runtime from "../core/runtime.mjs";
import {check, khLog, hex, readU64LE, readU32LE, readNative,
    writeNative, writeU64LE, arenaAlloc, arenaSlots, HEN_TITLE, RO_TITLE}
    from "./state.mjs";
import {buildNroImage, tryWaitAdapterBytes, runNroOnRawThread} from "./ro.mjs";
import {sdReadFile, openSdCard} from "./sdcard.mjs";

// thread-code.json (game SDK).
export const PTHREAD = {
    create: 0x142180, join: 0x142480, tryWait: 0x137110,
    handleForm: "tagged", tagMask: 7
};

const ARG_BYTES = 432;

function hexToBytes(text) {
    const out = [];
    for (let i = 0; i + 1 < text.length; i += 2)
        out.push(parseInt(text.substr(i, 2), 16));
    return out;
}

export async function runBootstrap(context, options = {}) {
    // Load bootstrap.bin from the staged SD file.
    const sd = openSdCard(context);
    const staged = globalThis.__KH_MANIFEST.bootstrap;
    const bootstrapFile = sdReadFile(context, sd, staged.path, 0x100000);
    let text = bootstrapFile.bytes;
    check(text.length <= 0xff80,
        "bootstrap.bin exceeds the NRO text segment: " + text.length);

    // Append the Civ7 trywait adapter after the unmodified text.
    const adapterOffset = (text.length + 15) & ~15;
    const adapter = tryWaitAdapterBytes(Number(sdk_base) + PTHREAD.tryWait);
    const padded = text.concat(new Array(adapterOffset - text.length).fill(0));
    text = padded.concat(adapter);
    context.tryWaitAdapter = {offset: adapterOffset,
        target: Number(sdk_base) + PTHREAD.tryWait};

    const image = buildNroImage(text);
    check(image.length === 0x12000, "NRO image size differs");

    const args = buildBootstrapArgs(context, options);
    const argsAddress = arenaAlloc(context, ARG_BYTES + 0x40, "bootstrap-args");
    context.bootstrapArgsAddress = Number(argsAddress);

    const result = await runNroOnRawThread(context, image, argsAddress,
        args.bytes, {
            waitMs: options.waitMs || 90000,
            patchArgs: async (address, destination) => {
                // The ldr:ro session handle joins late; the adapter lives at
                // entry + adapterOffset inside the mapped image.
                args.u32(292, context.ro.handle);
                args.u64(272, Number(destination) + 0x80 +
                    context.tryWaitAdapter.offset);
                writeNative(address, args.bytes);
            }
        });
    check(result.returned === 0,
        "bootstrap returned error " + result.returned);

    // The bootstrap published its record at args+408.
    const recordBytes = readNative(argsAddress + 408n, 24);
    const record = {
        operation: readU32LE(recordBytes, 0),
        result: readU32LE(recordBytes, 4),
        pid: readU64LE(recordBytes, 8).toString(),
        gateRestoreResult: readU32LE(recordBytes, 16),
        channelRestoreResult: readU32LE(recordBytes, 20)
    };
    check(record.operation === 10,
        "startup operation " + record.operation + " did not reach Complete");
    check(record.result === 0,
        "startup operation " + record.operation + " failed: 0x" +
        record.result.toString(16));
    const gatePending = record.gateRestoreResult === 0xea01;
    check(record.gateRestoreResult === 0 || gatePending,
        "gate restore failed: " + hex(record.gateRestoreResult));
    check(record.channelRestoreResult === 0,
        "channel restore failed: " + hex(record.channelRestoreResult));
    record.gateRestorePending = gatePending;
    context.henStartup = record;
    await khLog("HEN startup record: operation=" + record.operation +
        " result=" + record.result + " pid=" + record.pid +
        " gateRestore=" + hex(record.gateRestoreResult) +
        (gatePending ? " (receipt transferred to HEN)" : ""));
    return record;
}

export function buildBootstrapArgs(context, options = {}) {
    const launch = context.launch;
    const loaderDomain = context.loaderRoot.domain;
    const row = context.bound.rows.find(r => r.domain === loaderDomain);
    const donor = context.donorRow;
    const layout = context.layout;
    const event = context.gateEvent;
    const exported = context.loaderServerExport;
    check(row && donor && event && exported && exported.handle,
        "bootstrap args need the launch session, donor, event, and export");
    check(context.apiWorkers && context.apiWorkers.length === 7,
        "bootstrap args need the seven API workers");

    const bytes = new Array(ARG_BYTES).fill(0);
    const u32 = (offset, value) => {
        bytes[offset] = value & 0xff; bytes[offset + 1] = value >> 8 & 0xff;
        bytes[offset + 2] = value >> 16 & 0xff;
        bytes[offset + 3] = value >>> 24;
    };
    const u64 = (offset, value) => writeU64LE(bytes, offset, BigInt(value));
    const rowVptr = readU64LE(hexToBytes(row.raw), 0);

    u32(0, context.candidateHandle);
    u64(8, context.state.endpoint.dataOffset);              // channel data
    u64(16, context.state.endpoint.dataEntryOffset + 0x20); // pointer field
    // gate: row address, vptr, domain, metadata, request, then 7 waiters.
    u64(24, row.address);
    u64(32, rowVptr);
    u64(40, row.domain);
    u64(48, row.metadata);
    u64(56, row.request);
    layout.waiters.forEach((address, index) => u64(64 + index * 8, address));
    context.apiWorkers.forEach((worker, index) => u32(120 + index * 4, worker.handle));
    [row.receive, row.wait, event.sourceHandle, exported.handle,
        event.read, event.write].forEach((value, index) => u32(148 + index * 4, value));
    // mount: table, loader domain, loader entry index, donor row, title.
    u64(176, layout.table);
    u64(184, loaderDomain);
    u64(192, (context.loaderRoot.entry - layout.table) / 0x30 + 1);
    u64(200, donor.entry);
    u64(208, donor.object);
    u64(216, donor.metadata);
    u64(224, donor.vptr);
    u64(232, HEN_TITLE);
    u32(240, context.pm.shell);
    u64(248, HEN_TITLE);
    u32(256, 0x14);
    bytes[260] = 3;
    u32(244, context.pm.monitor);
    u64(264, Number(sdk_base) + PTHREAD.create);
    u64(272, Number(sdk_base) + PTHREAD.tryWait); // replaced by the adapter
    u64(280, Number(sdk_base) + PTHREAD.join);
    u32(288, context.pm.sm);
    // fsRoot: the DEDICATED pid-initialized fsp-srv session — the author's
    // root-open (fresh openService + Initialize). The bootstrap issues
    // plain fsp-srv commands (cmd 10/18/51) on it and needs the pid
    // binding (run109: the uninitialized promoted clone returned 0xF601).
    u32(296, context.fsRootDedicated);
    const packagePath = "@Sdcard:/ouncehen/bin/hen/exefs.nsp";
    for (let i = 0; i < packagePath.length; i++)
        bytes[300 + i] = packagePath.charCodeAt(i);
    u32(396, context.fsProcess.handle);
    u32(400, context.notifier.handle);
    u32(404, context.loaderCopy.handle);

    return {bytes, u32, u64};
}
