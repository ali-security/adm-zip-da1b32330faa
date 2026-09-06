"use strict";

const { expect } = require("chai");
const zlib = require("zlib");
const Zip = require("../adm-zip");
const Utils = require("../util");

// Regression test for CVE-2026-39244:
// adm-zip allocated the entry output buffer from the attacker-declared
// uncompressed size (central-directory / local-header size field) before any
// validation. A tiny crafted archive could declare a ~4 GB size and force a
// matching Buffer.alloc, OOM-killing the process. The allocation must be bound
// by the data actually present in the archive, not by the declared size.

const u16 = (n) => {
    const b = Buffer.alloc(2);
    b.writeUInt16LE(n >>> 0);
    return b;
};
const u32 = (n) => {
    const b = Buffer.alloc(4);
    b.writeUInt32LE(n >>> 0);
    return b;
};

// Build a single-entry zip that declares `declaredSize` uncompressed bytes while
// only carrying `content` bytes of payload. `crc` defaults to 0, which is
// deliberately wrong for any real payload - the vulnerable allocation happened
// before the crc was ever checked.
function craftBomb(declaredSize, method, content, crc) {
    const name = Buffer.from("a");
    crc = crc || 0;
    const lfh = Buffer.concat([
        u32(0x04034b50),
        u16(20),
        u16(0),
        u16(method),
        u16(0),
        u16(0),
        u32(crc),
        u32(content.length),
        u32(declaredSize),
        u16(name.length),
        u16(0),
        name,
        content
    ]);
    const cd = Buffer.concat([
        u32(0x02014b50),
        u16(20),
        u16(20),
        u16(0),
        u16(method),
        u16(0),
        u16(0),
        u32(crc),
        u32(content.length),
        u32(declaredSize),
        u16(name.length),
        u16(0),
        u16(0),
        u16(0),
        u16(0),
        u32(0),
        u32(0),
        name
    ]);
    const eocd = Buffer.concat([u32(0x06054b50), u16(0), u16(0), u16(1), u16(1), u32(cd.length), u32(lfh.length), u16(0)]);
    return Buffer.concat([lfh, cd, eocd]);
}

// Largest allocation a patched read of these archives may legitimately ask for.
// The real payload is a couple of bytes and zlib works in 16 KiB chunks, so
// anything above this can only come from the attacker-declared size.
const ALLOC_BOUND = 1024 * 1024;
// An allocation this large is refused outright rather than committed, so that a
// regression reports a bounded failure instead of exhausting the test runner.
const ALLOC_GUARD = 64 * 1024 * 1024;

// Watches every Buffer allocation made while it is armed. Measuring RSS alone is
// not enough: once one test has touched gigabytes the process keeps the pages,
// so a later eager allocation no longer shows up as RSS growth.
function allocationTracker() {
    const origAlloc = Buffer.alloc;
    const origAllocUnsafe = Buffer.allocUnsafe;

    const tracker = {
        largest: 0,
        stop: function () {
            Buffer.alloc = origAlloc;
            Buffer.allocUnsafe = origAllocUnsafe;
        }
    };

    const track = function (size) {
        if (typeof size !== "number") return;
        if (size > tracker.largest) tracker.largest = size;
        if (size > ALLOC_GUARD) {
            throw new Error("refused oversized allocation of " + size + " bytes");
        }
    };

    Buffer.alloc = function (size, fill, encoding) {
        track(size);
        return origAlloc.call(Buffer, size, fill, encoding);
    };
    Buffer.allocUnsafe = function (size) {
        track(size);
        return origAllocUnsafe.call(Buffer, size);
    };

    return tracker;
}

describe("decompression bomb (declared size) - CVE-2026-39244", () => {
    const DECLARED = 3 * 1024 * 1024 * 1024; // ~3 GB, far above any plausible RSS budget
    // The async cases have to decode successfully, and the inflater forwards the
    // declared size to zlib as maxOutputLength, which every supported node
    // version must accept as a buffer length. 1.5 GB stays below the smallest
    // buffer.constants.MAX_LENGTH in the test matrix while still being an
    // allocation no process should ever be tricked into making.
    const DECLARED_ASYNC = 1536 * 1024 * 1024;

    it("does not allocate the declared size for a STORED entry", () => {
        const zip = new Zip(craftBomb(DECLARED, 0 /* STORED */, Buffer.from("A")));
        const entry = zip.getEntries()[0];
        const before = process.memoryUsage().rss;

        const alloc = allocationTracker();
        let error;
        try {
            entry.getData();
        } catch (e) {
            error = e;
        } finally {
            alloc.stop();
        }

        // invalid crc -> must throw, but crucially without committing gigabytes
        expect(error, "invalid crc must be reported").to.be.an("error");
        expect(error.message).to.match(/CRC32/);
        expect(alloc.largest, "allocation must be bounded by real data, not declared size").to.be.below(ALLOC_BOUND);
        const grewMB = (process.memoryUsage().rss - before) / (1024 * 1024);
        expect(grewMB, "RSS growth must stay bounded by real data, not declared size").to.be.below(256);
    });

    it("does not allocate the declared size for a DEFLATED entry", () => {
        const zip = new Zip(craftBomb(DECLARED, 8 /* DEFLATED */, Buffer.from([0x00])));
        const entry = zip.getEntries()[0];
        const before = process.memoryUsage().rss;

        const alloc = allocationTracker();
        let error;
        try {
            entry.getData();
        } catch (e) {
            error = e;
        } finally {
            alloc.stop();
        }

        // bogus deflate stream / crc -> must throw without a huge eager allocation
        expect(error, "a bogus deflate stream must be reported").to.be.an("error");
        expect(alloc.largest, "allocation must be bounded by real data, not declared size").to.be.below(ALLOC_BOUND);
        const grewMB = (process.memoryUsage().rss - before) / (1024 * 1024);
        expect(grewMB, "RSS growth must stay bounded by real data, not declared size").to.be.below(256);
    });

    it("does not allocate the declared size for a STORED entry read asynchronously", (done) => {
        const payload = Buffer.from("A");
        const zip = new Zip(craftBomb(DECLARED_ASYNC, 0 /* STORED */, payload, Utils.crc32(payload)));
        const entry = zip.getEntries()[0];

        // the vulnerable allocation happened synchronously, before the method
        // switch, so the tracker only has to cover the synchronous call
        const alloc = allocationTracker();
        let result, error;
        try {
            entry.getDataAsync(function (data, err) {
                result = data;
                error = err;
            });
        } finally {
            alloc.stop();
        }

        expect(alloc.largest, "allocation must be bounded by real data, not declared size").to.be.below(ALLOC_BOUND);
        expect(error, "a stored entry with a valid crc must decode without error").to.equal(undefined);
        expect(result.equals(payload)).to.equal(true);
        done();
    });

    it("does not allocate the declared size for a DEFLATED entry read asynchronously", (done) => {
        const payload = Buffer.from("A");
        const zip = new Zip(craftBomb(DECLARED_ASYNC, 8 /* DEFLATED */, zlib.deflateRawSync(payload), Utils.crc32(payload)));
        const entry = zip.getEntries()[0];

        const alloc = allocationTracker();
        try {
            entry.getDataAsync(function (data, err) {
                try {
                    expect(err, "a deflated entry with a valid crc must decode without error").to.equal(undefined);
                    expect(data.equals(payload)).to.equal(true);
                    done();
                } catch (e) {
                    done(e);
                }
            });
        } finally {
            alloc.stop();
        }

        expect(alloc.largest, "allocation must be bounded by real data, not declared size").to.be.below(ALLOC_BOUND);
    });

    it("still reads a legitimate STORED entry", () => {
        const zip = new Zip();
        zip.addFile("s.bin", Buffer.from([1, 2, 3, 4, 5]));
        const round = new Zip(zip.toBuffer());
        expect([...round.readFile("s.bin")]).to.eql([1, 2, 3, 4, 5]);
    });

    it("still reads a legitimate DEFLATED entry", () => {
        const zip = new Zip();
        const payload = Buffer.from("hello world ".repeat(5000));
        zip.addFile("d.txt", payload);
        const round = new Zip(zip.toBuffer());
        expect(round.readFile("d.txt").equals(payload)).to.equal(true);
    });
});
