"use strict";

const { expect } = require("chai");
const Zip = require("../adm-zip");

describe("zip64", () => {
    it("writes and reads archives with more than 65535 entries", function () {
        // building/reading 65536 entries is slow on the oldest supported node
        // versions in the CI matrix, so allow generous headroom
        this.timeout(60000);

        const entryCount = 0x10000;
        const zip = new Zip({ noSort: true });

        for (let i = 0; i < entryCount; i++) {
            zip.addFile(`file-${i}.txt`, "");
        }

        const buffer = zip.toBuffer();
        const readZip = new Zip(buffer);

        expect(readZip.getEntries()).to.have.lengthOf(entryCount);
    });
});
