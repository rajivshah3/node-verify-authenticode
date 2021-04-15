const VerifyAuthenticode = require("../dist/binding.js");
const fs = require("fs");
const assert = require("assert");
const os = require("os");

assert(VerifyAuthenticode.verify, "The expected function is undefined");

async function testBasic() {
    let path = "C:\\Users\\rajiv\\Downloads\\firefly-desktop-0.3.1.exe";
    if (process.env.CI) {
        path = `${os.tmpdir()}\\test-file.exe`;
    }
    assert(fs.statSync(path), "Path does not exist");
    const result = await VerifyAuthenticode.verify(
        path,
        "IOTA Stiftung",
        "DigiCert SHA2 Assured ID Code Signing CA",
        "01 7e 53 37 de ca 4c 60 bd 18 81 e2 09 7e bd 3b"
    );
    assert.strictEqual(result, true, "Unexpected value returned");
}

assert.doesNotReject(testBasic, undefined, "testBasic threw an expection")
    .then(() => console.log("Tests passed - everything looks OK!"));
