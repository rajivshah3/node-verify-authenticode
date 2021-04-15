const VerifyAuthenticode = require("../dist/binding.js");
const fs = require("fs");
const assert = require("assert");

assert(VerifyAuthenticode.verify, "The expected function is undefined");

function testBasic()
{
    const path = "C:\\Users\\rajiv\\Downloads\\firefly-desktop-0.3.1.exe";
    assert(fs.statSync(path), "Path does not exist");
    const result = VerifyAuthenticode.verify(path, "IOTA Stiftung", "DigiCert SHA2 Assured ID Code Signing CA", "01 7e 53 37 de ca 4c 60 bd 18 81 e2 09 7e bd 3b");
    assert.strictEqual(result, true, "Unexpected value returned");
}

assert.doesNotThrow(testBasic, undefined, "testBasic threw an expection");

console.log("Tests passed - everything looks OK!");