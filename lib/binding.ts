const verify = (path: string, expectedSubjectName: string, expectedIssuerName: string, expectedSerialNumber: string): Promise<boolean> => {
    if (process.platform !== "win32") {
        throw new Error("verify-authenticode is not compatible with this platform");
    }
    const addon = require('../build/Release/verify-authenticode-native');
    return Promise.resolve(addon.verify(path, expectedSubjectName, expectedIssuerName, expectedSerialNumber));
};

export = { verify };
