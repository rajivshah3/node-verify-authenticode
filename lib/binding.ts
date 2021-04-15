const addon = require('../build/Release/verify-authenticode-native');

const verify = (path: string, expectedSubjectName: string, expectedIssuerName: string, expectedSerialNumber: string): Promise<boolean> => {
    return Promise.resolve(addon.verify(path, expectedSubjectName, expectedIssuerName, expectedSerialNumber));
};

export = { verify };
