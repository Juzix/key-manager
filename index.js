var keythereum = require("keythereum");
var path = require("path");
var fs = require("fs-extra");
var createKeccakHash = require("keccak/js");
var os = require('os');
var secp256k1 = require("secp256k1/elliptic");
var ffi = require('ffi');
var ref = require('ref');

var params = {
    keyBytes: 32,
    ivBytes: 16
};

var options = {
    kdf: "pbkdf2",
    cipher: "aes-128-ctr",
    kdfparams: {
        c: 262144,
        dklen: 32,
        prf: "hmac-sha256"
    }
};

const DEFAULT_PATH = path.join(os.homedir(), 'keystores');

var ukey = null;
var dwordPoint = ref.refType(ref.types.ulong);
if (os.platform() === 'win32') {
    var dllName = (os.arch() === 'x64') ? ('WDJuZhenAPIx64') : ('WDJuZhenAPIx86');
    var dllPath = path.join(__dirname, 'dynamic', dllName);
    ukey = ffi.Library(dllPath, {
        'J_BC_WD_OpenDevice': ['int', []],  // 01 √
        'J_BC_WD_CloseDevice': ['int', []],  // 02 √
        'J_BC_WD_VerifyPin': ['int', ['string', 'int']],  // 03 √
        'J_BC_WD_RSAGenKey': ['int', []],  // 04 √
        'J_BC_WD_ECCGenKey': ['int', []],  // 05 √
        'J_BC_WD_RSAGetPubKey': ['int', ['string', dwordPoint]],  // 06 √
        'J_BC_WD_ECCGetPubKey': ['int', ['string', dwordPoint]],  // 07 √
        'J_BC_WD_ImportRSACert': ['int', ['string']],  // 08 √
        'J_BC_WD_ExPortRSACert': ['int', ['string', dwordPoint]],  // 09 √
        'J_BC_WD_RSAEncrypt': ['int', ['string', 'int', 'string', dwordPoint]],  // 10 √
        'J_BC_WD_RSASign': ['int', ['int', 'string', 'int', 'string', dwordPoint]],  // 11 √
        'J_BC_WD_ECCSign': ['int', ['string', 'int', 'string', dwordPoint]],  // 12 √
        'J_BC_WD_RSAVerifySign': ['int', ['int', 'string', 'int', 'string']], // 13 × 
        'J_BC_WD_ECCVerifySign': ['int', ['string']],  // 14 √
        'J_BC_BE_Enc': ['int', ['string', 'int', 'int', 'string', 'string', dwordPoint]],  // 15 √
        'J_BC_BE_Dec': ['int', ['string', 'int', 'int', 'string', dwordPoint]],  // 16 ×
        'J_BC_GS_CheckKeyPair': ['int', []],  // 17 √
        'J_BC_GS_ImportMPubKey': ['int', ['string', 'int']],  // 18 √
        'J_BC_GS_ImportUPriKey': ['int', ['string', 'int']],  // 19 ×
        'J_BC_GS_Sign': ['int', ['string', 'int', 'string', dwordPoint]],  // 20 ×
        'J_BC_GS_Verify': ['int', ['string', 'int', 'string', 'int']],  // 21 ×
        'J_BC_WD_TradeSignProtect': ['int', ['string', 'int', 'int', 'string', 'string', dwordPoint]],  // 22 √
        'WDScardEncrypt_ECIES': ['int', ['string', 'int', 'string', dwordPoint]],  // 23 √
        'WDScardDecrypt_ECIES': ['int', ['string', 'int', 'string', dwordPoint]],  // 24 ×
    });
}

function keccak256(buffer) {
    return createKeccakHash("keccak256").update(buffer).digest();
}

function isFunction(f) {
    return typeof f === "function";
}

function c(err) {
    switch (err) {
        case null: return -100;
        case 1: return 0;
        case 0: return 1;
        default: return err;
    }
}

module.exports = {
    // 01 J_BC_WD_OpenDevice ()
    ukeyOpenDevice: function (cb) {
        var err = c(ukey && ukey.J_BC_WD_OpenDevice());
        var ret = {
            err: err,
        }
        isFunction(cb) && cb(err, ret);
        return ret;
    },
    // 02 J_BC_WD_CloseDevice()
    ukeyCloseDevice: function (cb) {
        var err = c(ukey && ukey.J_BC_WD_CloseDevice());
        var ret = {
            err: err,
        }
        isFunction(cb) && cb(err, ret);
        return ret;
    },
    // 03 J_BC_WD_VerifyPin (IN BYTE *pbUserPin,IN DWORD dwUserPinLen)
    ukeyVerifyPin: function (pbUserPin, cb) {
        var dwUserPinLen = pb.pbUserPin.length;
        var err = c(ukey && ukey.J_BC_WD_VerifyPin(pbUserPin, dwUserPinLen));
        var ret = {
            err: err,
        }
        isFunction(cb) && cb(err, ret);
        return ret;
    },
    // 04 J_BC_WD_RSAGenKey ()
    ukeyRSAGenKey: function (cb) {
        var err = c(ukey && ukey.J_BC_WD_RSAGenKey());
        var ret = {
            err: err,
        }
        isFunction(cb) && cb(err, ret);
        return ret;
    },
    // 05 J_BC_WD_ECCGenKey ()
    ukeyECCGenKey: function (cb) {
        var err = c(ukey && ukey.J_BC_WD_ECCGenKey());
        var ret = {
            err: err,
        }
        isFunction(cb) && cb(err, ret);
        return ret;
    },
    // 06 J_BC_WD_RSAGetPubKey ( OUT BYTE *pbPubKey, OUT DWORD *pdwPubKeyLen)
    ukeyRSAGetPubKey: function (cb) {
        var pbPubKey = Buffer.alloc(512);
        var pdwPubKeyLen = ref.alloc('ulong');
        pdwPubKeyLen.writeUInt32LE(512);

        var err = c(ukey && ukey.J_BC_WD_RSAGetPubKey(pbPubKey, pdwPubKeyLen));
        if (err === 0) {
            pdwPubKeyLen = pdwPubKeyLen.readUInt32LE();
            pbPubKey = pbPubKey.toString('hex', 0, pdwPubKeyLen);
        }

        var ret = {
            err: err,
            pbPubKey: pbPubKey,
            // pdwPubKeyLen: pdwPubKeyLen,
        }
        isFunction(cb) && cb(err, ret);
        return ret;
    },
    // 07 J_BC_WD_ECCGetPubKey (OUT BYTE *pbPubKey, OUT DWORD *pdwPubKeyLen);
    ukeyECCGetPubKey: function (cb) {
        var pbPubKey = Buffer.alloc(512);
        var pdwPubKeyLen = ref.alloc('ulong');
        pdwPubKeyLen.writeUInt32LE(512);

        var err = c(ukey && ukey.J_BC_WD_ECCGetPubKey(pbPubKey, pdwPubKeyLen));
        if (err === 0) {
            pdwPubKeyLen = pdwPubKeyLen.readUInt32LE();
            pbPubKey = pbPubKey.toString('hex', 0, pdwPubKeyLen);
        }

        var ret = {
            err: err,
            pbPubKey: pbPubKey,
            // pdwPubKeyLen: pdwPubKeyLen,
        }
        isFunction(cb) && cb(err, ret);
        return ret;
    },
    // 08 J_BC_WD_ImportRSACert( IN BYTE *pbCert)
    ukeyImportRSACert: function (pbCert, cb) {
        var err = c(ukey && ukey.J_BC_WD_ImportRSACert(pbCert));
        var ret = {
            err: err,
        }
        isFunction(cb) && cb(err, ret);
        return ret;
    },
    // 09 J_BC_WD_ExPortRSACert( OUT BYTE *pbCert,OUT DWORD *pdwCertLen);
    ukeyExPortRSACert: function (cb) {
        var pbCert = Buffer.alloc(128);
        var pdwCertLen = ref.alloc('ulong');
        pdwCertLen.writeUInt32LE(128);
        var err = c(ukey && ukey.J_BC_WD_ExPortRSACert(pbCert, pdwCertLen));
        if (err === 0) {
            pdwCertLen = pdwCertLen.readUInt32LE();
            pbCert = pbCert.toString('hex', 0, pdwCertLen);
        }
        var ret = {
            err: err,
            pbCert: pbCert,
            // pdwCertLen: pdwCertLen,
        }
        isFunction(cb) && cb(err, ret);
        return ret;
    },
    // 10 J_BC_WD_RSAEncrypt(IN BYTE *pbData, IN DWORD dwDataLen, OUT BYTE*pbCipher, OUT DWORD* pdwCipherLen)
    ukeyRSAEncrypt: function (pbData, cb) {
        var dwDataLen = pbData.length;
        var pbCipher = Buffer.alloc(512);
        var pdwCipherLen = ref.alloc('ulong');
        pdwCipherLen.writeUInt32LE(512);

        var err = c(ukey && ukey.J_BC_WD_RSAEncrypt(pbData, dwDataLen, pbCipher, pdwCipherLen));
        if (err === 0) {
            pdwCipherLen = pdwCipherLen.readUInt32LE();
            pbCipher = pbCipher.toString('hex', 0, pdwCipherLen);
        }
        var ret = {
            err: err,
            pbCipher: pbCipher,
            // pdwCipherLen: pdwCipherLen,
        }
        isFunction(cb) && cb(err, ret);
        return ret;
    },
    // 11 J_BC_WD_RSASign (IN DWORD dwHashAlg, IN BYTE* pbData, IN DWORD dwDataLen, OUT BYTE* pbSign, OUT DWORD* pdwSignLen)
    ukeyRSASign: function (dwHashAlg, pbData) {
        var dwDataLen = pbData.length;
        var pbSign = Buffer.alloc(512);
        var pdwSignLen = ref.alloc('ulong');
        pdwSignLen.writeUInt32LE(pbSign.length);

        var err = c(ukey && ukey.J_BC_WD_RSASign(dwHashAlg, pbData, dwDataLen, pbSign, pdwSignLen));
        if (err === 0) {
            pdwSignLen = pdwSignLen.readUInt32LE();
            pbSign = pbSign.toString('hex', 0, pdwSignLen);
        }
        var ret = {
            err: err,
            pbSign: pbSign,
            // pdwSignLen: pdwSignLen,
        }

        isFunction(cb) && cb(err, ret);
        return ret;
    },
    // 12 J_BC_WD_ECCSign (IN BYTE* pbMsgRlp,IN DWORD dwMsgRlpLen, OUT BYTE*pbSignRlp, OUT DWORD*pdwSignLen);
    ukeyECCSign: function (pbMsgRlp) {
        var pbMsgRlp = Buffer.from(pbMsgRlp, 'hex');
        var dwMsgRlpLen = pbMsgRlp.length;
        var pbSignRlp = Buffer.alloc(1024);
        var pdwSignLen = ref.alloc('ulong');
        pdwSignLen.writeUInt32LE(pbSignRlp.length);

        var err = c(ukey && ukey.J_BC_WD_ECCSign(pbMsgRlp, dwMsgRlpLen, pbSignRlp, pdwSignLen));
        if (err === 0) {
            pdwSignLen = pdwSignLen.readUInt32LE();
            pbSignRlp = pbSignRlp.toString('hex', 0, pdwSignLen);
        }
        var ret = {
            err: err,
            pbSignRlp: pbSignRlp,
            // pdwSignLen: pdwSignLen,
        }

        isFunction(cb) && cb(err, ret);
        return ret;
    },
    // 13 J_BC_WD_RSAVerifySign(IN DWORD dwHashAlg, IN  BYTE* pbData, IN DWORD dwDataLen, IN BYTE* pbSign); 注释跟头文件生命不一致
    ukeyRSAVerifySign: function (dwHashAlg, pbData, pbSign) {
        pbData = Buffer.from(pbData, 'hex');
        dwDataLen = pbData.length;
        pbSign = Buffer.from(pbSign, 'hex');

        var err = c(ukey && ukey.J_BC_WD_RSAVerifySign(dwHashAlg, pbData, dwDataLen, pbSign));

        var ret = {
            err: err,
        }

        isFunction(cb) && cb(err, ret);
        return ret;
    },
    // 14 J_BC_WD_ECCVerifySign(IN BYTE* pbSignRlp)
    ukeyECCVerifySign: function (pbSignRlp) {
        pbSignRlp = Buffer.from(pbSignRlp, 'hex');
        var err = c(ukey && ukey.J_BC_WD_ECCVerifySign(pbSignRlp));
        var ret = {
            err: err,
        }
        isFunction(cb) && cb(err, ret);
        return ret;
    },
    // 15 J_BC_BE_Enc(IN BYTE*pbMessage, IN DWORD dwMessage_Len, IN DWORD dwGroupNum, IN BYTE*pbGroup_PubKey, OUT BYTE*pbCipherText, OUT DWORD *pdwCipherText_Len)
    ukeyEnc: function (pbMessage, dwGroupNum, pbGroup_PubKey) {
        pbMessage = Buffer.from(pbMessage, 'hex');
        var dwMessage_Len = pbMessage.length;
        pbGroup_PubKey = Buffer.from(pbGroup_PubKey, 'hex');
        var pbCipherText = Buffer.alloc(512);
        var pdwCipherText_Len = ref.alloc('ulong');
        pdwCipherText_Len.writeUInt32LE(pbCipherText.length);

        var err = c(ukey && ukey.J_BC_BE_Enc(pbMessage, dwMessage_Len, dwGroupNum, pbGroup_PubKey, pbCipherText, pdwCipherText_Len));
        if (err === 0) {
            pdwCipherText_Len = pdwCipherText_Len.readUInt32LE();
            pbCipherText = pbCipherText.toString('hex', 0, pdwCipherText_Len);
        }
        var ret = {
            err: err,
            pbCipherText: pbCipherText,
        }
        isFunction(cb) && cb(err, ret);
        return ret;
    },
    // 16 J_BC_BE_Dec(IN BYTE*pbCipherText, IN DWORD dwCipherText_Len, IN DWORD dwGroupNum, OUT BYTE*pbMessage, OUT DWORD*pdwMessage_Len)
    ukeyDec: function (pbCipherText, dwGroupNum) {
        pbCipherText = Buffer.from(pbCipherText, 'hex');
        var dwCipherText_Len = pbCipherText.length;
        var pbMessage = Buffer.alloc(1024);
        var pdwMessage_Len = ref.alloc('ulong');
        pdwMessage_Len.writeUInt32LE(1024);

        var err = c(ukey && ukey.J_BC_BE_Dec(pbCipherText, dwCipherText_Len, dwGroupNum, pbMessage, pdwMessage_Len));
        if (err === 0) {
            pdwMessage_Len = pdwMessage_Len.readUInt32LE();
            pbMessage = pbMessage.toString('hex', 0, pdwMessage_Len);
        }
        var ret = {
            err: err,
            pbMessage: pbMessage,
        }
        isFunction(cb) && cb(err, ret);
        return ret;
    },
    // 17 J_BC_GS_CheckKeyPair()
    ukeyCheckKeyPair: function () {
        var err = c(ukey && ukey.J_BC_GS_CheckKeyPair());
        var ret = {
            err: err,
        }
        isFunction(cb) && cb(err, ret);
        return ret;
    },
    // 18 J_BC_GS_ImportMPubKey(IN BYTE* pbMPubKey,IN DWORD dwMPubKey)
    ukeyImportMPubKey: function (pbMPubKey) {
        pbMPubKey = Buffer.from(pbMPubKey, 'hex');
        var dwMPubKey = pbMPubKey.length;
        var err = c(ukey && ukey.J_BC_GS_ImportMPubKey());
        var ret = {
            err: err,
        }
        isFunction(cb) && cb(err, ret);
        return ret;
    },
    // 19 J_BC_GS_ImportUPriKey(IN BYTE  *pbUPriKey,IN DWORD dwUPriKey)
    ukeyImportUPriKey: function (pbUPriKey) {
        var pbUPriKey = Buffer.from(tmp, 'hex');
        var dwUPriKey = pbUPriKey.length;
        var err = c(ukey && ukey.J_BC_GS_ImportUPriKey());
        var ret = {
            err: err,
        }
        isFunction(cb) && cb(err, ret);
        return ret;
    },
    // 20 J_BC_GS_Sign(IN BYTE* pbHash, IN DWORD dwHash, OUT BYTE*pbSign, OUT DWORD* pdwSignLen)
    ukeyGSSign: function (pbHash) {
        pbHash = Buffer.from(pbHash, 'hex');
        var dwHash = pbHash.length;
        var pbSign = Buffer.alloc(512);
        var pdwSignLen = ref.alloc('ulong');
        pdwSignLen.writeUInt32LE(pbSign.length);

        var err = c(ukey && ukey.J_BC_GS_Sign(pbHash, dwHash, pbSign, pdwSignLen));
        if (err === 0) {
            pdwSignLen = pdwSignLen.readUInt32LE();
            pbSign = pbSign.toString('hex', 0, pdwSignLen);
        }
        var ret = {
            err: err,
            pbSign: pbSign,
        }
        isFunction(cb) && cb(err, ret);
        return ret;
    },
    // 21 J_BC_GS_Verify(IN BYTE* pbHash, IN DWORD dwHash, IN BYTE* pbSign, IN DWORD dwSignLen)
    ukeyGSVerify: function (pbHash, pbSign) {
        pbHash = Buffer.from(pbHash, 'hex');
        var dwHash = pbHash.length;
        pbSign = Buffer.from(pbSign, 'hex');
        var pdwSignLen = pbSign.length;

        var err = c(ukey && ukey.J_BC_GS_Verify(pbHash, dwHash, pbSign, pdwSignLen));
        var ret = {
            err: err,
        }
        isFunction(cb) && cb(err, ret);
        return ret;
    },
    // 22 J_BC_WD_TradeSignProtect(IN  BYTE *pbMsg, IN DWORD dwMsg, IN DWORD dwGroupNum, IN BYTE *pbGroup_PubKey, OUT BYTE *pbSign, OUT DWORD *pdwSignLen)
    ukeyTradeSignProtect: function (pbMsg, dwGroupNum, pbGroup_PubKey) {
        pbMsg = Buffer.from(pbMsg, 'hex');
        var dwMsg = pbMsg.length;
        dwGroupNum = Buffer.from(dwGroupNum, 'hex');
        var pbSign = Buffer.alloc(1024);
        var pdwSignLen = ref.alloc('ulong');
        pdwSignLen.writeUInt32LE(pbSign.length);

        var err = c(ukey && ukey.J_BC_WD_TradeSignProtect(pbMsg, dwMsg, dwGroupNum, pbGroup_PubKey, pbSign, pdwSignLen));
        if (err === 0) {
            pdwSignLen = pdwSignLen.readUInt32LE();
            pbSign = pbSign.toString('hex', 0, pdwSignLen);
        }
        var ret = {
            err: err,
            pbSign: pbSign,
        }
        isFunction(cb) && cb(err, ret);
        return ret;
    },
    // 23 WDScardEncrypt_ECIES(IN LPBYTE pbData, IN DWORD dwDataLen, OUT LPBYTE pbEncryptedData, OUT LPDWORD pdwEncryptedDataLen);
    ukeyWDScardEncryptECIES: function (pbData) {
        pbData = Buffer.from(tmp, 'hex');
        var dwDataLen = pbData.length;
        var pbEncryptedData = Buffer.alloc(1024);
        var pdwEncryptedDataLen = ref.alloc('ulong');
        pdwEncryptedDataLen.writeUInt32LE(pbEncryptedData.length);

        var err = c(ukey && ukey.WDScardEncrypt_ECIES(pbData, dwDataLen, pbEncryptedData, pdwEncryptedDataLen));
        if (err === 0) {
            pdwEncryptedDataLen = pdwEncryptedDataLen.readUInt32LE();
            pbEncryptedData = pbEncryptedData.toString('hex', 0, pdwEncryptedDataLen);
        }
        var ret = {
            err: err,
            pbEncryptedData: pbEncryptedData,
        }
        isFunction(cb) && cb(err, ret);
        return ret;
    },
    // 24 WDScardDecrypt_ECIES(IN LPBYTE pbEncryptedData, IN DWORD dwEncryptedDataLen, OUT LPBYTE pbDecryptedData, OUT PDWORD pdwDecryptedDataLen)
    ukeyWDScardDecryptECIES: function (pbEncryptedData) {
        pbEncryptedData = Buffer.from(pbEncryptedData, 'hex');
        var dwEncryptedDataLen = pbEncryptedData.length;
        var pbDecryptedData = Buffer.alloc(1024);
        var pdwDecryptedDataLen = ref.alloc('ulong');
        pdwDecryptedDataLen.writeUInt32LE(pbDecryptedData.length);

        var err = c(ukey && ukey.ukey.WDScardEncrypt_ECIES(pbEncryptedData, dwEncryptedDataLen, pbDecryptedData, pdwDecryptedDataLen));
        if (err === 0) {
            pdwDecryptedDataLen = pdwDecryptedDataLen.readUInt32LE();
            pbDecryptedData = pbDecryptedData.toString('hex', 0, pdwDecryptedDataLen);
        }
        var ret = {
            err: err,
            pbDecryptedData: pbDecryptedData,
        }
        isFunction(cb) && cb(err, ret);
        return ret;
    },

    // 以下为文件证书函数
    browser: typeof process === "undefined" || !process.nextTick || Boolean(process.browser),
    setParams: function (_params) {
        params = _params;
    },
    getParams: function () {
        return params;
    },
    setOption: function (_options) {
        options = _options;
    },
    getOption: function () {
        return options;
    },
    createDk: function (cb) {
        err = 0;
        if (isFunction(cb)) {
            keythereum.create(this.getParams(), function (dk) {
                if (!dk) {
                    err = 1;
                }
                cb(err, dk);
            })
        } else {
            var dk = keythereum.create(this.getParams());
            return dk;
        }
    },
    // 获取key的文件名
    generateKeystoreFilename: function (keyObject) {
        var now = new Date().getTime().toString();
        filename = (keyObject.username || now) + '.json';

        return filename;
    },
    // 创建key
    createKey: function (username, password, cb) {
        var options = this.getOption();
        var err = 0;
        if (isFunction(cb)) {
            this.createDk(function (_err, dk) {
                err = _err;
                if (!err) {
                    keythereum.dump(password, dk.privateKey, dk.salt, dk.iv, options, function (keyObject) {
                        if (keyObject) {
                            keyObject.username = username;
                        } else {
                            err = 2;
                        }
                        cb(err, keyObject);
                    })
                } else {
                    cb(err, keyObject);
                }
            })
        } else {
            var dk = this.createDk();
            var keyObject = keythereum.dump(password, dk.privateKey, dk.salt, dk.iv, options);
            keyObject.username = username;
            return keyObject;
        }
    },
    // 导出key到文件
    exportToFile: function (keyObject, keystore, outfile, cb) {
        var outfile, outpath, json;
        var err = 0;
        keystore = keystore || DEFAULT_PATH;
        outfile = outfile || this.generateKeystoreFilename(keyObject);
        outpath = path.join(keystore, outfile);
        json = JSON.stringify(keyObject, null, 4);

        var fileExist = fs.existsSync(outpath);

        if (this.browser)
            throw new Error("method only available in Node.js");

        if (!isFunction(cb)) {
            if (!fileExist) {
                fs.writeFileSync(outpath, json);
                return outpath;
            } else {
                return null;
            }
        } else {
            if (fileExist) {
                err = 2;
                cb(err, null);
            } else {
                fs.exists(keystore, function (exists) {
                    if (exists) {
                        fs.writeFile(outpath, json, function (ex) {
                            if (ex) {
                                err = 1;
                                outpath = null;
                            }
                            cb(err, outpath);
                        });
                    } else {
                        fs.mkdir(keystore, function () {
                            fs.writeFile(outpath, json, function (ex) {
                                if (ex) {
                                    err = 1;
                                    outpath = null;
                                }
                                cb(err, outpath);
                            });
                        });
                    }
                });
            }
        }
    },
    // 通过用户名，目录找到对应的key
    importFromUsername: function (username, keystore, cb) {
        var filepath;
        function findKeyfile(keystore, username, files) {
            var len = files.length;
            var filepath = null;
            for (var i = 0; i < len; ++i) {
                if (files[i].indexOf(username) > -1) {
                    filepath = path.join(keystore, files[i]);
                    if (fs.lstatSync(filepath).isDirectory()) {
                        filepath = path.join(filepath, files[i]);
                    }
                    break;
                }
            }
            return filepath;
        }

        if (this.browser)
            throw new Error("method only available in Node.js");
        keystore = keystore || DEFAULT_PATH;
        if (!isFunction(cb)) {
            filepath = findKeyfile(keystore, username, fs.readdirSync(keystore));
            return filepath ? JSON.parse(fs.readFileSync(filepath)) : null;
        }
        fs.readdir(keystore, function (ex, files) {
            var filepath;
            if (ex) {
                cb(1, null);
            } else {
                filepath = findKeyfile(keystore, username, files);
                filepath ? cb(0, JSON.parse(fs.readFileSync(filepath))) : cb(2, null);
            }
        });
    },
    // 通过路径，找到对应的key
    importFromFilePath: function (filepath, cb) {
        if (this.browser)
            throw new Error("method only available in Node.js");
        var fileExist = fs.existsSync(filepath);

        if (!isFunction(cb)) {
            return fileExist ? JSON.parse(fs.readFileSync(filepath)) : null;
        } else {
            if (fileExist) {
                fs.readFile(filepath, function (err, data) {
                    err ? cb(2, null) : cb(0, JSON.parse(data));
                });
            } else {
                cb(1, null);
            }
        }
    },
    // 获取某个目录下面的所有keys
    importFromDir: function (keystore, cb) {
        var keyObjects = [];
        keystore = keystore || DEFAULT_PATH;
        if (isFunction(cb)) {
            fs.readdir(keystore, function (err, files) {
                if (err || files.errno) {
                    console.log('readFile ' + keystore + ' error: ', err || files.errno);
                    cb(1, keyObjects);
                } else {
                    files.forEach(function (file, index) {
                        try {
                            var data = fs.readFileSync(keystore + '/' + file);
                            var key = JSON.parse(data);
                            if (!key.privateKey) {
                                key.privateKey = null;
                            }
                            if (key.address && key.address.length == 40) {
                                key.address = '0x' + key.address;
                            }
                            keyObjects.push(key);
                        } catch (e) {

                        }
                    });
                    cb(0, keyObjects);
                }
            });
        } else {
            var files = fs.readdirSync(keystore);
            var fileCount = files.length;
            files.forEach(function (file, index) {
                try {
                    var data = fs.readFileSync(keystore + '/' + file);
                    var key = JSON.parse(data);
                    key.privateKey = null;
                    key.address = '0x' + key.address;
                    keyObjects.push(key);
                } catch (e) {

                }
            });
            return keyObjects;
        }
    },
    // 重置key
    resetPassword: function (oldPassword, newPassword, keyObject, cb) {
        var newKeyObject = null;
        var self = this;
        if (isFunction(cb)) {
            self.recover(oldPassword, keyObject, function (err, privateKey) {
                if (privateKey) {
                    self.createDk(function (err, dk) {
                        if (dk) {
                            self.createKey(keyObject.username, newPassword, function (err, keyObject) {
                                newKeyObject = keyObject
                                cb(err, newKeyObject);
                            })
                        } else {
                            cb(err, newKeyObject);
                        }
                    })
                } else {
                    cb(err, newKeyObject);
                }
            });
        } else {
            var privateKey = this.recover(oldPassword, keyObject);
            if (privateKey) {
                var dk = this.createDk();
                newKeyObject = this.createKey(keyObject.username, newPassword);
            }
            return newKeyObject;
        }
    },
    // 获取私钥privateKey
    recover: function (password, keyObject, cb) {
        var keyObjectCrypto, iv, salt, ciphertext, algo;
        var self = keythereum;
        var privateKey = '';
        keyObjectCrypto = keyObject.Crypto || keyObject.crypto;

        function verifyAndDecrypt(derivedKey, salt, iv, ciphertext, algo) {
            var key;
            if (self.getMAC(derivedKey, ciphertext) !== keyObjectCrypto.mac) {
                return null;
            }
            if (keyObject.version === "1") {
                key = keccak256(derivedKey.slice(0, 16)).slice(0, 16);
            } else {
                key = derivedKey.slice(0, 16);
            }
            return self.decrypt(ciphertext, key, iv, algo);
        }

        iv = self.str2buf(keyObjectCrypto.cipherparams.iv);
        salt = self.str2buf(keyObjectCrypto.kdfparams.salt);
        ciphertext = self.str2buf(keyObjectCrypto.ciphertext);
        algo = keyObjectCrypto.cipher;

        if (keyObjectCrypto.kdf === "pbkdf2" && keyObjectCrypto.kdfparams.prf !== "hmac-sha256") {
            if (!isFunction(cb)) {
                return null;
            } else {
                cb(2, null);
            }
        }

        if (!isFunction(cb)) {
            privateKey = verifyAndDecrypt(self.deriveKey(password, salt, keyObjectCrypto), salt, iv, ciphertext, algo);
            if (privateKey) {
                privateKey = privateKey.toString('hex');
            }
            return privateKey;
        } else {
            self.deriveKey(password, salt, keyObjectCrypto, function (derivedKey) {
                var err = 0;
                privateKey = verifyAndDecrypt(derivedKey, salt, iv, ciphertext, algo);
                if (!privateKey) {
                    err = 1;
                } else {
                    privateKey = privateKey.toString('hex');
                }
                cb(err, privateKey);
            });
        }
    },

    // 获取公钥
    getPublicKey: function (privateKey, cb) {
        var err = 0;
        if (typeof privateKey == 'string' && privateKey.constructor == String) {
            privateKey = Buffer.from(privateKey, 'hex');
        }
        var publicKey = null;
        try {
            publicKey = secp256k1.publicKeyCreate(privateKey, false).slice(1);
        } catch (e) {
            err = 1;
        }
        if (publicKey) {
            publicKey = publicKey.toString('hex');
        }
        if (isFunction(cb)) {
            cb(err, publicKey);
        } else {
            return publicKey;
        }
    },

    // 导入keyObjects
    restoreKeys: function (srcDir, distDir, cb) {
        var err = 0;
        var copyFiles = [];
        distDir = distDir || DEFAULT_PATH;

        var srcFiles = fs.readdirSync(srcDir).filter((file) => fs.lstatSync(path.join(srcDir, file)).isFile());
        srcFiles = srcFiles.filter((file) => file.endsWith('.json'));

        var copyCount = 0;

        if (isFunction(cb)) {
            srcFiles.forEach((file) => {
                var srcFilePath = path.join(srcDir, file);
                var distFilePath = path.join(distDir, file);
                if (!fs.existsSync(distFilePath)) {
                    fs.readFile(srcFilePath, (err, data) => {
                        if (!err) {
                            fs.writeFile(distFilePath, data, function (ex) {
                                copyCount++;
                                if (!ex) {
                                    copyFiles.push(file);
                                }
                                if (copyCount == srcFiles.length) {
                                    cb(0, copyFiles);
                                }
                            });
                        } else {
                            copyCount++;
                            if (copyCount == srcFiles.length) {
                                cb(0, copyFiles);
                            }
                        };
                    });
                } else {
                    copyCount++;
                    if (copyCount == srcFiles.length) {
                        cb(0, copyFiles);
                    }
                }
            })
        } else {
            srcFiles.forEach((file) => {
                var srcFilePath = path.join(srcDir, file);
                var distFilePath = path.join(distDir, file);
                if (!fs.existsSync(filePath)) {
                    try {
                        var data = fs.readFileSync(srcFilePath);
                        fs.writeFileSync(distFilePath, data);
                        copyFiles.push(file);
                    } catch (e) {

                    }
                }
            })
            return copyFiles;
        }
    }
}
