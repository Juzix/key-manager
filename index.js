var keythereum = require("keythereum");
var path = require("path");
var fs = require("fs-extra");
var createKeccakHash = require("keccak/js");
var os = require('os');
var secp256k1 = require("secp256k1/elliptic");
var ffi = require('ffi');
var ref = require('ref');
var sha3 = require('crypto-js/sha3');

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
var uint64Point = ref.refType(ref.types.uint64);
var boolPoint = ref.refType(ref.types.bool);
if (os.platform() === 'win32') {
    var dllName = (os.arch() === 'x64') ? ('WDJuZhenAPIx64') : ('WDJuZhenAPIx86');
    var dllPath = path.join(__dirname, 'dynamic', dllName);
    if (!fs.existsSync(dllPath)) {
        if (os.platform() === 'win32') {
            if (os.arch() === 'x64') {
                dllPath = path.join("c:", "Windows", "System32", "WatchDataV5", "Juzhen CSP v1.0", "WDJuZhenAPI.dll");
            } else {
                dllPath = path.join("c:", "Windows", "SysWOW64", "WatchDataV5", "Juzhen CSP v1.0", "WDJuZhenAPI.dll");
            }
        }
    }

    if (fs.existsSync(dllPath)) {
        ukey = ffi.Library(dllPath, {
            'J_BC_WD_EnumDevice': ['int', ['string', dwordPoint]],  // 01 
            'J_BC_WD_OpenDevice': ['int', ['string', uint64Point]],  // 02 
            'J_BC_WD_CloseDevice': ['int', ['uint64']],  // 03 
            'J_BC_WD_FormatDevice': ['int', ['uint64', 'string']],  // 04 
            'J_BC_WD_IsDefaultPin': ['int', ['uint64', 'int', boolPoint]],  // 05 
            'J_BC_WD_VerifyPin': ['int', ['uint64', 'ulong', 'string', dwordPoint]],  // 06 
            'J_BC_WD_ChangePin': ['int', ['uint64', 'ulong', 'string', 'string', dwordPoint]],  // 07 
            'J_BC_WD_RSAGenKey': ['int', ['uint64']],  // 08 
            'J_BC_WD_ECCGenKey': ['int', ['uint64']],  // 09 
            'J_BC_WD_RSAGetPubKey': ['int', ['uint64', 'string', dwordPoint]],  // 10 
            'J_BC_WD_ECCGetPubKey': ['int', ['uint64', 'string', dwordPoint]],  // 11 
            'J_BC_WD_ImportRSACert': ['int', ['uint64', 'string']],  // 12 
            'J_BC_WD_ExPortRSACert': ['int', ['uint64', 'string', dwordPoint]],  // 13 
            'J_BC_WD_RSAEncrypt': ['int', ['uint64', 'string', 'int', 'string', dwordPoint]],  // 14 
            'J_BC_WD_RSASign': ['int', ['uint64', 'int', 'string', 'int', 'string', dwordPoint]],  // 15 
            'J_BC_WD_ECCSign': ['int', ['uint64', 'string', 'int', 'string', 'int', 'string', dwordPoint]],  // 16 
            'J_BC_WD_RSAVerifySign': ['int', ['uint64', 'int', 'string', 'int', 'string']], // 17  
            'J_BC_WD_ECCVerifySign': ['int', ['uint64', 'string']],  // 18 
            'J_BC_BE_Enc': ['int', ['uint64', 'string', 'int', 'int', 'string', 'string', dwordPoint]],  // 19
            'J_BC_BE_Dec': ['int', ['uint64', 'string', 'int', 'int', 'string', dwordPoint]],  // 20
            'J_BC_GS_CheckKeyPair': ['int', ['uint64']],  // 21
            'J_BC_GS_ImportMPubKey': ['int', ['uint64', 'string', 'int']],  // 22
            'J_BC_GS_ImportUPriKey': ['int', ['uint64', 'string', 'int']],  // 23 
            'J_BC_GS_Sign': ['int', ['uint64', 'string', 'int', 'string', dwordPoint]],  // 24
            'J_BC_GS_Verify': ['int', ['uint64', 'string', 'int', 'string', 'int']],  // 25
            'J_BC_WD_TradeSignProtect': ['int', ['uint64', 'string', 'int', 'string', 'int', 'int', 'string', 'string', dwordPoint]],  // 26
            'WDScardEncrypt_ECIES': ['int', ['uint64', 'string', 'int', 'string', dwordPoint]],  // 27
            'WDScardDecrypt_ECIES': ['int', ['uint64', 'string', 'int', 'string', dwordPoint]],  // 28 
            'J_BC_WD_WriteData': ['int', ['uint64', 'string', 'int']],  // 29 
            'J_BC_WD_ReadData': ['int', ['uint64', 'string', dwordPoint]],  // 30 
            'WDScardGenKey_PAI': ['int', ['uint64', 'int']],  // 31 
            'WDScardGetPubKeyn_PAI': ['int', ['uint64', 'string', dwordPoint]],  // 32 
            'WDScardEncryption_PAI': ['int', ['uint64', 'string', 'int', 'string', dwordPoint]],  // 33 
            'WDScardDecryption_PAI': ['int', ['uint64', 'string', 'int', 'string', dwordPoint]],  // 34 
            'WDScardHomAdd_PAI': ['int', ['uint64', 'string', 'int', 'string', 'int', 'string', dwordPoint]],  // 35 
        });
    } else {
        console.error('WatchDataV5 not exit!')
    }
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

function getBLen(str) {
    var len = 0;
    for (var i = 0; i < str.length; i++) {
        var c = str.charCodeAt(i);
        if ((c >= 0x0001 && c <= 0x007e) || (0xff60 <= c && c <= 0xff9f)) {
            len++;
        } else {
            len += 3;
        }
    }
    return len;
}

module.exports = {
    // 01 J_BC_WD_EnumDevice ( OUT BYTE*pbNameList, OUT DWORD* pdwSizeLen);
    ukeyEnumDevice: function (cb) {
        var pbNameList = Buffer.alloc(512);
        var pdwSizeLen = ref.alloc('ulong');
        pdwSizeLen.writeUInt32LE(pbNameList.length);
        var err = c(ukey && ukey.J_BC_WD_EnumDevice(pbNameList, pdwSizeLen));
        if (err === 0) {
            pdwSizeLen = pdwSizeLen.readUInt32LE();
            pbNameList = pbNameList.toString('ascii', 0, pdwSizeLen);
            pbNameList = pbNameList.split("\u0000");
            pbNameList = pbNameList.filter((name) => name != '');
        }

        var ret = {
            err: err,
            pbNameList: pbNameList,
        }
        isFunction(cb) && cb(err, ret);
        return ret;
    },
    // 02 J_BC_WD_OpenDevice (IN BYTE* pbDevSN,OUT HANDLE* phDev);
    ukeyOpenDevice: function (pbDevSN, cb) {
        var phDev = ref.alloc('uint64');
        phDev.writeUInt64LE(0);
        var err = c(ukey && ukey.J_BC_WD_OpenDevice(pbDevSN, phDev));
        if (err === 0) {
            phDev = phDev.readUInt64LE();
        }
        var ret = {
            err: err,
            phDev: phDev,
        }
        isFunction(cb) && cb(err, ret);
        return ret;
    },

    // 03 J_BC_WD_CloseDevice(IN HANDLE hDev);
    ukeyCloseDevice: function (hDev, cb) {
        var err = c(ukey && ukey.J_BC_WD_CloseDevice(hDev));
        var ret = {
            err: err,
        }
        isFunction(cb) && cb(err, ret);
        return ret;
    },
    // 04 J_BC_WD_FormatDevice(IN HANDLE hDev,IN BYTE *pbSoPin);
    ukeyFormatDevice: function (hDev, pbSoPin, cb) {
        var err = c(ukey && ukey.J_BC_WD_FormatDevice(hDev, pbSoPin));
        var ret = {
            err: err,
        }
        isFunction(cb) && cb(err, ret);
        return ret;
    },
    // 05 J_BC_WD_IsDefaultPin (IN HANDLE hDev,IN DWORD dwPinType,OUT BOOL* pbDefaultPin);
    ukeyIsDefaultPin: function (hDev, dwPinType, cb) {
        var pbDefaultPin = ref.alloc('bool');

        var err = c(ukey && ukey.J_BC_WD_IsDefaultPin(hDev, dwPinType, pbDefaultPin));
        if (err === 0) {
            pbDefaultPin = Boolean(pbDefaultPin.toString('hex'));
        }
        var ret = {
            err: err,
            pbDefaultPin: pbDefaultPin,
        }
        isFunction(cb) && cb(err, ret);
        return ret;
    },
    // 06 J_BC_WD_VerifyPin (IN HANDLE hDev,IN DWORD dwPinType,IN BYTE *pbUserPin,OUT DWORD *pdwRetryCount);
    ukeyVerifyPin: function (hDev, dwPinType, pbUserPin, cb) {
        var pdwRetryCount = ref.alloc('ulong');
        var err = c(ukey && ukey.J_BC_WD_VerifyPin(hDev, dwPinType, pbUserPin, pdwRetryCount));
        if (err != 0) {
            pdwRetryCount = pdwRetryCount.readUInt32LE();
        }
        var ret = {
            err: err,
            pdwRetryCount: pdwRetryCount,
        }
        isFunction(cb) && cb(err, ret);
        return ret;
    },
    // 07 J_BC_WD_ChangePin (IN HANDLE hDev,IN DWORD dwPinType,IN BYTE *pbOldPin,IN BYTE *pbNewPin,OUT DWORD *pdwRetryCount)
    ukeyChangePin: function (hDev, dwPinType, pbOldPin, pbNewPin, cb) {
        var pdwRetryCount = ref.alloc('ulong');
        var err = c(ukey && ukey.J_BC_WD_ChangePin(hDev, dwPinType, pbOldPin, pbNewPin, pdwRetryCount));
        if (err != 0) {
            pdwRetryCount = pdwRetryCount.readUInt32LE();
        }
        var ret = {
            err: err,
            pdwRetryCount: pdwRetryCount,
        }
        isFunction(cb) && cb(err, ret);
        return ret;
    },

    // 08 J_BC_WD_RSAGenKey (IN HANDLE hDev)
    ukeyRSAGenKey: function (hDev, cb) {
        var err = c(ukey && ukey.J_BC_WD_RSAGenKey(hDev));
        var ret = {
            err: err,
        }
        isFunction(cb) && cb(err, ret);
        return ret;
    },
    // 09 J_BC_WD_ECCGenKey (IN HANDLE hDev)
    ukeyECCGenKey: function (hDev, cb) {
        var err = c(ukey && ukey.J_BC_WD_ECCGenKey(hDev));
        var ret = {
            err: err,
        }
        isFunction(cb) && cb(err, ret);
        return ret;
    },
    // 10 J_BC_WD_RSAGetPubKey (IN HANDLE hDev, OUT BYTE *pbPubKey, OUT DWORD *pdwPubKeyLen)
    ukeyRSAGetPubKey: function (hDev, cb) {
        var pbPubKey = Buffer.alloc(512);
        var pdwPubKeyLen = ref.alloc('ulong');
        pdwPubKeyLen.writeUInt32LE(pbPubKey.length);

        var err = c(ukey && ukey.J_BC_WD_RSAGetPubKey(hDev, pbPubKey, pdwPubKeyLen));
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
    // 11 J_BC_WD_ECCGetPubKey (IN HANDLE hDev, OUT BYTE *pbPubKey, OUT DWORD *pdwPubKeyLen);
    ukeyECCGetPubKey: function (hDev, cb) {
        var pbPubKey = Buffer.alloc(512);
        var pdwPubKeyLen = ref.alloc('ulong');
        pdwPubKeyLen.writeUInt32LE(512);

        var err = c(ukey && ukey.J_BC_WD_ECCGetPubKey(hDev, pbPubKey, pdwPubKeyLen));
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
    ukeyECCAddress: function (hDev, cb) {
        var r = this.ukeyECCGetPubKey(hDev);
        var ret = {
            err: r.err,
            address: null,
        }
        if (r.err === 0) {
            ret.address = '0x' + sha3(ret.pbPubKey, { outputLength: 256 }).toString().slice(-40);
        }
        isFunction(cb) && cb(ret.err, ret);
        return ret;
    },
    // 12 J_BC_WD_ImportRSACert(IN HANDLE hDev, IN BYTE *pbCert)
    ukeyImportRSACert: function (hDev, pbCert, cb) {
        var err = c(ukey && ukey.J_BC_WD_ImportRSACert(hDev, pbCert));
        var ret = {
            err: err,
        }
        isFunction(cb) && cb(err, ret);
        return ret;
    },
    // 13 J_BC_WD_ExPortRSACert(IN HANDLE hDev, OUT BYTE *pbCert,OUT DWORD *pdwCertLen);
    ukeyExPortRSACert: function (hDev, cb) {
        var pbCert = Buffer.alloc(128);
        var pdwCertLen = ref.alloc('ulong');
        pdwCertLen.writeUInt32LE(128);
        var err = c(ukey && ukey.J_BC_WD_ExPortRSACert(hDev, pbCert, pdwCertLen));
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
    // 14 J_BC_WD_RSAEncrypt(IN HANDLE hDev, IN BYTE *pbData, IN DWORD dwDataLen, OUT BYTE*pbCipher, OUT DWORD* pdwCipherLen)
    ukeyRSAEncrypt: function (hDev, pbData, cb) {
        var dwDataLen = pbData.length;
        var pbCipher = Buffer.alloc(512);
        var pdwCipherLen = ref.alloc('ulong');
        pdwCipherLen.writeUInt32LE(512);
        var err = c(ukey && ukey.J_BC_WD_RSAEncrypt(hDev, pbData, dwDataLen, pbCipher, pdwCipherLen));
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
    // 15 J_BC_WD_RSASign (IN HANDLE hDev, IN DWORD dwHashAlg, IN BYTE* pbData, IN DWORD dwDataLen, OUT BYTE* pbSign, OUT DWORD* pdwSignLen)
    ukeyRSASign: function (hDev, dwHashAlg, pbData, cb) {
        var dwDataLen = pbData.length;
        var pbSign = Buffer.alloc(512);
        var pdwSignLen = ref.alloc('ulong');
        pdwSignLen.writeUInt32LE(pbSign.length);

        var err = c(ukey && ukey.J_BC_WD_RSASign(hDev, dwHashAlg, pbData, dwDataLen, pbSign, pdwSignLen));
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
    // 16 J_BC_WD_ECCSign (IN HANDLE hDev, IN BYTE* pbMsgRlp,IN DWORD dwMsgRlpLen, IN BYTE* pbShowData,IN DWORD dwShowLen, OUT BYTE*pbSignRlp, OUT DWORD*pdwSignLen);
    ukeyECCSign: function (hDev, pbMsgRlp, pbShowData, cb) {
        var pbMsgRlp = Buffer.from(pbMsgRlp, 'hex');
        var dwMsgRlpLen = pbMsgRlp.length;
        var dwShowLen = getBLen(pbShowData);
        var pbSignRlp = Buffer.alloc(1024);
        var pdwSignLen = ref.alloc('ulong');
        pdwSignLen.writeUInt32LE(pbSignRlp.length);
        var err = c(ukey && ukey.J_BC_WD_ECCSign(hDev, pbMsgRlp, dwMsgRlpLen, pbShowData, dwShowLen, pbSignRlp, pdwSignLen));
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
    // 17 J_BC_WD_RSAVerifySign(IN HANDLE hDev, IN DWORD dwHashAlg, IN  BYTE* pbData, IN DWORD dwDataLen, IN BYTE* pbSign); 注释跟头文件生命不一致
    ukeyRSAVerifySign: function (hDev, dwHashAlg, pbData, pbSign, cb) {
        dwDataLen = pbData.length;
        pbSign = Buffer.from(pbSign, 'hex');

        var err = c(ukey && ukey.J_BC_WD_RSAVerifySign(hDev, dwHashAlg, pbData, dwDataLen, pbSign));

        var ret = {
            err: err,
        }

        isFunction(cb) && cb(err, ret);
        return ret;
    },
    // 18 J_BC_WD_ECCVerifySign(IN HANDLE hDev, IN BYTE* pbSignRlp)
    ukeyECCVerifySign: function (hDev, pbSignRlp, cb) {
        pbSignRlp = Buffer.from(pbSignRlp, 'hex');
        var err = c(ukey && ukey.J_BC_WD_ECCVerifySign(hDev, pbSignRlp));
        var ret = {
            err: err,
        }
        isFunction(cb) && cb(err, ret);
        return ret;
    },
    // 19 J_BC_BE_Enc(IN HANDLE hDev, IN BYTE*pbMessage, IN DWORD dwMessage_Len, IN DWORD dwGroupNum, IN BYTE*pbGroup_PubKey, OUT BYTE*pbCipherText, OUT DWORD *pdwCipherText_Len)
    ukeyEnc: function (hDev, pbMessage, dwGroupNum, pbGroup_PubKey, cb) {
        pbMessage = Buffer.from(pbMessage, 'hex');
        var dwMessage_Len = pbMessage.length;
        pbGroup_PubKey = Buffer.from(pbGroup_PubKey, 'hex');
        var pbCipherText = Buffer.alloc(1024);
        var pdwCipherText_Len = ref.alloc('ulong');
        pdwCipherText_Len.writeUInt32LE(pbCipherText.length);

        var err = c(ukey && ukey.J_BC_BE_Enc(hDev, pbMessage, dwMessage_Len, dwGroupNum, pbGroup_PubKey, pbCipherText, pdwCipherText_Len));
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
    // 20 J_BC_BE_Dec(IN HANDLE hDev, IN BYTE*pbCipherText, IN DWORD dwCipherText_Len, IN DWORD dwGroupNum, OUT BYTE*pbMessage, OUT DWORD*pdwMessage_Len)
    ukeyDec: function (hDev, pbCipherText, dwGroupNum, cb) {
        pbCipherText = Buffer.from(pbCipherText, 'hex');
        var dwCipherText_Len = pbCipherText.length;
        var pbMessage = Buffer.alloc(1024);
        var pdwMessage_Len = ref.alloc('ulong');
        pdwMessage_Len.writeUInt32LE(pbMessage.length);

        var err = c(ukey && ukey.J_BC_BE_Dec(hDev, pbCipherText, dwCipherText_Len, dwGroupNum, pbMessage, pdwMessage_Len));
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
    // 21 J_BC_GS_CheckKeyPair(IN HANDLE hDev)
    ukeyCheckKeyPair: function (hDev, cb) {
        var err = c(ukey && ukey.J_BC_GS_CheckKeyPair(hDev));
        var ret = {
            err: err,
        }
        isFunction(cb) && cb(err, ret);
        return ret;
    },
    // 22 J_BC_GS_ImportMPubKey(IN HANDLE hDev, IN BYTE* pbMPubKey,IN DWORD dwMPubKey)
    ukeyImportMPubKey: function (hDev, pbMPubKey, cb) {
        pbMPubKey = Buffer.from(pbMPubKey, 'hex');
        var dwMPubKey = pbMPubKey.length;
        var err = c(ukey && ukey.J_BC_GS_ImportMPubKey(hDev, pbMPubKey, dwMPubKey));
        var ret = {
            err: err,
        }
        isFunction(cb) && cb(err, ret);
        return ret;
    },
    // 23 J_BC_GS_ImportUPriKey(IN HANDLE hDev, IN BYTE  *pbUPriKey,IN DWORD dwUPriKey)
    ukeyImportUPriKey: function (hDev, pbUPriKey, cb) {
        pbUPriKey = Buffer.from(pbUPriKey, 'hex');
        var dwUPriKey = pbUPriKey.length;
        var err = c(ukey && ukey.J_BC_GS_ImportUPriKey(hDev, pbUPriKey, dwUPriKey));
        var ret = {
            err: err,
        }
        isFunction(cb) && cb(err, ret);
        return ret;
    },
    // 24 J_BC_GS_Sign(IN HANDLE hDev, IN BYTE* pbHash, IN DWORD dwHash, OUT BYTE*pbSign, OUT DWORD* pdwSignLen)
    ukeyGSSign: function (hDev, pbHash, cb) {
        pbHash = sha3(pbHash, { outputLength: 256 }).toString();
        pbHash = Buffer.from(pbHash, 'hex');
        var dwHash = pbHash.length;
        var pbSign = Buffer.alloc(512);
        var pdwSignLen = ref.alloc('ulong');
        pdwSignLen.writeUInt32LE(pbSign.length);

        var err = c(ukey && ukey.J_BC_GS_Sign(hDev, pbHash, dwHash, pbSign, pdwSignLen));
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
    // 25 J_BC_GS_Verify(IN HANDLE hDev, IN BYTE* pbHash, IN DWORD dwHash, IN BYTE* pbSign, IN DWORD dwSignLen)
    ukeyGSVerify: function (hDev, pbHash, pbSign, cb) {
        pbHash = sha3(pbHash, { outputLength: 256 }).toString();
        pbHash = Buffer.from(pbHash, 'hex');
        var dwHash = pbHash.length;
        pbSign = Buffer.from(pbSign, 'hex');
        var pdwSignLen = pbSign.length;

        var err = c(ukey && ukey.J_BC_GS_Verify(hDev, pbHash, dwHash, pbSign, pdwSignLen));
        var ret = {
            err: err,
        }
        isFunction(cb) && cb(err, ret);
        return ret;
    },
    // 26 J_BC_WD_TradeSignProtect(IN HANDLE hDev, IN  BYTE *pbMsg, IN DWORD dwMsg, IN BYTE* pbShowData, IN DWORD dwShowLen, IN DWORD dwGroupNum, IN BYTE *pbGroup_PubKey, OUT BYTE *pbSign, OUT DWORD *pdwSignLen)
    ukeyTradeSignProtect: function (hDev, pbMsg, pbShowData, dwGroupNum, pbGroup_PubKey, cb) {
        pbMsg = Buffer.from(pbMsg, 'hex');
        var dwMsg = pbMsg.length;
        var dwShowLen = getBLen(pbShowData);
        pbGroup_PubKey = Buffer.from(pbGroup_PubKey, 'hex');
        var pbSign = Buffer.alloc(1024);
        var pdwSignLen = ref.alloc('ulong');
        pdwSignLen.writeUInt32LE(pbSign.length);

        var err = c(ukey && ukey.J_BC_WD_TradeSignProtect(hDev, pbMsg, dwMsg, pbShowData, dwShowLen, dwGroupNum, pbGroup_PubKey, pbSign, pdwSignLen));
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
    // 27 WDScardEncrypt_ECIES(IN HANDLE hDev, IN LPBYTE pbData, IN DWORD dwDataLen, OUT LPBYTE pbEncryptedData, OUT LPDWORD pdwEncryptedDataLen);
    ukeyWDScardEncryptECIES: function (hDev, pbData, cb) {
        pbData = Buffer.from(pbData, 'hex');
        var dwDataLen = pbData.length;
        var pbEncryptedData = Buffer.alloc(1024);
        var pdwEncryptedDataLen = ref.alloc('ulong');
        pdwEncryptedDataLen.writeUInt32LE(pbEncryptedData.length);

        var err = c(ukey && ukey.WDScardEncrypt_ECIES(hDev, pbData, dwDataLen, pbEncryptedData, pdwEncryptedDataLen));
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
    // 28 WDScardDecrypt_ECIES(IN HANDLE hDev, IN LPBYTE pbEncryptedData, IN DWORD dwEncryptedDataLen, OUT LPBYTE pbDecryptedData, OUT PDWORD pdwDecryptedDataLen)
    ukeyWDScardDecryptECIES: function (hDev, pbEncryptedData, cb) {
        pbEncryptedData = Buffer.from(pbEncryptedData, 'hex');
        var dwEncryptedDataLen = pbEncryptedData.length;
        var pbDecryptedData = Buffer.alloc(1024);
        var pdwDecryptedDataLen = ref.alloc('ulong');
        pdwDecryptedDataLen.writeUInt32LE(pbDecryptedData.length);

        var err = c(ukey && ukey.WDScardDecrypt_ECIES(hDev, pbEncryptedData, dwEncryptedDataLen, pbDecryptedData, pdwDecryptedDataLen));
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

    // 29 J_BC_WD_WriteData(IN HANDLE hDev, IN LPBYTE pbData, IN DWORD dwDataLen)
    ukeyWriteData: function (hDev, pbData, cb) {
        var dwDataLen = pbData.length;
        var err = c(ukey && ukey.J_BC_WD_WriteData(hDev, pbData, dwDataLen));
        var ret = {
            err: err,
        }
        isFunction(cb) && cb(err, ret);
        return ret;
    },

    // 30 J_BC_WD_ReadData(IN HANDLE hDev, OUT LPBYTE pbData, OUT DWORD *pdwDataLen)
    ukeyReadData: function (hDev, cb) {
        var pbData = Buffer.alloc(4096);
        var pdwDataLen = ref.alloc('ulong');
        pdwDataLen.writeUInt32LE(pbData.length);
        var err = c(ukey && ukey.J_BC_WD_ReadData(hDev, pbData, pdwDataLen));
        if (err === 0) {
            pdwDataLen = pdwDataLen.readUInt32LE();
            pbData = pbData.toString('ascii', 0, pdwDataLen);
        }
        var ret = {
            err: err,
            pbData: pbData,
        }
        isFunction(cb) && cb(err, ret);
        return ret;
    },
    // 31 WDScardGenKey_PAI(IN HANDLE hDev,IN DWORD dwKeyLen)
    ukeyWDScardGenKeyPAI: function (hDev, dwKeyLen, cb) {
        var err = c(ukey && ukey.WDScardGenKey_PAI(hDev, dwKeyLen));
        var ret = {
            err: err,
        }
        isFunction(cb) && cb(err, ret);
        return ret;
    },
    // 32 WDScardGetPubKeyn_PAI(IN  HANDLE  hDev,OUT LPBYTE pbPubKey_n,OUT DWORD *dwPubKeyLen);
    ukeyWDScardGetPubKeynPAI: function (hDev, cb) {
        var pbPubKey_n = Buffer.alloc(512);
        var dwPubKeyLen = ref.alloc('ulong');
        dwPubKeyLen.writeUInt32LE(pbPubKey_n.length);
        var err = c(ukey && ukey.WDScardGetPubKeyn_PAI(hDev, pbPubKey_n, dwPubKeyLen));
        if (err === 0) {
            dwPubKeyLen = dwPubKeyLen.readUInt32LE();
            pbPubKey_n = pbPubKey_n.toString('hex', 0, dwPubKeyLen);
        }
        var ret = {
            err: err,
            pbPubKey_n: pbPubKey_n,
        }
        isFunction(cb) && cb(err, ret);
        return ret;
    },
    // 33 WDScardEncryption_PAI(IN HANDLE hDev, IN LPBYTE pbMsg, IN DWORD dwMsgLen, OUT LPBYTE pbCipher, OUT LPDWORD pdwCipherLen);
    ukeyWDScardEncryptionPAI: function (hDev, pbMsg, cb) {
        var dwMsgLen = pbMsg.length;
        var pbCipher = Buffer.alloc(1024);
        var pdwCipherLen = ref.alloc('ulong');
        pdwCipherLen.writeUInt32LE(pbCipher.length);

        var err = c(ukey && ukey.WDScardEncryption_PAI(hDev, pbMsg, dwMsgLen, pbCipher, pdwCipherLen));
        if (err === 0) {
            pdwCipherLen = pdwCipherLen.readUInt32LE();
            pbCipher = pbCipher.toString('ascii', 0, pdwCipherLen);
        }
        var ret = {
            err: err,
            pbCipher: pbCipher,
        }
        isFunction(cb) && cb(err, ret);
        return ret;
    },
    // 34 WINAPI WDScardDecryption_PAI(IN HANDLE hDev, IN LPBYTE pbCipher, IN DWORD dwCipherLen, OUT LPBYTE pbMsg, OUT LPDWORD pdwMsgLen);
    ukeyWDScardDecryptionPAI: function (hDev, pbCipher, cb) {
        var dwCipherLen = pbCipher.length;
        var pbMsg = Buffer.alloc(1024);
        var dwMsgLen = ref.alloc('ulong');
        dwMsgLen.writeUInt32LE(pbMsg.length);

        var err = c(ukey && ukey.WDScardEncryption_PAI(hDev, pbCipher, dwCipherLen, pbMsg, dwMsgLen));
        if (err === 0) {
            dwMsgLen = dwMsgLen.readUInt32LE();
            pbMsg = pbMsg.toString('ascii', 0, dwMsgLen);
        }
        var ret = {
            err: err,
            pbMsg: pbMsg,
        }
        isFunction(cb) && cb(err, ret);
        return ret;
    },

    // 35 WDScardHomAdd_PAI(IN HANDLE hDev, IN LPBYTE pbCipherA, IN DWORD dwCipherALen, IN LPBYTE pbCipherB, IN DWORD dwCipherBLen, OUT LPBYTE pbResult, OUT LPDWORD pdwResultLen);
    ukeyWDScardHomAddPAI: function (hDev, pbCipherA, pbCipherB, cb) {
        var dwCipherALen = pbCipherA.length;
        var dwCipherBLen = pbCipherB.length;
        var pbResult = Buffer.alloc(1024);
        var pdwResultLen = ref.alloc('ulong');
        pdwResultLen.writeUInt32LE(pbResult.length);

        var err = c(ukey && ukey.WDScardHomAdd_PAI(hDev, pbCipherA, dwCipherALen, pbCipherB, dwCipherBLen, pbResult, pdwResultLen));
        if (err === 0) {
            pdwResultLen = pdwResultLen.readUInt32LE();
            pbResult = pbResult.toString('ascii', 0, pdwResultLen);
        }
        var ret = {
            err: err,
            pbResult: pbResult,
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
                            keyObject.address = '0x' + keyObject.address;
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
    exportToFile: function (keyObject, keystore, outfileName, cb) {
        keystore = keystore || DEFAULT_PATH;
        var err = 0;
        var outfileName = outfileName || this.generateKeystoreFilename(keyObject);
        var outpath = path.join(keystore, outfileName);
        var option = { spaces: 2 };
        var fileExist = fs.existsSync(outpath);

        if (isFunction(cb)) {
            if (fileExist) {
                err = 2;
                cb(err, null);
            } else {
                fs.outputJson(outpath, keyObject, option, err => {
                    if (!err) {
                        cb(0, outpath)
                    }
                })
            }
        } else {
            if (!fileExist) {
                fs.outputJsonSync(outpath, keyObject, option);
                return outpath;
            } else {
                return null;
            }
        }
    },
    // 通过用户名，目录找到对应的key
    importFromUsername: function (username, keystore, cb) {
        keystore = keystore || DEFAULT_PATH;
        var filePath = path.join(keystore, username + '.json');
        return this.importFromFilePath(filePath, cb);
    },
    // 通过路径，找到对应的key
    importFromFilePath: function (filePath, cb) {
        if (isFunction(cb)) {
            fs.readJson(filePath, (err, keyObject) => {
                err = err ? 1 : 0;
                cb(err, keyObject);
            })
        } else {
            var keyObject = null;
            try {
                keyObject = fs.readJsonSync(filePath);
            } catch (e) {

            }
            return keyObject;
        }
    },
    // 获取某个目录下面的所有keys
    importFromDir: function (keystore, cb) {
        keystore = keystore || DEFAULT_PATH;
        var keyObjects = [];
        var self = this;
        if (isFunction(cb)) {
            fs.readdir(keystore, function (err, files) {
                if (err || files.errno) {
                    console.log('readFile ' + keystore + ' error: ', err || files.errno);
                    cb(1, keyObjects);
                } else {
                    files = files.filter((file) => file.endsWith('.json'));
                    files.forEach(function (file, index) {
                        var filePath = path.join(keystore, file);
                        self.importFromFilePath(filePath, function (err, keyObject) {
                            if (err === 0) {
                                keyObjects.push(keyObject)
                            }
                            if (index + 1 === files.length) {
                                cb(0, keyObjects);
                            }
                        });
                    });
                }
            });
        } else {
            var files = fs.readdirSync(keystore);
            files = files.filter((file) => file.endsWith('.json'));
            files.forEach(function (file, index) {
                var filePath = path.join(keystore, file);
                var keyObject = self.importFromFilePath(filePath);
                if (keyObject) {
                    keyObjects.push(keyObject);
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
        var option = {
            overwrite: false,
        }

        // 只拷贝一级目录且不存在目标路径的json文件。
        var srcFiles = fs.readdirSync(srcDir).filter((file) => fs.lstatSync(path.join(srcDir, file)).isFile());
        var distFiles = fs.readdirSync(distDir).filter((file) => fs.lstatSync(path.join(distDir, file)).isFile());
        srcFiles = srcFiles.filter((file) => file.endsWith('.json'));
        srcFiles = srcFiles.filter((file) => distFiles.indexOf(file) < 0);

        var copyCount = 0;

        if (isFunction(cb)) {
            srcFiles.forEach((file, index) => {
                var srcFilePath = path.join(srcDir, file);
                var distFilePath = path.join(distDir, file);
                fs.copy(srcFilePath, distFilePath, option, function (err) {
                    if (!err) {
                        copyFiles.push(file);
                    }
                    if (index + 1 === srcFiles.length) {
                        cb(0, srcFiles);
                    }
                })
            })
            if (srcFiles.length === 0) {
                cb(0, copyFiles);
            }
        } else {
            srcFiles.forEach((file, index) => {
                var srcFilePath = path.join(srcDir, file);
                var distFilePath = path.join(distDir, file);
                fs.copy(srcFilePath, distFilePath, option);
                copyFiles.push(file);
            })
            return copyFiles;
        }
    }
}
