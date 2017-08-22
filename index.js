var keythereum = require("keythereum");
var path = require("path");
var fs = require("fs");
var createKeccakHash = require("keccak/js");
var os = require('os');

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

function keccak256(buffer) {
    return createKeccakHash("keccak256").update(buffer).digest();
}

function isFunction(f) {
    return typeof f === "function";
}

module.exports = {
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

        if (this.browser)
            throw new Error("method only available in Node.js");

        if (!isFunction(cb)) {
            fs.writeFileSync(outpath, json);
            return outpath;
        }
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
    },
    // 通过用户名，目录找到对应的key
    importFromFile: function (username, keystore, cb) {
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
    importFromFileName: function (fileName, keystore, cb) {
        if (this.browser)
            throw new Error("method only available in Node.js");
        keystore = keystore || DEFAULT_PATH;
        var filepath = path.join(keystore, fileName);
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
            return verifyAndDecrypt(self.deriveKey(password, salt, keyObjectCrypto), salt, iv, ciphertext, algo);
        } else {
            self.deriveKey(password, salt, keyObjectCrypto, function (derivedKey) {
                var err = 0;
                var privateKey = verifyAndDecrypt(derivedKey, salt, iv, ciphertext, algo);
                if (!privateKey) {
                    err = 1;
                }
                cb(err, privateKey);
            });
        }
    },

    // 获取公钥
    getPublicKey: function (keyObject, cb) {
        var err = 0;
        var publicKey = null;
        if (isFunction(cb)) {
            cb(err, publicKey);
        } else {
            return publicKey;
        }
    },

    // 获取群私钥
    getGroupPrivateKey: function(keyObject, cb){
        var err = 0;
        var groupPrivateKey = null;
        if (isFunction(cb)) {
            cb(err, groupPrivateKey);
        } else {
            return groupPrivateKey;
        }
    },

    // 导入keyObjects
    restoreKeys: function (srcPath, distPath, cb) {
        var err = 0;
        var files = [];
        if (isFunction(cb)) {
            cb(err, files);
        } else {
            return files;
        }
    }
}
