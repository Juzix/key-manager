var keythereum = require("keythereum");
var path = require("path");
var fs = require("fs");
var createKeccakHash = require("keccak/js");

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

function keccak256(buffer) {
    return createKeccakHash("keccak256").update(buffer).digest();
}

function isFunction(f) {
    return typeof f === "function";
}

module.exports = {
    browser: typeof process === "undefined" || !process.nextTick || Boolean(process.browser),
    setParams: function(_params) {
        params = _params;
    },
    getParams: function() {
        return params;
    },
    setOption: function(_options) {
        options = _options;
    },
    getOption: function() {
        return options;
    },
    createDk: function(err, cb) {
        err = 0;
        if (isFunction(cb)) {
            keythereum.create(this.getParams(), function(dk) {
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
    generateKeystoreFilename: function(keyObject) {
        var username = keyObject.id;
        var address = keyObject.address;
        var filename = address + "--" + username;
        filename = username;
        // Windows does not permit ":" in filenames, replace all with "-"
        if (process.platform === "win32") {
            filename = filename.split(":").join("-");
        }
        filename += '.json';

        return filename;
    },
    createKey: function(username, password, cb) {
        var options = this.getOption();
        var err = 0;
        if (isFunction(cb)) {
            this.createDk(function(_err, dk) {
                err = _err;
                if (!err) {
                    keythereum.dump(password, dk.privateKey, dk.salt, dk.iv, options, function(err, keyObject) {
                        if (keyObject) {
                            keyObject.id = username;
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
            keyObject.id = username;
            return keyObject;
        }
    },
    exportToFile: function(keyObject, keystore, outfile, cb) {
        var outfile,
            outpath,
            json;
        var err = 1;
        keystore = keystore || "keystore";
        outfile = outfile || this.generateKeystoreFilename(keyObject);
        outpath = path.join(keystore, outfile);
        json = JSON.stringify(keyObject, null, 4);

        if (this.browser)
            throw new Error("method only available in Node.js");

        if (!isFunction(cb)) {
            fs.writeFileSync(outpath, json);
            return outpath;
        }
        fs.writeFile(outpath, json, function(ex) {
            if (ex){
                err = 1;
            }
            cb(err, outpath);
        });
    },
    importFromFile: function(username, datadir, cb) {
        var keystore;
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
        keystore = datadir || "keystore"
        if (!isFunction(cb)) {
            filepath = findKeyfile(keystore, username, fs.readdirSync(keystore));
            if (!filepath) {
                throw new Error("could not find key file for username " + username);
            }
            return JSON.parse(fs.readFileSync(filepath));
        }
        fs.readdir(keystore, function(ex, files) {
            var filepath;
            if (ex)
                return cb(1, null);
            filepath = findKeyfile(keystore, username, files);
            if (!filepath) {
                return new Error("could not find key file for username " + username);
            }
            return cb(0, JSON.parse(fs.readFileSync(filepath)));
        });
    },
    importFromDir: function(keystore, cb) {
        var keyObjects = [];
        keystore = keystore || "keystore";
        if (isFunction(cb)) {
            fs.readdir(keystore, function(err, files) {
                if (err || files.errno) {
                    console.log('readFile ' + keystore + ' error: ', err || files.errno);
                    cb(1, keyObjects);
                } else {
                    files.forEach(function(file, index) {
                        fs.readFile(keystore + '/' + file, function(err, data) {
                            if (!err) {
                                var key = JSON.parse(data);
                                key.privateKey = null;
                                key.address = '0x' + key.address;
                                keyObjects.push(key);
                            }
                            if (index + 1 >= files.length) {
                                cb(0, keyObjects);
                            }
                        });
                    });
                }
            });
        } else {
            var files = fs.readdirSync(keystore);
            var fileCount = files.length;
            files.forEach(function(file, index) {
                try {
                    var data = fs.readFileSync(keystore + '/' + file);
                    var key = JSON.parse(data);
                    key.privateKey = null;
                    key.address = '0x' + key.address;
                    keyObjects.push(key);
                } catch (e) {}
            });
            return keyObjects;
        }
    },
    resetPassword: function(oldPassword, newPassword, keyObject, cb) {
        var newKeyObject = null;
        var self = this;
        if (isFunction(cb)) {
            self.recover(oldPassword, keyObject, function(err, privateKey) {
                if (privateKey) {
                    self.createDk(function(err, dk) {
                        if (dk) {
                            self.createKey(keyObject.id, newPassword, function(err, keyObject) {
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
                newKeyObject = this.createKey(keyObject.id, newPassword);
            }
            return newKeyObject;
        }
    },
    recover: function(password, keyObject, cb) {
        var keyObjectCrypto,
            iv,
            salt,
            ciphertext,
            algo,
            self = keythereum;
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
            throw new Error("PBKDF2 only supported with HMAC-SHA256");
        }

        if (!isFunction(cb)) {
            return verifyAndDecrypt(self.deriveKey(password, salt, keyObjectCrypto), salt, iv, ciphertext, algo);
        }
        self.deriveKey(password, salt, keyObjectCrypto, function(derivedKey) {
            var err = 0;
            if (derivedKey) {
                err = 1;
            }
            cb(err, verifyAndDecrypt(derivedKey, salt, iv, ciphertext, algo));
        });
    }
}
