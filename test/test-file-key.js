var mocha = require('mocha');
var path = require("path");
var os = require('os');
var fs = require('fs-extra')
var expect = require('chai').expect;
var key = require('../index.js');
require('mocha-steps');

var config = null;
try {
    config = require('./config.js');
} catch (error) {
    config = require('./config.default.js');
}

var skip = it.skip;
var only = it.only;

describe("开始文件证书测试...", function () {
    var keyObject = null;
    var outpath = null;
    var privateKey = null;

    step('测试生成文件证书对象', function(done){
        key.createKey(config.account, config.username, config.pwd, function(err, _keyObject){
            expect(err).to.be.equal(0);
            if (err === 0) {
                keyObject = _keyObject;
            }
            done();
        })
    })

    step('测试生成文件导入到文件夹', function(done){
        key.exportToFile(keyObject, null, keyObject.account + '.json', true, function(err, _outpath){
            expect(err).to.be.equal(0);
            if (err === 0) {
                outpath = _outpath;
            }
            done();
        });
    })

    step('测试通过账号获取keyObject(存在)', function(done){
        key.importFromAccount(keyObject.account, null, function(err, keyObject){
            expect(err).to.be.equal(0);
            done();
        });
    })

    step('测试通过账号获取keyObject(不存在)', function(done){
        key.importFromAccount(String(new Date().getTime()), null, function(err, keyObject){
            expect(err).to.be.not.equal(0);
            done();
        });
    })

    step('测试通过文件读取key', function(done){
        key.importFromFilePath(outpath, function(err, _keyObject){
            expect(err).to.be.equal(0);
            expect(_keyObject).to.be.deep.equal(keyObject);
            done();
        });
    })

    step('从目录读取文件证书', function(done){
        key.importFromDir(null, function(err, keyObjects){
            expect(err).to.be.equal(0);
            done();
        })
    })

    step('测试修改密码(密码正确)', function(done){
        var newPwd = '654321';
        key.resetPassword(config.pwd, newPwd, keyObject, function(err, newKeyObject){
            expect(err).to.be.equal(0);
            if (err === 0) {
                expect(keyObject.address).to.be.equal(newKeyObject.address);
                expect(keyObject.id).to.be.equal(newKeyObject.id);
                expect(keyObject.version).to.be.equal(newKeyObject.version);
                expect(keyObject.username).to.be.equal(newKeyObject.username);
                expect(keyObject.account).to.be.equal(newKeyObject.account);
                key.recover(newPwd, newKeyObject, function(err, privateKey){
                    expect(err).to.be.equal(0);
                    done();
                })
            } else {
                done();
            }
        })
    })

    step('测试修改密码(密码错误)', function(done){
        key.resetPassword(String(new Date().getTime()), '654321', keyObject, function(err, keyObject){
            expect(err).to.be.not.equal(0);
            expect(keyObject).to.be.null;
            done();
        })
    })

    step('测试解密文件证书(密码正确)', function(done){
        key.recover(config.pwd, keyObject, function(err, _privateKey){
            privateKey = _privateKey;
            expect(err).to.be.equal(0);
            done();
        })
    })

    step('测试解密文件证书(密码错误)', function(done){
        key.recover(String(new Date().getTime()), keyObject, function(err, privateKey){
            expect(err).to.be.not.equal(0);
            done();
        })
    })

    step('测试获取公钥', function(done){
        key.getPublicKey(privateKey, function(err, publicKey){
            expect(err).to.be.equal(0);
            done();
        })
    })

    step('备份文件证书', function(done){
        const src = path.join(os.homedir(), 'keystores');
        const dest = path.join(os.homedir(), '_keystores_bak');
        fs.removeSync(dest);
        key.restoreKeys(src, dest, function(err, copyFiles){
            expect(err).to.be.equal(0);
            done();
        })
    })
})
