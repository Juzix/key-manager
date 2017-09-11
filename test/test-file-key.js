var mocha = require('mocha');
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
    var keyobject = null;
    var outpath = null;

    step('测试生成文件证书对象', function(done){
        key.createKey(config.account, config.username, config.pwd, function(err, _keyobject){
            expect(err).to.be.equal(0);
            if (err === 0) {
                keyobject = _keyobject;
            }
            done();
        })
    })

    step('测试生成文件导入到文件夹', function(done){
        key.exportToFile(keyobject, null, keyobject.account + '.json', true, function(err, _outpath){
            expect(err).to.be.equal(0);
            if (err === 0) {
                outpath = _outpath;
            }
            done();
        });
    })

    step('测试通过文件读取key', function(done){
        key.importFromFilePath(outpath, function(err, _keyobject){
            expect(err).to.be.equal(0);
            expect(_keyobject).to.be.deep.equal(keyobject);
            done();
        });
    })

    step('测试解密文件证书', function(done){
        key.recover(config.pwd, keyobject, function(err, privateKey){
            expect(err).to.be.equal(0);
            done();
        })
    })

    step('从目录读取文件证书', function(done){
        key.importFromDir(null, function(err, keyObjects){
            expect(err).to.be.equal(0);
            // console.log(keyObjects)
            done();
        })
    })

})
