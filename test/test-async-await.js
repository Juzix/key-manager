var fs = require('fs-extra')
var key = require('../index.js');

var config = null;
try {
    config = require('./config.js');
} catch (error) {
    config = require('./config.default.js');
}
// 1 根据用户名读取一个key.
// 2 如果该key存在，那么进行下一步，如果不存在，创建key
// 3 获取上面的key的私钥
// 4 获取上面的key的公钥
// 5 重置文件证书的密码
// 6 将上面的文件证书写到指定的目录
function test(){
    console.log('test begin...');
    var keyObject = null;

    // 根据用户名读取一个key. 如果该key存在，那么进行下一步，如果不存在，创建key
    function getKeyObject(account, username, pwd, cb){
        key.importFromAccount(account, null, function(err, keyObject){
            if (err === 0) {
                cb(0, keyObject);
            } else {
                key.createKey(config.account, config.username, config.pwd, function(err, keyObject){
                    cb(err, keyObject);
                })
            }
        })
    }
    getKeyObject(config.account, config.username, config.pwd, function(err, _keyObject){
        keyObject = _keyObject;
        if (err === 0) {
            //获取私钥
            key.recover(config.pwd, keyObject, function(err, privateKey){
                if (err === 0) {
                    keyObject.privateKey = privateKey;
                    // 获取公钥
                    key.getPublicKey(privateKey, function(err, publicKey){
                        if (err === 0) {
                            keyObject.publicKey = publicKey;
                            // 更换密码
                            key.resetPassword(config.pwd, config.pwd, keyObject, function(err, newKeyObject){
                                if (err === 0) {
                                    // 导出倒一个文件
                                    key.exportToFile(newKeyObject, null, null, true, function(err, outpath){
                                        if (err === 0) {
                                            console.log('test end...', outpath);
                                        }
                                    })
                                }
                            })
                        }
                    })
                }
            })
        }
    })

    // try {
    //     console.log('test begin...');
    //     let keyObject = null;
    //     try {
    //         keyObject = await key.fileImportAccount(config.account, null);
    //     } catch (error) {
    //         keyObject = await key.fileCreateKey(config.account, config.username, config.pwd);
    //     }
    //     keyObject.privateKey = await key.filePrivateKey(config.pwd, keyObject);
    //     keyObject.publicKey = await key.filePublicKey(keyObject.privateKey);
    //     let newKeyObject = await key.fileResetKey(config.pwd, config.pwd, keyObject);
    //     let outpath = await key.fileExportToFile(keyObject, null, null, true);
    //     console.log('test end...', outpath);
    // } catch (error) {
    //     console.error('error:', error);
    // }
}

console.log('await begin...')
test();
console.log('await end...')

