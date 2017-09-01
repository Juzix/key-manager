var mocha = require('mocha');
var expect = require('chai').expect;
var key = require('../index.js');
require('mocha-steps');

var skip = it.skip;
var only = it.only;
describe("开始ukey测试...", function () {
    var config = null;
    try {
        config = require('./config.js');
    } catch (error) {
        config = require('./config.default.js');
    }

    step('01 测试获取序列号列表：ukeyEnumDevice', function (done) {
        key.ukeyEnumDevice(function (err, ret) {
            expect(ret.err).to.be.equal(0);
            expect(ret.pbNameList).to.have.length.least(1);
            if (ret.err === 0) {
                config.pbDevSN = ret.pbNameList[0]; // 默认用第一个来测试
            }
            done();
        })
    });

    step('02 测试打开ukey：ukeyOpenDevice', function (done) {
        key.ukeyOpenDevice(config.pbDevSN, function (err, ret) {
            expect(ret.err).to.be.equal(0);
            config.hDev = ret.phDev;
            done();
        })
    });

    // 03 ukeyCloseDevice

    skip('04 测试初始化设备：ukeyFormatDevice', function (done) {
        key.ukeyFormatDevice(config.hDev, config.pbAdminPin, function (err, ret) {
            expect(ret.err).to.be.equal(0);
            done();
        })
    });

    step('05 测试验证用管理员户口令是否是原始的：ukeyIsDefaultPin', function (done) {
        key.ukeyIsDefaultPin(config.hDev, config.dwPinType.ADMIN_TYPE, function (err, ret) {
            expect(ret.err).to.be.equal(0);
            done();
        })
    });

    step('05 测试验证用用户户口令是否是原始的：ukeyIsDefaultPin', function (done) {
        key.ukeyIsDefaultPin(config.hDev, config.dwPinType.USER_TYPE, function (err, ret) {
            expect(ret.err).to.be.equal(0);
            done();
        })
    });

    step('06 测试验证用普通用户户口令是否正确：ukeyVerifyPin', function (done) {
        key.ukeyVerifyPin(config.hDev, config.dwPinType.USER_TYPE, config.pbUserPin, function (err, ret) {
            expect(ret.err).to.be.equal(0);
            done();
        })
    });

    step('06 测试验证用管理用户户口令是否正确：ukeyVerifyPin', function (done) {
        key.ukeyVerifyPin(config.hDev, config.dwPinType.ADMIN_TYPE, config.pbAdminPin, function (err, ret) {
            expect(ret.err).to.be.equal(0);
            done();
        })
    });

    // 本测试用例通过了，不反复测试修改密码，如果需要测试，将skip改为step
    skip('07 测试修改普通用户口令：ukeyChangePin', function (done) {
        key.ukeyChangePin(config.hDev, config.dwPinType.USER_TYPE, config.pbUserPin, config.pbNewUserPin, function (err, ret) {
            expect(ret.err).to.be.equal(0);
            done();
        })
    });

    // 本测试用例通过了，不反复测试修改密码，如果需要测试，将skip改为step
    skip('07 测试修改管理员口令：ukeyChangePin', function (done) {
        key.ukeyChangePin(config.hDev, config.dwPinType.ADMIN_TYPE, config.pbAdminPin, config.pbNewAdminPin, function (err, ret) {
            expect(ret.err).to.be.equal(0);
            done();
        })
    });

    step('08 在USBKEY中生成指定类型的密钥对：ukeyRSAGenKey', function (done) {
        key.ukeyRSAGenKey(config.hDev, function (err, ret) {
            expect(ret.err).to.be.equal(0);
            done();
        })
    });

    step('09 在USBKEY中生成指定类型的密钥对：ukeyECCGenKey', function (done) {
        key.ukeyECCGenKey(config.hDev, function (err, ret) {
            expect(ret.err).to.be.equal(0);
            done();
        })
    });

    step('10 导出指定密钥类型的公钥：ukeyRSAGetPubKey', function (done) {
        key.ukeyRSAGetPubKey(config.hDev, function (err, ret) {
            expect(ret.err).to.be.equal(0);
            done();
        })
    });

    step('11 导出指定密钥类型的公钥：ukeyECCGetPubKey', function (done) {
        key.ukeyECCGetPubKey(config.hDev, function (err, ret) {
            expect(ret.err).to.be.equal(0);
            if (ret.err === 0) {
                config.eccPbMPubKey = ret.pbPubKey;
            }
            done();
        })
    });

    step('AA 获取ECC地址：ukeyECCAddress', function (done) {
        key.ukeyECCAddress(config.hDev, function (err, ret) {
            expect(ret.err).to.be.equal(0);
            done();
        })
    });

    it('12 导入RSA2048证书到USBKEY中：ukeyImportRSACert', function (done) {
        key.ukeyImportRSACert(config.hDev, config.pbCert, function (err, ret) {
            expect(ret.err).to.be.equal(0);
            done();
        })
    });

    it('13 导出RSA2048证书：ukeyExPortRSACert', function (done) {
        key.ukeyExPortRSACert(config.hDev, function (err, ret) {
            expect(ret.err).to.be.equal(0);
            done();
        })
    });

    step('14 RSA加密：ukeyRSAEncrypt', function (done) {
        key.ukeyRSAEncrypt(config.hDev, config.pbDataRSA, function (err, ret) {
            expect(ret.err).to.be.equal(0);
            done();
        })
    });

    step('15 17 RSA2048密钥对签名，RSA2048密钥对验签：ukeyRSASign，ukeyRSAVerifySign', function (done) {
        key.ukeyRSASign(config.hDev, config.dwHashAlg, config.pbDataRSA, function (err, ret) {
            expect(ret.err).to.be.equal(0);
            if (ret.err === 0) {
                key.ukeyRSAVerifySign(config.hDev, config.dwHashAlg, config.pbDataRSA, ret.pbSign, function (err, ret) {
                    expect(ret.err).to.be.equal(0);
                    done();
                })
            } else {
                done();
            }
        })
    });

    it('16 18 ECDSA签名，ECC验签：ukeyECCSign，ukeyECCVerifySign', function (done) {
        key.ukeyECCSign(config.hDev, config.pbMsgRlp, config.pbShowData, function (err, ret) {
            expect(ret.err).to.be.equal(0);
            if (ret.err === 0) {
                key.ukeyECCVerifySign(config.hDev, ret.pbSignRlp, function (err, ret) {
                    expect(ret.err).to.be.equal(0);
                    done();
                })
            } else {
                done();
            }
        })
    });

    step('27 28 Unkown：ukeyWDScardEncryptECIES，ukeyWDScardDecryptECIES', function (done) {
        key.ukeyWDScardEncryptECIES(config.hDev, config.pbData, function (err, ret) {
            expect(ret.err).to.be.equal(0);
            config.pbUPriKey = ret.pbEncryptedData;
            if (err === 0) {
                key.ukeyWDScardDecryptECIES(config.hDev, ret.pbEncryptedData, function (err, ret) {
                    expect(ret.err).to.be.equal(0);
                    done();
                })
            } else {
                done();
            }
        })
    });

    step('23 导入群签名用户私钥：ukeyImportUPriKey', function (done) {
        key.ukeyImportUPriKey(config.hDev, config.pbUPriKey, function (err, ret) {
            expect(ret.err).to.be.equal(0);
            done();
        })
    });

    step('22 导入群签名系统公钥：ukeyImportUPriKey', function (done) {
        key.ukeyImportMPubKey(config.hDev, config.pbMPubKey, function (err, ret) {
            expect(ret.err).to.be.equal(0);
            done();
        })
    });

    step('21 判断用户私钥和系统公钥是否已导入：ukeyImportUPriKey', function (done) {
        key.ukeyCheckKeyPair(config.hDev, function (err, ret) {
            expect(ret.err).to.be.equal(0);
            done();
        })
    });

    step('19 20 广播加密，广播解密：ukeyEnc，ukeyDec', function (done) {
        config.pbGroup_PubKey = config.eccPbMPubKey.repeat(config.dwGroupNum);
        key.ukeyEnc(config.hDev, config.pbMessage, config.dwGroupNum, config.pbGroup_PubKey, function (err, ret) {
            expect(ret.err).to.be.equal(0);
            if (ret.err === 0) {
                key.ukeyDec(config.hDev, ret.pbCipherText, config.dwGroupNum, function (err, ret) {
                    expect(ret.err).to.be.equal(0);
                    done();
                })
            } else {
                done();
            }
        })
    });

    step('24 25 群签名，群签名验签：ukeyGSSign，ukeyGSVerify', function (done) {
        key.ukeyGSSign(config.hDev, config.pbHash, function (err, ret) {
            expect(ret.err).to.be.equal(0);
            if (ret.err === 0) {
                key.ukeyGSVerify(config.hDev, config.pbHash, ret.pbSign, function (err, ret) {
                    expect(ret.err).to.be.equal(0);
                    done();
                })
            } else {
                done();
            }
        })
    });

    it('26 交易隐私保护接口：ukeyTradeSignProtect', function (done) {
        config.pbGroup_PubKey = config.pbMPubKey.repeat(config.dwGroupNum);
        key.ukeyTradeSignProtect(config.hDev, config.pbMsg, config.pbShowData, config.dwGroupNum, config.pbGroup_PubKey, function (err, ret) {
            expect(ret.err).to.be.equal(0);
            done();
        })
    });
    step('29 30 写数据到设备中，从数据中读取设备：ukeyWriteData，ukeyReadData', function (done) {
        var pbData = config.dataToKey;
        key.ukeyWriteData(config.hDev, pbData, function (err, ret) {
            expect(ret.err).to.be.equal(0);
            if (ret.err === 0) {
                key.ukeyReadData(config.hDev, function (err, ret) {
                    expect(ret.err).to.be.equal(0);
                    expect(ret.pbData).to.equal(pbData);
                    done();
                })
            } else {
                done();
            }
        })
    });

    step('03 测试关闭ukey：ukeyCloseDevice', function (done) {
        key.ukeyCloseDevice(config.hDev, function (err, ret) {
            expect(ret.err).to.be.equal(0);
            done();
        })
    });
})

