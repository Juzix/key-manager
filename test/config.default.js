module.exports = {
    hDev: -1, // 打开设备之后返回的句柄
    pbDevSN: 'JUZHEN0123456787',
    pbUserPin: '123456',  // 用户pin 默认jz8888
    pbAdminPin: 'jz1234',  // 管理员pin 默认 jz1234
    pbNewUserPin: '123456',  // 用户pin
    pbNewAdminPin: '123456',  // 管理员pin
    pbCert: '../data/ca.crt.pem',// 导入证书路径
    dwHashAlg: 3,   // Hash算法，MD5:1,SHA1:2,SHA256:3,SHA3:4
    pbDataRSA: 'hello', // 测试的入参RSA数据
    // pbMsgRlp 测试的ECC入参数据，RLP编码
    pbMsgRlp: 'F901FA808504E3B292008502540BE3FF941176FD5DC45001002EB2B893E5EF7C488475640780B901D4B1498E290000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000018A7B226964223A227371732D31222C226E616D65223A22535153222C22706172656E744964223A2261646D696E222C226465736372697074696F6E223A22626C6F636B636861696E20706C6174222C22636F6D6D6F6E4E616D65223A225465737431222C2273746174654E616D65223A224744222C22636F756E7472794E616D65223A22434E222C22656D61696C223A227465737431403132362E636F6D222C2274797065223A312C22656E6F64654C697374223A5B7B227075626B6579223A2230783331643137376235623261626133396531633330366331623333383334643234356538356435373763343332366237363162373334323365636139303063616536366638376432333430633135356634303238353832303663396533656566653830376363323433616636323864623138363064393965373132653535343862222C226970223A223139322E3136382E31302E3335222C22706F7274223A223130303031227D5D2C22726F6C6549644C697374223A5B5D2C2266696C6549644C697374223A5B5D7D000000000000',
    pbMessage: 'hello', // 广播加密入参数据
    dwGroupNum: 2,  // 群公钥把数
    pbGroup_PubKey: '', // 根据dwGroupNum，拼接pbMPubKey几次
    pbUPriKey: '',  // 调用ukeyWDScardEncryptECIES获取
    eccPbMPubKey:'',
    // pbMPubKey 群签名系统公钥
    pbMPubKey: '248aa357395507e74130bf7e38196be8c000f279b1d0a1984ac098077db89a8f3c3e1a8f68c970041cabaf744baf408c6fd16eb1716f7a7ff6e0a4f61b6f7145aedb4830f347e9a8a97c573304cd80709e99356a5aec51574c0c42b9a2bae8a912ea5b0a7ee8dddfad3743f150cdee36b53b95f32220c13251cb8ee5dcbb76323377537273baf0e75381b828cd962ad7b662fac1ddc63ec38db198bf09105b0a551059faf7c013c3839b2d56cc360ae679b5c0df6e45a87b0a90c52152435ace732122c0d6fd9ffc1c3542b04fb938c900781185a1cce6c38670b85001d2220626bcd16c2ab8a00a91ef70e83d4db0e77cc9ddc8ce64844aa087b4c8c041a077',
    pbHash: 'f848368504e3b292008502540be3ff941176fd5dc45001002eb2b893e5ef7c488475640780a440a5737f000000000000000000000000000000000000000000000000000000000000001e',
    pbMsg: 'f84b488504e3b292008502540be3ff941176fd5dc45001002eb2b893e5ef7c488475640780a440a5737f000000000000000000000000000000000000000000000000000000000000001e1c8080',
    pbData: '3349fbeff062de101f8f43dc04fb4b523ea665c39b1f76fb7fd85d06d85287a5674fa519e2f89de5d81aca267aa00a3ef6590a532270b0142059e46641898b538be96503a2c72ff19af2c1a923b79a719258a7c22d3c0d2c817d629f79d7c7e7',
    dwPinType: {
        ADMIN_TYPE: 0,  // 管理员PIN类型
        USER_TYPE: 1,// 普通用户PIN类型
    },
    dataToKey: new Date().getTime().toString(), // 写到key里面的数据
    pbShowData: "我爱 this world 呵呵哒",
    dwKeyLen: 128,   // 公私钥长度
    pbPubKey_n: '',
    // pbMsgPAI 128 等测试样例不能过
    pbMsgPAI:1111,//'0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000AABBCC', // WDScardEncryption_PAI 待加密的消息
    pbCipherA:'',
    pbCipherB:'',
    pbResult: '',
}
