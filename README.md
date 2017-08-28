安装
-----
`npm install git+ssh://http://luchenqun:fendoubuxi@192.168.9.66/Juzix-ethereum/key-manager.git#develop`   
如果是写到package.json里面，以git协议这么写：
`'key-manager':git+ssh://http://luchenqun:fendoubuxi@192.168.9.66/Juzix-ethereum/key-manager.git#develop`

说明
-----
1. 大部分文件方法提供同步以及异步的调用。建议使用均使用异步调用。异步调用大部分回调函数均以`function(err, data1, data2, ...){}`返回，第一个参数是错误返回代码，0为正常，其他为异常。
2. 所有ukey的调用函数均为ukey开头，用来区分与文件证书的函数接口。0
3. 如果需要使用ukey的接口，需要安装node-gyp的环境：[node-gyp环境搭建](https://github.com/nodejs/node-gyp#installation)。

使用
-----
如果你在Node.js环境下面使用，先引入：
`var key = require("key-manager");`   
所有的的文件默认存在DEFAULT_PATH下面，获取方式如下。即当前用户的home目录的keystores下面。下面示例代码的DEFAULT_PATH也是来自如此。
```JavaScript
var path = require("path");
var os = require('os');
const DEFAULT_PATH = path.join(os.homedir(), 'keystores');
```   

所有的ukey方法由于提供的动态库均是同步调用。为了跟文件证书的调用保持一致。提供同步与异步的调用。异步调用回调函数均以`function(err, ret){}`返回。第一个参数是错误返回代码，0为正常，-100为系统无法调用ukey提供的动态库(比如在Ubuntu下调用)，其它代码为ukey厂商提供的。`ret`为一个对象，下面以调用RSA加密函数说明，演示函数的调用以及返回值。其他调用均与此类似，不再做说明。建议使用者均使用回调的方式调用。示例如下：
```JavaScript
var key = require("key-manager");

var pbData = 'i love this world';
var ret1 = key.ukeyRSAEncrypt(pbData, function(err, ret2){
    // err 为返回的错误码。
    // ret2 为回调函数里面的返回对象，类似如下：
    //{
    //   err: 0,
    //   pbCipher:'4b608752d8e48cf...'
    //}
    // 特此说明：对于回调函数第一个参数返回了err，返回的第二个对象还有err属性主要是为了同步返回的对象需要一个err。
})
// ret1 为同步调用返回的值，与异步调用里面的ret2的值是一样的。当然，如果想同步调用，回调函数可以省略不写，类似这样如下:
var ret1 = key.ukeyRSAEncrypt(pbData);
```   

文件证书常用方法说明 
--------------------------  
#### 1 创建key
|     参数       |             说明                   |
| :------------    | :--------------------------------- |
| username         | 用户账号                            |
| password         | 用户密码                            |
| cb(err, keyObject) | 回调函数，如果不传，那么同步调用      |
返回值说明：一个新的keyObject对象。
```JavaScript
// 同步创建key
var keyObject = key.createKey('lcq', '123456');

// 异步创建key
key.createKey('lcq', '123456', function(err, keyObject) {
    console.log(keyObject);
});

创建出来的key对象类似如下
{
    "address":"2f10359548470362201e13ea11f64cee0fd0cfbf",
    "crypto":{
        "cipher":"aes-128-ctr",
        "ciphertext":"232c3f5f29b522aa1581087906bf4bcd2fd2d56cb5b26fef1ce51d40ec1788d4",
        "cipherparams":{
            "iv":"79734181aacfe629d84d575860ffb426"
        },
        "mac":"6de93cc426ed67840d98b246d83e3dcebbd09b77fdc062a750278e00b5844d92",
        "kdf":"pbkdf2",
        "kdfparams":{
            "c":262144,
            "dklen":32,
            "prf":"hmac-sha256",
            "salt":"e3846591d0b83c211b384ad4a9db4116aa9bfd0dada7fbd36edd27acf4a275f4"
        }
    },
    "id":"5c3eb953-bc5c-4512-ad0b-a8365a7ec414",
    "version":3,
    "username":"lcq"
}
```

### 2 导出Key到文件
|     参数      |             说明                   |
| :------------   | :--------------------------------- |
| keyObject       | 生成的key对象，调用函数               |
| keystore        | 导出的目录                            |
| outfileName        | 导出的文件名                            |
| cb(err, outpath)  | 回调函数，如果不传，那么同步调用      |
返回值说明：导出的文件路径outpath。
```JavaScript
var keyObject = key.createKey('lcq', '123456');
// 异步导出
key.exportToFile(keyObject, DEFAULT_PATH, 'lcq.json', function(err, outpath){
    console.log(outpath);
});
```

### 3 根据用户名导出key
|     参数      |             说明                   |
| :------------   | :--------------------------------- |
| username       | 用户名               |
| keystore        | 目录路径                            |
| cb(err, keyObject)  | 回调函数，如果不传，那么同步调用      |
返回值说明：用户对应的keyObject。
```JavaScript
key.importFromUsername('lcq', DEFAULT_PATH, function(err, keyObject){
    console.log(keyObject);
});
```

### 4 根据目录读取所有的key
|     参数      |             说明                   |
| :------------   | :--------------------------------- |
| keystore       | 目录名               |
| cb(err, keyObjects) | 回调函数，如果不传，那么同步调用      |
返回值说明：该目录下面的所有keyObjects，为数组对象。
```JavaScript
key.importFromDir(DEFAULT_PATH, function(err, keyObjects){
    console.log(keyObjects);
});
```

### 5 重置key
|     参数      |             说明                   |
| :------------   | :--------------------------------- |
| oldPassword       | 旧密码               |
| newPassword       | 新密码               |
| keyObject       | 旧key               |
| cb(err, newKeyObject)   | 回调函数，如果不传，那么同步调用      |
返回值说明：根据用户新密码产生的新newKeyObject。
```JavaScript
var keyObject = key.createKey('lcq', '123456');
key.resetPassword('123456', '654321', keyObject, function(err, newKeyObject){
    console.log(newKeyObject);
});
```

### 6 获取key的私钥
|     参数      |             说明                   |
| :------------   | :--------------------------------- |
| password       | 密码               |
| keyObject       | key               |
| cb(err, privateKey) | 回调函数，如果不传，那么同步调用      |
返回值说明：用户的私钥。类型为string。
```JavaScript
var keyObject = key.createKey('lcq', '123456');
key.recover('123456', keyObject, function(err, privateKey){
    console.log(privateKey);
});
```

### 7 根据私钥获取公钥
|     参数      |             说明                   |
| :------------   | :--------------------------------- |
| privateKey       | 私钥               |
| cb(err, publicKey) | 回调函数，如果不传，那么同步调用      |
返回值说明：用户的公钥。类型为string。
```JavaScript
key.getPublicKey(privateKey, function(err, publicKey){
    console.log(publicKey);
});
```

### 8 根据文件路径，获取对应的keyObject
|     参数      |             说明                   |
| :------------   | :--------------------------------- |
| filePath       | 文件路径               |
| cb(err, keyObject) | 回调函数，如果不传，那么同步调用      |
返回值说明：文件名对应的keyObject。
```JavaScript
key.importFromFilePath(filePath, function(err, keyObject){
    console.log(keyObject);
});
```

### 9 导入keyObjects
|     参数      |             说明                   |
| :------------   | :--------------------------------- |
| srcDir       | 原目录               |
| distDir       | 目标目录               |
| cb(err, files) | 回调函数，如果不传，那么同步调用      |
返回值说明：导入成功的文件名。注意，只导入当前目录下面的文件后缀为.json文件，同时不会去导入该目录下面的子目录。
```JavaScript
key.restoreKeys('C:/Users/lcq/Desktop/keys', DEFAULT_PATH, function(err, files){
    console.log(err, files);
});
```

ukey常用方法说明 
--------------------------
关于`入参`与`出参`的说明：如果有入参，则按照入参的描述，依次传入参数，最后传入回调函数。如果入参描述`无`，则只需要传入回调函数。如果出参描述`无`，则可在同步调用返回的对象，或者异步调用返回的对象里面只有err属性，如果有出参描述，则可在返回的对象里面找到该属性对应的值。若函数无特别说明，ukey的函数调用均遵守此规则！
### 01 创建USBKEY设备上下文并打开USBKEY设备
函数名称：**`ukeyOpenDevice`**   
入参：
* 无  

出参：
* 无

### 02 关闭USBKEY设备，并释放设备上下文
函数名称：**`ukeyCloseDevice`**   
入参：
* 无  

出参：
* 无

### 03 验证用户口令
函数名称：**`ukeyVerifyPin`**   
入参：
* `pbUserPin`: String 用户PIN   

出参：
* 无

### 04 在USBKEY中生成指定类型的密钥对
函数名称：**`ukeyRSAGenKey`**   
入参：
* 无  

出参：
* 无

### 05 在USBKEY中生成指定类型的密钥对
函数名称：**`ukeyECCGenKey`**   
入参：
* 无  

出参：
* 无

### 06 导出指定密钥类型的公钥
函数名称：**`ukeyRSAGetPubKey`**   
入参：
* 无 

出参：
* `pbPubKey`: String 生成的用户公钥

### 07 导出指定密钥类型的公钥
函数名称：**`ukeyECCGetPubKey`**   
入参：
* 无 

出参：
* `pbPubKey`: String 生成的用户公钥

### 08 导入RSA2048证书到USBKEY中。证书编码格式为PEM或者DER
函数名称：**`ukeyImportRSACert`**   
入参：
* `pbCert`: String 证书数据(其实是证书路径)   

出参：
* 无

### 09 导出RSA2048证书。证书编码格式为PEM
函数名称：**`ukeyExPortRSACert`**   
入参：
* 无  

出参：
* `pbCert`: String 证书数据

### 10 RSA加密
函数名称：**`ukeyRSAEncrypt`**   
入参：
* `pbData`: String 明文数据   

出参：
* `pbCipher`: String 密文

### 11 支持RSA2048密钥对签名
函数名称：**`ukeyRSASign`**   
入参：
* `dwHashAlg`: Integer Hash算法，MD5:1,SHA1:2,SHA256:3,SHA3:4   
* `pbData`: String 待签名消息数据   

出参：
* `pbSign`: String 签名值

### 12 支持ECDSA签名
函数名称：**`ukeyECCSign`**   
入参：
* `pbMsgRlp`: String 待签名消息数据   

出参：
* `pbSignRlp`: String 签名值

### 13 支持RSA2048密钥对验签
函数名称：**`ukeyRSAVerifySign`**   
入参：
* `dwHashAlg`: Integer Hash算法，MD5:1,SHA1:2,SHA256:3,SHA3:4   
* `pbData`: String 待签名消息数据   
* `pbSign`: String 签名值   

出参：
* 无

### 14 支持ECC验签
函数名称：**`ukeyECCVerifySign`**   
入参：
* `pbSignRlp`: String 签名值   

出参：
* 无

### 15 根据广播加密算法机制对数据进行加密
函数名称：**`ukeyEnc`**   
入参：
* `pbMessage`: String 待加密的明文数据   
* `dwGroupNum`: Integer 群成员个数（小于100）   
* `pbGroup_PubKey`: String 群成员公钥（长度nGroupNum*Point_Len）   

出参：
* `pbCipherText`: String 密文

### 16 ECC广播解密
函数名称：**`ukeyDec`**   
入参：
* `pbCipherText`: String 密文数据   
* `dwGroupNum`: Integer 群成员个数（小于100）   

出参：
* `pbMessage`: String 解密的明文数据

### 17 判断用户私钥和系统公钥是否已导入
函数名称：**`ukeyCheckKeyPair`**   
入参：
* 无

出参：
* 无

### 18 导入群签名系统公钥
函数名称：**`ukeyImportMPubKey`**   
入参：
* `pbMPubKey`: String 群签名系统公钥   

出参：
* 无

### 19 导入群签名用户私钥
函数名称：**`ukeyImportUPriKey`**   
入参：
* `pbUPriKey`: String 群签名用户私钥   

出参：
* 无

### 20 群签名
函数名称：**`ukeyGSSign`**   
入参：
* `pbHash`: String 签名消息的摘要   

出参：
* `pbSign`: String 签名值

### 21 群签名验签
函数名称：**`ukeyGSVerify`**   
入参：
* `pbHash`: String 签名消息的摘要   
* `pbSign`: String 签名值   

出参：
* 无

### 22 交易隐私保护接口：即以交易为输入，先对交易进行ECDSA签名，再对整个数据和签名进行广播加密，最后对整个密文进行群签名作为输出(暂不能用)
函数名称：**`ukeyTradeSignProtect`**   
入参：
* `pbMsg`: String 待签名的交易数据原文   
* `dwGroupNum`: Integer 群成员个数（小于100）   
* `pbGroup_PubKey`: String 群成员公钥（长度nGroupNum*Point_Len）   

出参：
* `pbSign`: 签名值

### 23 暂无描述，待确定
函数名称：**`ukeyWDScardEncryptECIES`**   
入参：
* `pbData`: String 待签名消息数据   

出参：
* `pbEncryptedData`: String 加密后的数据

### 24 暂无描述，待确定
函数名称：**`ukeyWDScardDecryptECIES`**   
入参：
* `pbEncryptedData`: String 加密后的数据   

出参：
* `pbDecryptedData`: String 原始数据

### 25 获取地址
函数名称：**`ukeyECCAddress`**   
入参：
* 无 

出参：
* `address`: String 地址信息

