安装
-----
`npm install git+ssh://http://luchenqun:fendoubuxi@192.168.9.66/Juzix-ethereum/key-manager.git#develop`   
如果是写到package.json里面，以git协议这么写：
`'key-manager':git+ssh://http://luchenqun:fendoubuxi@192.168.9.66/Juzix-ethereum/key-manager.git#develop`

说明
-----
1. 大部分文件方法提供同步以及异步的调用。建议使用均使用异步调用。异步调用大部分回调函数均以`function(err, data1, data2, ...){}`返回，第一个参数是错误返回代码，0为正常，其他为异常。
2. 所有ukey的调用函数均为ukey开头，用来区分与文件证书的函数接口。
3. 如果需要使用ukey的接口，首先需要安装ukey的驱动，clone下来之后，文件为`./dynamic/JuZhenUSBKey.exe`。然后需要安装node-gyp的环境：[node-gyp环境搭建](https://github.com/nodejs/node-gyp#installation)。安装好node-gyp环境之后，因为执行`npm install`的时候使用的node的版本可能跟electron使用的版本不一致，所以你需要重新安装（其实就是用electron依赖的node版本重新编译）key-manager依赖的包，官方文档[Using Native Node Modules](https://electron.atom.io/docs/tutorial/using-native-node-modules/)供参考。这里也有一篇中文[Electron 使用 Node 原生模块](http://www.jianshu.com/p/9ce7a9ccdc78)供参考。上面的中文参考我使用命令没法设置成功，最后我只直接把下面的配置拷贝到了.npmrc文件下面。下面配置仅供参考。当然，安装过程需要全局翻墙，你懂的！
```
target=1.7.5  -- 你的electron版本
arch=x64   -- 你的系统位数
target_arch=x64 --目标系统位数
disturl=https://atom.io/download/electron
runtime=electron
build_from_source=true
```

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

测试
-----
目前写了所有的ukey的测试用例，如果你需要测试，请在`test`目录下面以config.default.js为蓝本，重新生成一份你的ukey信息的config.js配置，然后执行`npm run test`即可。里面有一些调用接口的示例，也可进行参考。


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

### **`ukeyEnumDevice`** 
枚举所有设备，并返回设备的序列号列表 
入参：
* 无 

出参：
* `pbNameList`: Array 所有设备的名称

### **`ukeyOpenDevice`**  
创建USBKEY设备上下文并打开USBKEY设备   
入参：
* `pbDevSN`: String 需要打开设备的序列号  

出参：
* `phDev`: Integer 设备操作句柄

### **`ukeyCloseDevice`**  
关闭USBKEY设备，并释放设备上下文    
入参：
* `hDev`: Integer 连接设备时返回的设备句柄  

出参：
* 无

### **`ukeyFormatDevice`**  
初始化设备       
入参：
* `hDev`: Integer 连接设备时返回的设备句柄  
* `pbSoPin`: String 管理员PIN   

出参：
* 无

### **`IsDefaultPin`**  
判断是否是初始PIN          
入参：
* `hDev`: Integer 连接设备时返回的设备句柄  
* `dwPinType`: Integer PIN类型 0：管理员PIN，1：用户PIN

出参：
* `pbDefaultPin`: Boolean true 初始PIN，false 非初始PIN

### **`ukeyVerifyPin`**  
验证用户口令   
入参：
* `hDev`: Integer 连接设备时返回的设备句柄  
* `dwPinType`: Integer PIN类型 0：管理员PIN，1：用户PIN
* `pbUserPin`: String 用户PIN   

出参：
* `pdwRetryCount`: Integer 出错后返回的重试次数

### **`ukeyChangePin`**  
修改用户口令          
入参：
* `hDev`: Integer 连接设备时返回的设备句柄  
* `dwPinType`: Integer PIN类型 0：管理员PIN，1：用户PIN
* `pbOldPin`: String 旧PIN 
* `pbNewPin`: String 新PIN 

出参：
* `pbDefaultPin`: Boolean true 初始PIN，false 非初始PIN

### **`ukeyRSAGenKey`**   
在USBKEY中生成指定类型的密钥对   
入参：
* `hDev`: Integer 连接设备时返回的设备句柄 

出参：
* 无

### **`ukeyECCGenKey`**
在USBKEY中生成指定类型的密钥对   
入参：
* `hDev`: Integer 连接设备时返回的设备句柄   

出参：
* 无

### **`ukeyRSAGetPubKey`**
导出指定密钥类型的公钥   
入参：
* `hDev`: Integer 连接设备时返回的设备句柄   

出参：
* `pbPubKey`: String 生成的用户公钥

### **`ukeyECCGetPubKey`**
导出指定密钥类型的公钥   
入参：
* `hDev`: Integer 连接设备时返回的设备句柄   

出参：
* `pbPubKey`: String 生成的用户公钥

### **`ukeyImportRSACert`**
导入RSA2048证书到USBKEY中。证书编码格式为PEM或者DER      
入参：
* `hDev`: Integer 连接设备时返回的设备句柄   
* `pbCert`: String 证书数据(其实是证书路径)   

出参：
* 无

### **`ukeyExPortRSACert`**
导出RSA2048证书。证书编码格式为PEM      
入参：
* `hDev`: Integer 连接设备时返回的设备句柄   

出参：
* `pbCert`: String 证书数据

### **`ukeyRSAEncrypt`**
RSA加密      
入参：
* `hDev`: Integer 连接设备时返回的设备句柄   
* `pbData`: String 明文数据   

出参：
* `pbCipher`: String 密文

### **`ukeyRSASign`**
支持RSA2048密钥对签名       
入参：
* `hDev`: Integer 连接设备时返回的设备句柄   
* `dwHashAlg`: Integer Hash算法，MD5:1,SHA1:2,SHA256:3,SHA3:4   
* `pbData`: String 待签名消息数据   

出参：
* `pbSign`: String 签名值

### **`ukeyECCSign`**
支持ECDSA签名       
入参：
* `hDev`: Integer 连接设备时返回的设备句柄   
* `pbMsgRlp`: String 待签名消息数据，需要注意的是，数据必须是RLP的编码方式。   

出参：
* `pbSignRlp`: String 签名值

### **`ukeyRSAVerifySign`**
支持RSA2048密钥对验签       
入参：
* `hDev`: Integer 连接设备时返回的设备句柄   
* `dwHashAlg`: Integer Hash算法，MD5:1,SHA1:2,SHA256:3,SHA3:4   
* `pbData`: String 待签名消息数据   
* `pbSign`: String 签名值   

出参：
* 无

### **`ukeyECCVerifySign`** 
支持ECC验签   
入参：
* `hDev`: Integer 连接设备时返回的设备句柄   
* `pbSignRlp`: String 签名值   

出参：
* 无

### **`ukeyEnc`**
根据广播加密算法机制对数据进行加密   
入参：
* `hDev`: Integer 连接设备时返回的设备句柄   
* `pbMessage`: String 待加密的明文数据   
* `dwGroupNum`: Integer 群成员个数（小于100）   
* `pbGroup_PubKey`: String 群成员公钥（长度nGroupNum*Point_Len）   

出参：
* `pbCipherText`: String 密文

### **`ukeyDec`**
ECC广播解密   
入参：
* `hDev`: Integer 连接设备时返回的设备句柄   
* `pbCipherText`: String 密文数据   
* `dwGroupNum`: Integer 群成员个数（小于100）   

出参：
* `pbMessage`: String 解密的明文数据

### **`ukeyCheckKeyPair`**
判断用户私钥和系统公钥是否已导入   
入参：
* `hDev`: Integer 连接设备时返回的设备句柄   

出参：
* 无

### **`ukeyImportMPubKey`**
导入群签名系统公钥   
入参：
* `hDev`: Integer 连接设备时返回的设备句柄   
* `pbMPubKey`: String 群签名系统公钥   

出参：
* 无

### **`ukeyImportUPriKey`**
导入群签名用户私钥   
入参：
* `hDev`: Integer 连接设备时返回的设备句柄   
* `pbUPriKey`: String 群签名用户私钥   

出参：
* 无

### **`ukeyGSSign`**
群签名   
入参：
* `hDev`: Integer 连接设备时返回的设备句柄   
* `pbHash`: String 签名消息的摘要   

出参：
* `pbSign`: String 签名值

### **`ukeyGSVerify`**
群签名验签   
入参：
* `hDev`: Integer 连接设备时返回的设备句柄   
* `pbHash`: String 签名消息的摘要   
* `pbSign`: String 签名值   

出参：
* 无

### **`ukeyTradeSignProtect`**
交易隐私保护接口：即以交易为输入，先对交易进行ECDSA签名，再对整个数据和签名进行广播加密，最后对整个密文进行群签名作为输出(暂不能用)   
入参：
* `hDev`: Integer 连接设备时返回的设备句柄   
* `pbMsg`: String 待签名的交易数据原文   
* `dwGroupNum`: Integer 群成员个数（小于100）   
* `pbGroup_PubKey`: String 群成员公钥（长度nGroupNum*Point_Len）   

出参：
* `pbSign`: 签名值

### **`ukeyWDScardEncryptECIES`**
暂无描述，待确定   
入参：
* `hDev`: Integer 连接设备时返回的设备句柄   
* `pbData`: String 待签名消息数据   

出参：
* `pbEncryptedData`: String 加密后的数据

### **`ukeyWDScardDecryptECIES`**
暂无描述，待确定   
入参：
* `hDev`: Integer 连接设备时返回的设备句柄   
* `pbEncryptedData`: String 加密后的数据   

出参：
* `pbDecryptedData`: String 原始数据

### **`ukeyECCAddress`**
获取地址   
入参：
* `hDev`: Integer 连接设备时返回的设备句柄   

出参：
* `address`: String 地址信息

