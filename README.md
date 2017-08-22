安装
-----
`npm install git+ssh://http://luchenqun:fendoubuxi@192.168.9.66/Juzix-ethereum/key-manager.git#develop`   
如果是写到package.json里面，以git协议这么写：
`'key-manager':git+ssh://http://luchenqun:fendoubuxi@192.168.9.66/Juzix-ethereum/key-manager.git#develop`

说明
-----
1. 大部分方法提供同步以及异步的调用。建议使用均使用异步调用。异步调用大部分回调函数均以`function(err, data1, data2, ...){}`返回，第一个参数是错误返回代码，0为正常，其他为异常。

使用
-----
如果你在Node.js环境下面使用，先引入：
`var keyManager = require("key-manager");`   
所有的的文件默认存在DEFAULT_PATH下面，获取方式如下。即当前用户的home目录的keystores下面。下面示例代码的DEFAULT_PATH也是来自如此。
```JavaScript
var fs = require("fs");
var path = require("path");
var os = require('os');
const DEFAULT_PATH = path.join(os.homedir(), 'keystores');
```   

常用方法使用示例如下：   
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
    "address":"f268ae4b262baed1e1a265dc6af46b6f496535ba",
    "crypto":{
        "cipher":"aes-128-ctr",
        "ciphertext":"27a21f8d8e94b17a95d769b4451ed513be11c5ca9fa32b37cc4cee463c9b9705",
        "cipherparams":{
            "iv":"45fa7893a1574f4928fa237d0e13e19c"
        },
        "mac":"b0c5e6626f1b6036c8ad86960d441f64967ad894750c726a5c8615dd3facbcc5",
        "kdf":"pbkdf2",
        "kdfparams":{
            "c":262144,
            "dklen":32,
            "prf":"hmac-sha256",
            "salt":"b865ddff48a195f78ab299e022430a558daa48fd71da24de3b3da55b034d811b"
        }
    },
    "id":"lcq",
    "version":3
}
```

### 2 导出Key到文件
|     参数      |             说明                   |
| :------------   | :--------------------------------- |
| keyObject       | 生成的key对象，调用函数               |
| keystore        | 导出的目录                            |
| outfile        | 导出的文件名                            |
| cb(err, outpath)  | 回调函数，如果不传，那么同步调用      |
返回值说明：导出的文件路径outpath。
```JavaScript
var keyObject = key.createKey('lcq', '123456');
// 异步导出
key.exportToFile(keyObject, DEFAULT_PATH, 'lcq.json', function(err, outpath){
    console.log(outpath);
});
```

### 3 根据用户名导入key
|     参数      |             说明                   |
| :------------   | :--------------------------------- |
| username       | 用户名               |
| datadir        | 导入的目录                            |
| cbfunction(err, keyObject)  | 回调函数，如果不传，那么同步调用      |
返回值说明：用户对应的keyObject。
```JavaScript
key.importFromFile('lcq', DEFAULT_PATH, function(err, keyObject){
    console.log(keyObject);
});
```

### 4 根据目录读取所有的key
|     参数      |             说明                   |
| :------------   | :--------------------------------- |
| keystore       | 目录名               |
| cbfunction(err, keyObjects) | 回调函数，如果不传，那么同步调用      |
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
返回值说明：用户的私钥。
```JavaScript
var keyObject = key.createKey('lcq', '123456');
key.recover('123456', keyObject, function(err, privateKey){
    console.log(privateKey);
});
```

### 7 获取key的公钥
|     参数      |             说明                   |
| :------------   | :--------------------------------- |
| keyObject       | key               |
| cb(err, publicKey) | 回调函数，如果不传，那么同步调用      |
返回值说明：用户的私钥。
```JavaScript
key.getPublicKey(keyObject, function(err, publicKey){
    console.log(publicKey);
});
```

### 8 获取群私钥
|     参数      |             说明                   |
| :------------   | :--------------------------------- |
| keyObject       | key               |
| cb(err, groupPrivateKey) | 回调函数，如果不传，那么同步调用      |
返回值说明：用户的群私钥。
```JavaScript
key.getGroupPrivateKey(keyObject, function(err, groupPrivateKey){
    console.log(groupPrivateKey);
});
```

### 9 根据文件名字，获取对应的keyObject
|     参数      |             说明                   |
| :------------   | :--------------------------------- |
| fileName       | 文件名               |
| keystore       | 文件所在目录路径               |
| cb(err, keyObject) | 回调函数，如果不传，那么同步调用      |
返回值说明：文件名对应的keyObject。
```JavaScript
key.importFromFileName('lcq.json', DEFAULT_PATH, function(err, keyObject){
    console.log(keyObject);
});
```

### 10 导入keyObjects
|     参数      |             说明                   |
| :------------   | :--------------------------------- |
| srcPath       | 原目录               |
| distPath       | 目标目录               |
| cb(err, files) | 回调函数，如果不传，那么同步调用      |
返回值说明：导入成功的文件名。
```JavaScript
key.restoreKeys('lcq.json', DEFAULT_PATH, function(err, files){
    console.log(files);
});
```
