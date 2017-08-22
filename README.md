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
