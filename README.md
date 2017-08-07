安装
-----
`npm install git+ssh://http://luchenqun:fendoubuxi@192.168.9.66/Juzix-ethereum/key-manager.git#master`   
如果是写到package.json里面，以git协议这么写：
`'key-manager':git+ssh://http://luchenqun:fendoubuxi@192.168.9.66/Juzix-ethereum/key-manager.git#master`

使用
-----
如果你在Node.js环境下面使用，先引入：
`var keyManager = require("key-manager");`   
常用方法使用示例如下：   
#### 1 创建key
|     参数       |             说明                   |
| :------------    | :--------------------------------- |
| username         | 用户账号                            |
| password         | 用户密码                            |
| cb                | 回调函数，如果不传，那么同步调用      |
```JavaScript
// 同步创建key
var keyObject = key.createKey('lcq', '123456');

// 异步创建key
key.createKey('lcq', '123456', function(keyObject) {
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
| cb              | 回调函数，如果不传，那么同步调用      |
```JavaScript
var keyObject = key.createKey('lcq', '123456');
// 异步导出
key.exportToFile(keyObject, './keystore', 'xxxxx.json', function(outpath){
    console.log(outpath);
});
```

### 3 根据用户名导入key
|     参数      |             说明                   |
| :------------   | :--------------------------------- |
| username       | 用户名               |
| datadir        | 导入的目录                            |
| cb              | 回调函数，如果不传，那么同步调用      |
```JavaScript
key.importFromFile('lcq', './keystore', function(keyObject){
    console.log(keyObject);
});
```

### 4 根据目录读取所有的key
|     参数      |             说明                   |
| :------------   | :--------------------------------- |
| datadir       | 目录名               |
| cb              | 回调函数，如果不传，那么同步调用      |
```JavaScript
key.importFromDir('./keystore', function(keyObjects){
    console.log(keyObjects);
});
```

### 5 重置key
|     参数      |             说明                   |
| :------------   | :--------------------------------- |
| oldPassword       | 旧密码               |
| newPassword       | 新密码               |
| keyObject       | 旧key               |
| cb              | 回调函数，如果不传，那么同步调用      |
```JavaScript
var keyObject = key.createKey('lcq', '123456');
key.resetPassword('123456', '654321', keyObject, function(newKeyObject){
    console.log(newKeyObject);
});
```

### 6 获取key的私钥
|     参数      |             说明                   |
| :------------   | :--------------------------------- |
| password       | 旧密码               |
| keyObject       | key               |
| cb              | 回调函数，如果不传，那么同步调用      |
```JavaScript
var keyObject = key.createKey('lcq', '123456');
key.recover('123456', keyObject, function(privateKey){
    console.log(privateKey);
});
```
