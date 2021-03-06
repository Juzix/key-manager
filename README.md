## 文件钱包功能 ##
1. 创建生成文件钱包，使用指定的密码加密钱包文件，将钱包文件写入规定的目录中 √ createKey + exportToFile
2. 导出钱包文件，用于将生成的钱包文件导出到指定的目录，简单的文件拷贝 √ 读文件，然后自己写文件
3. 修改钱包文件密码，在指定当前钱包文件正确密码的情况下解开钱包文件重新加密保存 √ resetPassword
4. 导入钱包文件，用于加载非客户端管理目录下的钱包文件，导入时验证密码的正确性 √ recover
5. 支持钱包文件的密码校验功能，指定用户名和密码，加载钱包文件，并校验密码解开私钥 √ 自己读取 + recover
6. 考虑将钱包文件中的UUID修改成用户名称，在生成时校验名称的唯一性，同时在加载时可以基于用户名称加载 √ createKey
7. 支持文件钱包的签名功能，能够基于文件钱包中的私钥签名交易 √ web3
8. 能够基于钱包文件获取钱包文件中私钥对应的公钥和用户地址信息
9. 支持文件钱包的加解密功能，能够基于公钥加密，进行私钥解密功能
10. 能够提供对应的JAVASCRIPT API供浏览器使用（考虑到浏览器的文件读写能力，在javascript api中仅仅实现对文件内容的操作，具体的文件操作通过Native客户端实现，例如：在生成文件钱包时，javascript仅仅生成钱包文件内容，具体的内容写入文件操作api不处理，由Native的客户端实现）

## 硬件钱包功能 ##
1. 能够加载硬件钱包的动态库，将动态库中的相关能力或者API注入到javascript中
2. 基于硬件的API调用创建硬件钱包中的ECC公私钥、RSA公私钥
3. 基于硬件的API调用导出硬件钱包中的ECC公钥、RSA公钥
4. 基于硬件的API调用实现ECC的私钥签名、解密能力；公钥加密、验签能力
5. 基于硬件的API能力检测硬件KEY是否可以正常连接访问，并且用户输入的密码是否正确

## 隐私保护功能 ##
1. 查询服务器端的API接口获取用户信息，从返回的用户属性中获取群私钥
2. 如果本地是文件钱包，则解密返回的群私钥，机密成功则将用户的群私钥保存在本地（私钥加密的结果）；如果是硬件钱包，则调用硬件的API接口导入群私钥，硬件会将正确的用户群私钥保存在硬件KEY中
3. 支持从服务器端查询返回所有共识节点的公钥列表，并将公钥保存在本地，定期的进行公钥列表的同步
4. 实现广播加密的算法，并以JAVASCRIPT API的形式提供，采用用户公钥、共识节点公钥列表进行广播加密
5. 实现广播解密的算法，使用用户的ECC私钥解密广播加密结果，得到原始的加密信息。广播加解密的算法可以参考c语言版本的实现
6. 实现群签名的算法，采用用户的群私钥签名消息，得到签名结果。群签名的算法可以参考c语言版本的实现
7. 结合广播加密、群签名、Nonce、交易签名的特性封装隐私保护交易签名接口

## 功能实现建议 ##
1. 基于nodejs实现相关算法和业务逻辑，然后基于browserfy转换成浏览器的版本实现
2. 能够实现一个统一的keymanager，在一些通用的API上实现统一的入口，通过扩展的方式实现文件钱包或者硬件钱包的特殊keymanager，来扩展不同的功能实现
