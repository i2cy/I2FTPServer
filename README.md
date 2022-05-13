# 介绍
本项目为一款基于[I2TCP](https://github.com/i2cy/I2cylib)通讯协议
的文件传输服务器， 有效密钥长度达到512bit，同时嵌有类Google双重认证机制，
确保服务能在公网环境下安全存活。

# 安装方法
`pip install i2ftp-server`

# 环境需求
`Python3.7+`
`i2cylib >= 1.8.3`

# 集成命令
`i2ftps-setup` 服务器配置向导

## 默认配置文件路径
`/usr/share/i2ftp/server_conf.json`

## 附：通讯协议说明
### 通讯流程：

### 协议结构：
`TCP/IP` - `I2TCP` - `User`

### User层数据包：

 - 客户端命令 - “查询”：`LIST,<PATH>`

   返回：`<bool 路径是否存在>,{'文件1':{size:<int 大小>,
                                    time:<float 文件修改时间戳>}}`


 - 客户端命令 - “请求下载”：`GETF,<PATH>`

   返回：`<bool 请求是否接受>,[下载会话ID]`


 - 客户端命令 - “通过会话ID下载”：`DOWN,<str 下载会话ID>,<int 文件指针偏移量>`

   返回：`<bool 操作是否有效>,[bytes 数据内容 最大长度8192 Bytes]`


 - 客户端命令 - “请求上传”：`PULF,<PATH>,<str_hex 文件哈希校验值>`

   返回：`<bool 操作是否有效>,[上传会话ID]`


 - 客户端命令 - “通过会话ID上传”：`UPLD,<str 上传会话ID>,<int 文件指针偏移量>,<bytes 数据内容 最大长度8192 Bytes>`

   返回：`<bool 上传是否成功>,[int 当前文件指针偏移量]`