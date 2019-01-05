# DB 设计方案 Version 0.1
### 实现功能
文件管理 
用户管理
组管理
文件信息标注
文件版本控制
### http api
---
#####基本格式
用户端向服务端发送multipart form,该form中目前可以包含:
json: json部分, 名字目前只用到action
file: 二进制file部分 (目前只有upload_file用到)
服务器端在不同情况下会返回json或二进制文件(read_file函数)

下面的示例使用了**requests**库
客户端请求示例如下
```python
files = [
    ('json', ("action", json.dumps({"action": "login", "param": {"username": "root", "password": "root"}}), 'application/json'))
]
r = requests.post("http://127.0.0.1:8002/login", files=files)
print(r.content)
```
另一个上传文件的示例如下
```python
files = [
    ('file', ('paper-othello.pdf', open("/home/Administrator/iffi/Projects/DB/proj_final/test_data/paper-othello.pdf", 'rb'), 'application/octet')),
    ('json', ('action', json.dumps({"action": "upload_file", "token": "cm9vdDphMTQ0YTYyZDJiMTQwNTUxOWQ1ZTNmY2ZkZTVjYmRjNGUxNDAzOGE5MDZmN2M2ZmExMDhmNjRkZTk3MzNkOTIx",
                                      "param": {"dir_root": "/user/root", "file_name": "paper-othello.pdf"}}), 'application/json')),
]

r = requests.post("http://127.0.0.1:8002/file", files=files)
print(r.content)
```
#####用户登录 /login: 
```
 C->S json action {"action": "login", "param":{"username":"", "password":""}}
 C<-S json result 200/401 + {info: "...",  token:"..."}
```
解释:
client 向 server发起http登录请求
server向client返回状态码+json信息,  如果发送的请求非有效json, 返回400, 登录失败返回401, 登录成功返回200, info表示人类可读状态, token为以后任何操作使用的token
---
##### 文件操作 /file:
```
C->S json action {"action": "...", "token": "...", "param":{}}
C<-S json result 200/400 + {"status": <int>, "info": "", "data":{}}
```
解释:
client向server发起http文件操作请求
server向client返回状态码+json信息, 如果发送的请求非有效json, 返回400, 否则返回200
api接口如下
```
C->S action="read_dir" param={"dir_root": <string>, "dir_read_offset": <int>, "dir_read_num": <int>}
解释: 
dir_root: 要读取的文件根目录, user自己目录的根目录为/user,  group的根目录为/group, eg: "/user/2016/my_photos"
dir_read_offset: 开始读取的entryoffset, 因为可能一个文件夹下文件过多, 因此一次可以只请求一部分的文件名, 这个是从列表开始的offset
dir_read_num: 要读取的文件项的数目, 为大于0的值, 超过实际有的项的数目也没关系, 只会返回实际读取的数目

S<-C data={"dir_root": <string>, "dir_read_num": <int>, "dir_read_offset": <int>, "real_read_num": <int>, "entries": [文件名数组]}
如果权限不足, status为ST_USER_NOT_ALLOWED
如果读取的dir_root非法, status值为ST_INVALID_DIR,
如果dir_read_offset(小于0或超出最大值)或dir_read_num(小于0)非法, status值为ST_INVALID_VALUE
成功则ST_OK

```
```
C->S action="del_dir" param={"dir_root": <string>, "dir_name":<string>}
S<-C data={"dir_root": <string>, "dir_name":<string>}
如果权限不足, status为ST_USER_NOT_ALLOWED
如果dir_root或dir_name非法, status值为ST_INVALID_DIR,
否则status为ST_OK
```
```
# 因为权限管理问题, 目前不支持
C->S action="mv_dir" param={"dir_root": <string>, "dir_name":<string>, "dest_root": <string>, "dest_name": <string>}
S<-C data={"dir_root": <string>, "dir_name":<string>, "dest_root": <string>, "dest_name": <string>}
如果权限不足, status为ST_USER_NOT_ALLOWED
如果dir_root或dir_name或dest_root非法, status值为ST_INVALID_DIR
如果dest_name非法(目标已存在, 文件名有不合法字符...), status值为ST_INVALID_DIR
否则status为ST_OK

eg: dir_root="/user/2016/" dir_name="books" dest_root="/group/2018/documents/" dest_name="books"
```
```
C->S action="create_dir" param={"dir_root": <string>, "dir_name":<string>}
S<-C data={"dir_root": <string>, "dir_name":<string>}
如果权限不足, status为ST_USER_NOT_ALLOWED
如果dir_root非法, status值为ST_INVALID_DIR
如果dir_name非法(目标已存在, 文件名有不合法字符...), status值为ST_INVALID_DIR
否则status为ST_OK

eg: dir_root="/user/2016/" dir_name="books" dest_root="/group/2018/documents/" dest_name="books"
```
```
# 因为权限管理问题, 目前不支持
C->S action="copy_dir", param={"dir_root": <string>, "dir_name": <string>,"dest_root": <string>, "dest_name": <string>}
S<-C data=param(和用户请求param一致)
如果权限不足, status为ST_USER_NOT_ALLOWED
如果dir_root或dir_name或dest_root非法, status值为ST_INVALID_DIR
如果dest_name非法(目标已存在, 文件名有不合法字符...), status值为ST_INVALID_DIR
否则status为ST_OK
```
```
C->S action="read_file" param={"dir_root": <string>, "file_name": <string>}
如果权限不足, status为ST_USER_NOT_ALLOWED
如果dir_root非法, status值为ST_INVALID_DIR
如果file_name非法, status值为ST_INVALID_FILE
否则直接返回文件
```
```
C->S action="del_file" param={"dir_root": <string>, "file_name": <string>}
S<-C data=param(和用户请求param一致)
如果权限不足, status为ST_USER_NOT_ALLOWED
如果dir_root非法, status值为ST_INVALID_DIR
如果file_name非法, status值为ST_INVALID_FILE
否则status为ST_OK
```
```
C->S action="mv_file" param={"dir_root": <string>, "file_name": <string>, "dest_root": <string>, "dest_name": <string>}
S<-C data=param(和用户请求param一致)
如果权限不足, status为ST_USER_NOT_ALLOWED
如果dir_root或dest_root非法, status值为ST_INVALID_DIR
如果file_name非法, status值为ST_INVALID_FILE
如果dest_name非法(目标已存在, 文件名有不合法字符...), status值为ST_INVALID_FILE
否则status为ST_OK
```
```
C->S action="copy_file", param={"dir_root": <string>, "file_name": <string>,"dest_root": <string>, "dest_name": <string>}
S<-C data=param(和用户请求param一致)
如果权限不足, status为ST_USER_NOT_ALLOWED
如果dir_root或dest_root非法, status值为ST_INVALID_DIR
如果file_name非法, status值为ST_INVALID_FILE
如果dest_name非法, status值为ST_INVALID_FILE
否则status为ST_OK
```
```
C->S action="upload_file", param={"dir_root": <string>, "file_name": <string>}
	 file=<any file>
S<-C data={"dir_root": <string>, "file_name": <string>}
如果权限不足, status为ST_USER_NOT_ALLOWED
如果dir_root非法, status值为ST_INVALID_DIR
如果file_name非法, status值为ST_INVALID_FILE
否则status为ST_OK
```
```
C->S action="read_meta", param={"dir_root": <string>, "file_name": <string>}
S<-C data={"dir_root": <string>, "file_name": <string>, "meta": {键:值}}
如果权限不足, status为ST_USER_NOT_ALLOWED
如果dir_root非法, status值为ST_INVALID_DIR
如果file_name非法, status值为ST_INVALID_FILE
如果meta_read_offset或meta_read_num非法,  status值为ST_INVALID_VALUE
否则status为ST_OK
```
```
action="set_meta", param={"dir_root": <string>, "file_name": <string>, "meta_key":<string>, "meta_val": <any>}
如果权限不足, status为ST_USER_NOT_ALLOWED
如果dir_root非法, status值为ST_INVALID_DIR
如果file_name非法, status值为ST_INVALID_FILE
如果meta_key非法, status值为ST_INVALID_META
如果meta_val非法, status值为ST_INVALID_VALUE
否则status为ST_OK
```
##### 管理 /manage (不实现, 仅仅在报告里假装说明即可)
能够执行/manage的用户属于一个特殊的管理员组, 管理员组的group_id为0, 同时有一个root用户, root用户的user_id为0
###### 对用户的操作
```
 C->S action="read_user" param={"user_name": <string>}
 S<-C data={"role":<string>, "groups":{<group_name>: <group_role>}}
 
 C->S action="del_user" param={"user_name": <string>}
 C->S action="add_user" param={"user_name": <string>, "password":<string>}
 
 C->S action="update_user" param={"user_name": <string>, "update":{键:值}}
 其中键可以为: "user_name", "password", "role"
 键为user_name时, 值为string (使用bloom filter查重)
 键为password时, 值为string
 键为role时, 值为string
```
###### 对组的操作
```
 C->S action="read_group" param={"group_name": <string>}
 S<-C data={"group_name":<string>, "group_role":<string>, "users":[<user_name>]}
 
 C->S action="del_group" param={"group_name": <string>}
 C->S action="add_group" param={"group_name": <string>}
 C->S action="update_group" param={"group_name": <string>,  "update": {键:值}}
 其中键可以为: "group_name", "role", "add_user", "remove_user"
 键为group_name时, 值为string (使用bloom filter查重)
 键为role时, 值为string
 键为add_user/remove_user时, 值为string
```
###### 对role的操作
``` 
 C->S action="read_role" param={"role_name": <string>}
 C->S action="del_role" param={"role_name": <string>}
 C->S action="add_role" param={"role_name": <string>}
 C->S action="update_role" param={"role_name": <string>, "update": {键:值}}
 其中键可以为: "operate_dir", "allow_insert", "allow_read", "allow_modify", "allow_delete"
 键为operate_dir时, 值为string
 键为allow*时, 值为bool
```
### 共用部分

##### status 状态码
```
ST_OK = 0
ST_INVALID_VALUE = 100
ST_INVALID_FILE = 101
ST_INVALID_META = 102
ST_INVALID_DIR = 103
ST_INVALID_USER = 104
ST_INVALID_GROUP =  105
ST_INVLAID_ROLE = 106
ST_USER_NOT_ALLOWED = 200
```