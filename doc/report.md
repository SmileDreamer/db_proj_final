# 数据库期末项目 V-0.2
-------------------
数据科学与计算机学院

小组成员：   
李沐晗 16313018  
赵彬琦 16337319  
卓睿祺 16337345  

指导老师：阮文江


## 项目简介

现如今，文件管理越来越受到各个行业的重视，但是在进行文件管理的过程中，经常会碰到各种问题：海量文件存储，管理困难；查找缓慢，效率低下；文件版本管理混乱；文件安全缺乏保障；文件无法有效协作共享；知识管理举步维艰等。因此，研究文件管理成为一个非常有意义问题。

另外，文件管理本身还是操作系统中一项重要的功能。其重要性在于，在现代计算机系统中，用户的程序和数据，操作系统自身的程序和数据，甚至各种输出输入设备，都是以文件形式出现的。可以说，尽管文件有多种存储介质可以使用，但是，它们都以文件的形式出现在操作系统的管理者和用户面前。

为此，本次实验实现了一个相对简单的文件管理系统，并在文件管理、用户管理、组管理、文件信息标注、文件版本控制等方面做出了自己的贡献，并在下面等实验报告中一一列出。

## E-R图

设计一个数据库系统，首先应当设计的就是E-R图，也就是实体联系图，只有基于E-R图，我们才能继续下一步的数据库建立。基于本次的实验需求，我们的E-R图当中主要包含了File、Directory、User、Group、Role、MetaTable、Metadata等实体：

![](/Users/zhaobinqi/Desktop/picture/屏幕快照 2019-01-04 22.07.09.png)

## 建立数据库

首先需要说明一点的就是，我们小组本次实现的文件管理系统，Python Web框架并不是基于Django的，而是基于另一个轻量级的框架Flask，Flask也是一个使用Python编写的轻量级Web应用框架。其WSGI 工具箱采用Werkzeug，模板引擎则使用Jinja2。

根据已经建立的数据库系统等E-R图，我们开始搭建数据库。搭建数据库我们使用的是flask下的SQLAlchemy，SQLAlchemy是一个基于Python实现的ORM框架。该框架建立在 DB API之上，使用关系对象映射进行数据库操作，换句话说：将类和对象转换成SQL，然后使用数据API执行SQL并获取执行结果：


**下面的各个代码都需要解释：**

### 用户实体和相关联系

用户实体包含了用户的id`user id`，用户名`username`和密码`password`。

``` python
class User(database.Model):
    __tablename__ = "user"
    user_id = database.Column(database.Integer,
                              primary_key=True,
                              nullable=False,
                              autoincrement=True)
    token = database.Column(database.String(64))
    token_expire = database.Column(database.DateTime)
    username = database.Column(database.String(64), unique=True, nullable=False)
    password = database.Column(database.String(256), nullable=False)

    def __init__(self, username, password):
        self.username = username
        self.password = bcrypt.hash(password)

    def __repr__(self):
        return "<User(user_id='%d', username='%s')>" % (self.user_id, self.username)

    def validate_password(self, password):
        return bcrypt.verify(password, self.password)

    def generate_token(self):
        # read 32 bytes(256bit) of random secret, then convert to hexadecimal format
        self.token = Random.new().read(32).hex()
        self.token_expire = datetime.datetime.utcnow() + datetime.timedelta(days=1)
        return base64.encode(self.username + ":" + self.token)

    def validate_token(self, token):
        if datetime.datetime.utcnow() > self.token_expire:
            return False
        try:
            token = base64.decode(token).split(":")[1]
        except KeyError:
            return False
        if self.token == token:
            return True
        else:
            return False

    def get_groups(self):
        subq = database.session.query\
        (UserGroup.group_id).filter(UserGroup.user_id == self.user_id).subquery()
        return database.session.query(Group).filter(Group.group_id.in_(subq)).all()

    def get_user_roles(self):
        subq = database.session.query\
        (UserRole.role_id).filter(UserRole.user_id == self.user_id).subquery()
        return database.session.query(Role).filter(Role.role_id.in_(subq)).all()

```

### 组实体和相关联系

组实体包含了组的id`group_id`，组名`groupname`。

``` python
class Group(database.Model):
    __tablename__ = "group"
    group_id = database.Column(database.Integer,
                               primary_key=True,
                               nullable=False,
                               autoincrement=True)
    groupname = database.Column(database.String(64), unique=True, nullable=False)

    def __init__(self, groupname):
        self.groupname = groupname

    def __repr__(self):
        return "<Group(group_id='%d', groupname='%s')>" % (self.group_id, self.groupname)

    def get_users(self):
        subq = database.session.query
        (UserGroup.user_id).filter(UserGroup.group_id == self.group_id).subquery()
        return database.session.query(User).filter(User.user_id.in_(subq)).all()

    def get_roles(self):
        subq = database.session.query
        (GroupRole.role_id).filter(GroupRole.group_id == self.group_id).subquery()
        return database.session.query(Role).filter(Role.role_id.in_(subq)).all()

```

### 目录实体及相关联系

目录实体包含了目录的id`dir_id`，父节点`parent`和父节点id`parent_id`，另外，还包含了路径`path`，并且这个路径是一个512char的全路径。

``` python
class Directory(database.Model):
    # TODO: change it to a hierarchical tree
    # eg: sqlalchemy-orm-tree
    # Currently deleting hierarchy of directories is not supported
    __tablename__ = "directory"

    dir_id = database.Column(database.Integer,
                             primary_key=True,
                             nullable=False,
                             autoincrement=True)
    path = database.Column(database.String(512))
    parent_id = database.Column
    (database.Integer, database.ForeignKey("directory.dir_id"), index=True)

    parent = database.relationship
    ("Directory", backref=database.backref("children", remote_side=dir_id))

    def __init__(self, path, parent_id):
        self.path = path
        self.parent_id = parent_id

    def __repr__(self):
        return "<Directory(dir_id='%d', path='%s')>" % (self.dir_id, self.path)

```

### 角色实体及相关联系

角色实体包含了角色的id`role_id`，操作路径`operate_dir_id`和读`allow_read`、插入`allow_insert`、删除`allow_delete`、修改`allow_modify`四大权限。

``` python

class Role(database.Model):
    __tablename__ = "role"
    role_id = database.Column(database.Integer,
                              primary_key=True,
                              nullable=False,
                              autoincrement=True)
    role_name = database.Column(database.String(256), nullable=False)
    operate_dir_id = database.Column
    (database.Integer, database.ForeignKey(Directory.dir_id, ondelete="CASCADE"))
    allow_insert = database.Column(database.Boolean, nullable=False)
    allow_read = database.Column(database.Boolean, nullable=False)
    allow_modify = database.Column(database.Boolean, nullable=False)
    allow_delete = database.Column(database.Boolean, nullable=False)

    # create relationships
    directory = database.relationship
    ("Directory", backref=database.backref("role", passive_deletes=True))

    def __init__(self, role_name, operate_dir_id, allow_insert, allow_read, allow_modify, allow_delete):
        self.role_name = role_name
        self.operate_dir_id = operate_dir_id
        self.allow_insert = allow_insert
        self.allow_read = allow_read
        self.allow_modify = allow_modify
        self.allow_delete = allow_delete

    def __repr__(self):
        return "<Role(role_id='%d', role_name='%s', dir_id='%d', i='%r', r='%r', m='%r', d='%r')>" \
               % (self.role_id, self.role_name, self.operate_dir_id,
                  self.allow_insert, self.allow_read, self.allow_modify, self.allow_delete)

```

### 文件实体及相关方法

文件实体包含了文件的哈希`file_hash`，文件路径`file_path`和文件索引数目`file_ref_count`。

``` python
class File(database.Model):
    __tablename__ = "file"
    file_hash = database.Column(database.String(256),
                                primary_key=True,
                                nullable=False)
    file_path = database.Column(database.String(512), nullable=False)
    file_ref_count = database.Column(database.Integer)

    def __init__(self, file_hash, file_path):
        self.file_hash = file_hash
        self.file_path = file_path
        self.file_ref_count = 0

    def __repr__(self):
        return "<File(hash='%s', name='%s', path='%s')>" % 
        (self.file_hash, self.file_name, self.file_path)
```
### 元数据实体及相关联系

元数据实体是相对困难，也是相对重要的一个实体，它是用来管理文件的文件。

元数据实体包含了表号`table_id`，文件的哈希`file_hash`，元数据的键`key`和值`value`。

``` python
class MetaTable(database.Model):
    __tablename__ = "meta_table"
    meta_table_id = database.Column(database.Integer,
                                    primary_key=True,
                                    nullable=False,
                                    autoincrement=True)
    file_hash = database.Column(database.String(256), 
    database.ForeignKey(File.file_hash, ondelete="CASCADE"))
    key = database.Column(database.String(256), nullable=True)
    value = database.Column(database.String(256), nullable=True)

    # create relationships
    file = database.relationship("File", backref=database.backref
    ("meta_table", passive_deletes=True))

    def __init__(self, file_hash, key, value):
        self.file_hash = file_hash
        self.key = key
        self.value = value

    def __repr__(self):
        return "<MetaTable(id='%d', key='%s', value='%s')>" \
               % (self.meta_table_id, self.key, self.value)
```



### 文件-目录联系集

``` python
class FileDir(database.Model):
    __tablename__ = "file_dir"
    id = database.Column(database.Integer, primary_key=True)
    dir_id = database.Column(database.Integer, database.ForeignKey(Directory.dir_id, ondelete="CASCADE"))
    file_hash = database.Column(database.String(256), database.ForeignKey(File.file_hash, ondelete="CASCADE"))
    file_name = database.Column(database.String(256), nullable=False)

    # create relationships
    file = database.relationship(File, backref=database.backref("file_dir", passive_deletes=True))
    dir = database.relationship(Directory, backref=database.backref("file_dir", passive_deletes=True))

    def __init__(self, dir_id, file_hash, file_name):
        self.dir_id = dir_id
        self.file_hash = file_hash
        self.file_name = file_name
```

### 用户-角色联系集

``` python
class UserRole(database.Model):
    __tablename__ = "user_role"
    id = database.Column(database.Integer, primary_key=True)
    user_id = database.Column(database.Integer, database.ForeignKey(User.user_id, ondelete="CASCADE"))
    role_id = database.Column(database.Integer, database.ForeignKey(Role.role_id, ondelete="CASCADE"))

    # create relationships
    user = database.relationship(User, backref=database.backref("user_role", passive_deletes=True))
    role = database.relationship(Role, backref=database.backref("user_role", passive_deletes=True))

    def __init__(self, user_id, role_id):
        self.user_id = user_id
        self.role_id = role_id

```

### 组-角色联系集

``` python

class GroupRole(database.Model):
    __tablename__ = "group_role"
    id = database.Column(database.Integer, primary_key=True)
    group_id = database.Column(database.Integer, database.ForeignKey(Group.group_id, ondelete="CASCADE"))
    role_id = database.Column(database.Integer, database.ForeignKey(Role.role_id, ondelete="CASCADE"))

    # create relationships
    group = database.relationship(Group, backref=database.backref("group_role", passive_deletes=True))
    role = database.relationship(Role, backref=database.backref("group_role", passive_deletes=True))

    def __init__(self, group_id, role_id):
        self.group_id = group_id
        self.role_id = role_id
```

### 用户-组联系集

``` python
class UserGroup(database.Model):
    __tablename__ = "user_group"
    id = database.Column(database.Integer, primary_key=True)
    group_id = database.Column(database.Integer, database.ForeignKey(Group.group_id, ondelete="CASCADE"))
    user_id = database.Column(database.Integer, database.ForeignKey(User.user_id, ondelete="CASCADE"))

    # create relationships
    user = database.relationship(User, backref=database.backref("user_group", passive_deletes=True))
    group = database.relationship(Group, backref=database.backref("user_group", passive_deletes=True))

    def __init__(self, group_id, user_id):
        self.group_id = group_id
        self.user_id = user_id
```



## 数据获取

<!--我们的文件系统内能不能多放一些文件??-->
???????????????????????????????????????


## 实现功能

在我们的数据库文件管理系统当中实现了文件管理、用户管理、组管理、文件信息标注、文件版本控制等的功能，在下面会一一给出介绍：

<!--### http api-->
------
#####API 基本格式

用户端向服务端发送multipart form,该form中目前可以包含:

* json: json部分, 名字目前只用到action
* file: 二进制file部分 (目前只有upload\_file用到)
* 服务器端在不同情况下会返回json或二进制文件(read\_file函数)

**下面的示例使用了*requests*库:**

客户端请求示例如下:

```python
files = [
    ('json', ("action", json.dumps
    ({"action": "login", "param": {"username": "root", "password": "root"}}),
     'application/json'))
]
r = requests.post("http://127.0.0.1:8002/login", files=files)
print(r.content)
```

**另一个上传文件的示例如下:**

```python
files = [
    ('file', ('paper-othello.pdf', 
    open("/home/Administrator/iffi/Projects/DB/proj\_final/test\_data/paper-othello.pdf", 'rb'), 
    'application/octet')),
    ('json', ('action', json.dumps({"action": "upload\_file", "token": 
    "cm9vdDphMTQ0YTYyZDJiMTQwNTUxOWQ1ZTNmY2ZkZTVjYmRjNGUxNDAzOGE5MDZmN2M2ZmExMDhmNjRkZTk3MzNkOTIx",
    "param": {"dir\_root": "/user/root", "file\_name": "paper-othello.pdf"}}), 'application/json')),
]

r = requests.post("http://127.0.0.1:8002/upload\_file", files=files)
print(r.content)
```


### 用户登陆
-----------------

``` python
# API
 C->S json action {"action": "login", "param":{"username":"", "password":""}}
 C<-S json result 200/401 + {info: "...",  token:"..."}
```

解释:

* client 向 server发起 http 登录请求
* server向client返回状态码+json信息,  如果发送的请求非有效json, 返回400, 登录失败返回401, 登录成功返回200, info表示人类可读状态, token为以后任何操作使用的token

### 文件管理 
------------------

``` python
# API
C->S json action {"action": "...", "token": "...", "param":{}}
C<-S json result 200/400 + {"status": <int>, "info": "", "data":{}}
```

解释:

* client向server发起http文件操作请求
* server向client返回状态码+json信息, 如果发送的请求非有效json, 返回400, 否则返回200

api接口如下:

--
###### Read Directory:

``` python
# API
C->S action="read_dir" 
param={"dir_root": <string>, "dir_read_offset": <int>, "dir_read_num": <int>}
```

解释: 

* dir\_root: 要读取的文件根目录, user自己目录的根目录为/user,  group的根目录为/group, 

> eg: "/user/2016/my\_photos"

* dir\_read\_offset: 开始读取的entryoffset, 因为可能一个文件夹下文件过多, 因此一次可以只请求一部分的文件名, 这个是从列表开始的offset
* dir\_read\_num: 要读取的文件项的数目, 为大于0的值, 超过实际有的项的数目也没关系, 只会返回实际读取的数目

``` python
# API
S<-C data={"dir_root": <string>, "dir_read_num": <int>, 
"dir_read_offset": <int>, "real_read_num": <int>, "entries": [文件名数组]}
```

* 如果权限不足, status为ST\_USER\_NOT\_ALLOWED
* 如果读取的dir\_root非法, status值为ST\_INVALID\_DIR,
* 如果dir\_read\_offset(小于0或超出最大值)或dir\_read\_num(小于0)非法, status值为ST\_INVALID\_VALUE
* 成功则status值为ST\_OK

--
###### Delete Directory:


``` python
# API
C->S action="del_dir" param={"dir_root": <string>, "dir_name":<string>}
S<-C data={"dir_root": <string>, "dir_name":<string>}
```

* 如果权限不足, status为ST\_USER\_NOT\_ALLOWED
* 如果dir\_root或dir\_name非法, status值为ST\_INVALID\_DIR,
* 否则status为ST\_OK

--
###### Move Directory:

``` python
# API
C->S action="mv_dir" param={"dir_root": <string>, "dir_name":<string>, "dest_root": <string>, "dest_name": <string>}
S<-C data={"dir_root": <string>, "dir_name":<string>, "dest_root": <string>, "dest_name": <string>}
```

* 如果权限不足, status为ST\_USER\_NOT\_ALLOWED
* 如果dir\_root或dir\_name或dest\_root非法, status值为ST\_INVALID\_DIR
* 如果dest\_name非法(目标已存在, 文件名有不合法字符...), status值为ST\_INVALID\_DIR
否则status为ST\_OK

> eg: 
> dir\_root="/user/2016/" 
> dir\_name="books" 
> dest\_root="/group/2018/documents/" 
> dest\_name="books"

--
###### Create Directory:

``` python
# API
C->S action="create_dir" param={"dir_root": <string>, "dir_name":<string>}
S<-C data={"dir_root": <string>, "dir_name":<string>}
```

* 如果权限不足, status为ST\_USER\_NOT\_ALLOWED
* 如果dir\_root非法, status值为ST\_INVALID\_DIR
* 如果dir\_name非法(目标已存在, 文件名有不合法字符...), status值为ST\_INVALID\_DIR
* 否则status为ST\_OK

> eg: dir\_root="/user/2016/" dir\_name="books" dest\_root="/group/2018/documents/" dest\_name="books"


<!--因为权限管理问题, 目前不支持-->
--
###### Copy Directory:

``` python
# API
C->S action="copy_dir", 
param={"dir_root": <string>, "dir_name": <string>,"dest_root": <string>, "dest_name": <string>}
S<-C data=param(和用户请求param一致)
```

* 如果权限不足, status为ST\_USER\_NOT\_ALLOWED
* 如果dir\_root或dir\_name或dest\_root非法, status值为ST\_INVALID\_DIR
* 如果dest\_name非法(目标已存在, 文件名有不合法字符...), status值为ST\_INVALID\_DIR
* 否则status为ST\_OK

--
###### Read File:


``` python
# API
C->S action="read_file" param={"dir_root": <string>, "file_name": <string>}
```

* 如果权限不足, status为ST\_USER\_NOT\_ALLOWED
* 如果dir\_root非法, status值为ST\_INVALID\_DIR
* 如果file\_name非法, status值为ST\_INVALID\_FILE
* 否则直接返回文件

--
###### Delete File:

``` python
# API
C->S action="del_file",
 param={"dir_root": <string>, "file_name": <string>}
S<-C data=param(和用户请求param一致)
```

* 如果权限不足, status为ST\_USER\_NOT\_ALLOWED
* 如果dir\_root非法, status值为ST\_INVALID\_DIR
* 如果file\_name非法, status值为ST\_INVALID\_FILE
* 否则status为ST\_OK

--
###### Move File:

``` python
# API
C->S action="mv_file" 
param={"dir_root": <string>, "file_name": <string>, "dest_root": <string>, "dest_name": <string>}
S<-C data=param(和用户请求param一致)
```

* 如果权限不足, status为ST\_USER\_NOT\_ALLOWED
* 如果dir\_root或dest\_root非法, status值为ST\_INVALID\_DIR
* 如果file\_name非法, status值为ST\_INVALID\_FILE
* 如果dest\_name非法(目标已存在, 文件名有不合法字符...), status值为ST\_INVALID\_FILE
* 否则status为ST\_OK

--
###### Copy File:


``` python
# API
C->S action="copy_file", param={"dir_root": <string>, "file_name": <string>,"dest_root": <string>, "dest_name": <string>}
S<-C data=param(和用户请求param一致)
```

* 如果权限不足, status为ST\_USER\_NOT\_ALLOWED
* 如果dir\_root或dest\_root非法, status值为ST\_INVALID\_DIR
* 如果file\_name非法, status值为ST\_INVALID\_FILE
* 如果dest\_name非法, status值为ST\_INVALID\_FILE
* 否则status为ST\_OK

--
###### Upload File:


``` python
# API
C->S action="upload_file", param={"dir_root": <string>, "file_name": <string>}
	 file=<any file>
S<-C data={"dir_root": <string>, "file_name": <string>}
```

* 如果权限不足, status为ST\_USER\_NOT\_ALLOWED
* 如果dir\_root非法, status值为ST\_INVALID\_DIR
* 如果file\_name非法, status值为ST\_INVALID\_FILE
* 否则status为ST\_OK

--
###### Read Metadata:

``` python
# API
C->S action="read_meta", param={"dir_root": <string>, "file_name": <string>}
S<-C data={"dir_root": <string>, "file_name": <string>, "meta": {键:值}}
```

* 如果权限不足, status为ST\_USER\_NOT\_ALLOWED
* 如果dir\_root非法, status值为ST\_INVALID\_DIR
* 如果file\_name非法, status值为ST\_INVALID\_FILE
* 如果meta\_read\_offset或meta\_read\_num非法,  status值为ST\_INVALID\_FILE
* 否则status为ST\_OK

--
###### Set Metadata:

``` python
# API
action="set_meta", param={"dir_root": <string>, "file_name": <string>, "meta_key":<string>, "meta_val": <any>}
```

* 如果权限不足, status为ST\_USER\_NOT\_ALLOWED
* 如果dir\_root非法, status值为ST\_INVALID\_DIR
* 如果file\_name非法, status值为ST\_INVALID\_FILE
* 如果meta\_key非法, status值为ST\_INVALID\_META
* 如果meta\_val非法, status值为ST\_INVALID\_VALUE
* 否则status为ST\_OK


### 管理员 /manage 

<!--(不实现, 仅仅在报告里假装说明即可)-->

能够执行/manage的用户属于一个特殊的管理员组, 管理员组的group\_id为0, 同时有一个root用户, root用户的user\_id为0

###### 管理员对用户的操作

``` python
# API
 C->S action="read_user" param={"user_name": <string>}
 S<-C data={"role":<string>, "groups":{<group_name>: <group_role>}}
 
 C->S action="del_user" param={"user_name": <string>}
 C->S action="add_user" param={"user_name": <string>, "password":<string>}
 
 C->S action="update_user" param={"user_name": <string>, "update":{键:值}}
```

* 其中键可以为: "user\_name", "password", "role"
* 键为user\_name时, 值为string (使用bloom filter查重)
* 键为password时, 值为string
* 键为role时, 值为string

###### 管理员对组的操作

``` python
# API
 C->S action="read_group" param={"group_name": <string>}
 S<-C data={"group_name":<string>, "group_role":<string>, "users":[<user\_name>]}
 
 C->S action="del_group" param={"group_name": <string>}
 C->S action="add_group" param={"group_name": <string>}
 C->S action="update_group" param={"group_name": <string>,  "update": {键:值}}
```

* 其中键可以为: "group\_name", "role", "add\_user", "remove\_user"
* 键为group\_name时, 值为string (使用bloom filter查重)
* 键为role时, 值为string
* 键为add\_user/remove\_user时, 值为string


###### 管理员对role的操作

``` python
# API
 C->S action="read_role" param={"role_name": <string>}
 C->S action="del_role" param={"role_name": <string>}
 C->S action="add_role" param={"role_name": <string>}
 C->S action="update_role" param={"role_name": <string>, "update": {键:值}}
```

* 其中键可以为: "operate\_dir", "allow\_insert", "allow\_read", "allow\_modify", "allow\_delete"
* 键为operate\_dir时, 值为string
* 键为allow*时, 值为bool

### 共用部分

##### status 状态码
``` python
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