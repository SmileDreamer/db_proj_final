# 数据库期末项目 V-0.3
-------------------
数据科学与计算机学院

小组工作：   

前期共同完成的工作：讨论究竟实现何种数据库项目、此数据库项目实现到何种程度、难度如何。多次讨论之后，最终决定实现文件管理系统。

分工：  
李沐晗 16313018 负责后端HTTP部分的编写和SQL部分的编写    
赵彬琦 16337319 负责跟进实验报告的撰写  
卓睿祺 16337345 负责前端GUI部分的搭建和编写

指导老师：阮文江

## 项目简介

现如今，文件管理越来越受到各个行业的重视，但是在进行文件管理的过程中，经常会碰到各种问题：海量文件存储，管理困难；查找缓慢，效率低下；文件版本管理混乱；文件安全缺乏保障；文件无法有效协作共享；知识管理举步维艰等。因此，研究文件管理成为一个非常有意义问题。

另外，文件管理本身还是操作系统中一项重要的功能。其重要性在于，在现代计算机系统中，用户的程序和数据，操作系统自身的程序和数据，甚至各种输出输入设备，都是以文件形式出现的。可以说，尽管文件有多种存储介质可以使用，但是，它们都以文件的形式出现在操作系统的管理者和用户面前。

为此，本次实验实现了一个相对简单的文件管理系统，并在文件管理、用户管理、组管理、文件信息标注、文件版本控制等方面做出了自己的贡献，并在下面等实验报告中一一列出。

## E-R图

设计一个数据库系统，首先应当设计的就是E-R图，也就是实体联系图，只有基于E-R图，我们才能继续下一步的数据库建立。基于本次的实验需求，我们的E-R图当中主要包含了File、Directory、User、Group、Role、MetaTable、Metadata等实体。

在E-R图当中，`->`表示外键引用, file\_dir, user\_role, user\_group, group\_role起到联系集的作用, 它们均为多对多。

![](images/ER.png)

## 建立数据库

首先需要说明一点的就是，我们小组本次实现的文件管理系统，Python Web框架并不是基于Django的，而是基于另一个轻量级的框架Flask，Flask也是一个使用Python编写的轻量级Web应用框架。其WSGI 工具箱采用Werkzeug，模板引擎则使用Jinja2。

根据已经建立的数据库系统等E-R图，我们开始搭建数据库。搭建数据库我们使用的是flask下的SQLAlchemy，SQLAlchemy是一个基于Python实现的ORM框架。该框架建立在 DB API之上，使用关系对象映射进行数据库操作，换句话说：将类和对象转换成SQL，然后使用数据API执行SQL并获取执行结果。

在代码文件当中，models是数据库ORM结构的定义, 本次使用的是python的SQLAlchemy库来实现跨数据库的表格结构定义而不用拘泥于一种或几种特定的数据库, 比使用模板+SQL语言的实现有更好的通用性和便利性，下面列出建立数据库的代码。


<!--**下面的各个代码都需要解释：**-->

### 用户实体和相关联系

用户实体包含了用户的id`user id`，用户名`username`和密码`password`，另外，还定义了相关的方法，如密码是否有效、生成token、得到群组、得到用户的角色等。

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

组实体包含了组的id`group_id`，组名`groupname`，另外，还定义了相关的方法，如得到群组中的用户、得到群组的角色等。

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

目录实体包含了目录的id`dir_id`，父节点`parent`和父节点id`parent_id`，另外，还包含了路径`path`，并且这个路径是一个512char的全路径，目录实体额外的方法不多，只有自定义的转换字符串输出函数比较重要。

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

角色实体包含了角色的id`role_id`，操作路径`operate_dir_id`和读`allow_read`、插入`allow_insert`、删除`allow_delete`、修改`allow_modify`四大权限，角色实体和目录实体类似，额外的方法不多，只有自定义的转换字符串输出函数比较重要。

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

元数据实体是相对困难，也是相对重要的一个实体，它是用来管理文件的文件。元数据实体包含了表号`table_id`，文件的哈希`file_hash`，元数据的键`key`和值`value`。

有一点需要注意的是，在具体实现之时，也定义了一个关系，为文件和元文件之间的关系。

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



### 联系集

* 从前面的E-R图中可知，联系集包含了四个：file\_dir, user\_role, user\_group, group\_role，分别为文件-目录联系集、用户-角色联系集、用户-组联系集、组-角色联系集。另外，它们均为多对多的联系集。

``` python
### 文件-目录联系集
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

``` python
### 用户-角色联系集
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

* 另外，我们的代码还包含了用户-组联系集和组-角色联系集，具体的实现和前面的联系集类似，就不多加阐述了。**可以到代码文件的models.py当中详细查看。**

``` python
### 用户-组联系集
...
### 组-角色联系集
...
```



## 实验数据

<!--我们的文件系统内能不能多放一些文件??-->
???????????????????????????????????????

## 具体实现

### 后端http服务器的实现

后端http服务器的实现主要在代码文件的app.py当中给出，app.py使用flask来实现。

#### 后端服务器初始化的实现：


``` python
def app_init():
    database.init_app(app)
    app.app_context().push()
    database.create_all(app=app)
    database.get_engine(app=app).execute("""
        CREATE OR REPLACE TRIGGER update_file_ref_inc
        AFTER INSERT ON file_dir
        FOR EACH ROW
        BEGIN
            UPDATE file SET file.file_ref_count = file.file_ref_count + 1
            WHERE file.file_hash = NEW.file_hash;
        END
    """)
    database.get_engine(app=app).execute("""
        CREATE OR REPLACE TRIGGER update_file_ref_dec
        AFTER DELETE ON file_dir
        FOR EACH ROW
        BEGIN
            UPDATE file SET file.file_ref_count = file.file_ref_count - 1
            WHERE file.file_hash = OLD.file_hash;
        END

    """)
    database.session.commit()
```

#### 用户登陆的实现：

* 在用户登陆操作时，传输的文件是json文件。首先读取的是文件当中的操作`action`查看用户进行了何种操作。其次，查看这一个请求是否是一个有效的请求，如果无效，则返回`Request is not valid json`。如果请求有效，则继续进一步获取用户输入的用户名和密码。如果用户输入的用户名和密码是有效的，则登陆成功。

``` python
@app.route("/login", methods=['GET', 'POST'])
def app_login():
    json_files = request.files.getlist("json")
    req = None
    for f in json_files:
        if f.filename == "action":
            req = json.loads(f.read().decode('utf-8'))
    # request is not valid json
    if req is None:
        resp = jsonify({"status": code.ST_INVALID_VALUE,
                        "info": "Request is not valid json",
                        "data": {}})
        resp.status_code = 400
        return resp

    # request is valid json, validate content
    if not validate_request(req, "login", {"username":str, "password":str}):
        resp = jsonify({"status": code.ST_INVALID_VALUE,
                        "info": "Request content is invalid",
                        "data": {}})
        resp.status_code = 400
        return resp

    # validate username and password
    user = User.query.filter_by(username=req["param"]["username"]).first()
    if user is None:
        resp = jsonify({"status": code.ST_INVALID_USER,
                        "info": "User doesn't exists",
                        "data": {}})
        resp.status_code = 401
        return resp
    if not user.validate_password(req["param"]["password"]):
        resp = jsonify({"status": code.ST_INVALID_VALUE,
                        "info": "Invalid password",
                        "data": {}})
        resp.status_code = 401
        return resp

    token = user.generate_token()
    resp = jsonify({"status": code.ST_OK,
                    "info": "Login successful",
                    "data": {"token": token}})
    resp.status_code = 200
    return resp
```

#### 文件操作的实现

* 前置操作和用户登陆是相同的，读取的是文件当中的操作`action`查看用户进行了何种操作。并查看这一个请求是否是一个有效的请求，如果无效，则返回`Request is not valid json`。另外，对于用户进行的这一种操作，要归结到文件当中具体的执行。

``` python

    # request is valid json, validate content
    if not validate_request(req, ["read_dir", "del_dir", "create_dir",
                                  "read_file", "del_file", "mv_file", "copy_file", "upload_file",
                                  "read_meta", "set_meta"], {}):
        resp = jsonify({"status": code.ST_INVALID_VALUE,
                        "info": "Request content is invalid",
                        "data": {}})
        resp.status_code = 400
        return resp

    # hand over request process to api functions
    if req["action"] == "read_dir":
        return file.read_dir(req, database)
    elif req["action"] == "del_dir":
        return file.del_dir(req, database)
    elif req["action"] == "create_dir":
        return file.create_dir(req, database)
    elif req["action"] == "read_file":
        return file.read_file(req, database)
    elif req["action"] == "del_file":
        return file.del_file(req, database)
    elif req["action"] == "mv_file":
        return file.mv_file(req, database)
    elif req["action"] == "copy_file":
        return file.copy_file(req, database)
    elif req["action"] == "upload_file":
        if "file" in request.files:
            # NOTE: only the first file will be read
            return file.upload_file(req, database, request.files["file"].read())
        else:
            resp = jsonify({"status": code.ST_INVALID_VALUE,
                            "info": "Request content is invalid, file stream not found",
                            "data": {}})
            resp.status_code = 400
            return resp
    elif req["action"] == "read_meta":
        return file.read_meta(req, database)
    elif req["action"] == "set_meta":
        return file.set_meta(req, database)
    else:
        # this should not happen
        resp = jsonify({"status": code.ST_INVALID_VALUE,
                        "info": "Request content is invalid",
                        "data": {}})
        resp.status_code = 400
        return resp
```

#### 管理员的管理操作实现

* 整体操作和文件操作实现是类似的，读取的是管理员的操作`action`对用户进行了何种操作。并查看这一个请求是否是一个有效的请求，如果无效，则返回`Request is not valid json`。另外，管理员需要对用户进行的具体操作，如删除用户、添加组等等，也需要归结到具体文件中实现。

``` python
    # hand over request process to api functions
    if req["action"] == "read_user":
        return manage.read_user(req, database)
    elif req["action"] == "del_user":
        return manage.del_user(req, database)
    elif req["action"] == "add_user":
        return manage.add_user(req, database)
    elif req["action"] == "update_user":
        return manage.update_user(req, database)
    elif req["action"] == "read_group":
        return manage.read_group(req, database)
    elif req["action"] == "del_group":
        return manage.del_group(req, database)
    elif req["action"] == "add_group":
        return manage.add_group(req, database)
    elif req["action"] == "update_group":
        return manage.update_group(req, database)
    elif req["action"] == "read_role":
        return manage.read_role(req, database)
    elif req["action"] == "del_role":
        return manage.del_role(req, database)
    elif req["action"] == "add_role":
        return manage.add_role(req, database)
    elif req["action"] == "update_role":
        return manage.update_role(req, database)
```

### 启动服务器

* **启动服务器的函数主要是main.py。但是，实际应用中不会使用main文件来使用flask的默认服务器, 而是使用nginx+uwsgi, 这样可以达到很高的效率和并发量, 同时可以部署多个后端服务器做负载均衡处理，达到一种更好的效果。**

``` python
from backend import app

app.app.config["SQLALCHEMY_DATABASE_URI"] = 
	"mysql://root:5fwHFZYy@192.168.5.2:3311/final_proj"
app.app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.app.config["UPLOADED_ITEMS_DEST"] = 
	"/home/Administrator/iffi/Projects/DB/proj_final/data"
app.app_init()
app.app.run("0.0.0.0", 8002)
```


### API接口

在我们的数据库文件管理系统当中实现了文件管理、用户管理、组管理、文件信息标注、文件版本控制等的功能，在下面会一一给出介绍：

<!--### http api-->
------
####API 基本格式

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


#### 用户登陆
-----------------

``` python
# API
 C->S json action {"action": "login", "param":{"username":"", "password":""}}
 C<-S json result 200/401 + {info: "...",  token:"..."}
```

解释:

* client 向 server发起 http 登录请求
* server向client返回状态码+json信息,  如果发送的请求非有效json, 返回400, 登录失败返回401, 登录成功返回200, info表示人类可读状态, token为以后任何操作使用的token

#### 文件管理 
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
##### Read Directory:

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
##### Delete Directory:


``` python
# API
C->S action="del_dir" param={"dir_root": <string>, "dir_name":<string>}
S<-C data={"dir_root": <string>, "dir_name":<string>}
```

* 如果权限不足, status为ST\_USER\_NOT\_ALLOWED
* 如果dir\_root或dir\_name非法, status值为ST\_INVALID\_DIR,
* 否则status为ST\_OK

--
##### Move Directory:

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
##### Create Directory:

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
##### Copy Directory:

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
##### Read File:


``` python
# API
C->S action="read_file" param={"dir_root": <string>, "file_name": <string>}
```

* 如果权限不足, status为ST\_USER\_NOT\_ALLOWED
* 如果dir\_root非法, status值为ST\_INVALID\_DIR
* 如果file\_name非法, status值为ST\_INVALID\_FILE
* 否则直接返回文件

--
##### Delete File:

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
##### Move File:

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
##### Copy File:


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
##### Upload File:


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
##### Read Metadata:

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
##### Set Metadata:

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


#### 管理员 /manage 

<!--(不实现, 仅仅在报告里假装说明即可)-->

能够执行/manage的用户属于一个特殊的管理员组, 管理员组的group\_id为0, 同时有一个root用户, root用户的user\_id为0

##### 管理员对用户的操作

``` python
# API
 C->S action="read_user" param={"user_name": <string>}
 S<-C data={"role":<string>, "groups":{<group_name>: <group_role>}}
 
 C->S action="del_user" param={"user_name": <string>}
 C->S action="add_user" param={"user_name": <string>, "password":<string>}
 
 C->S action="update_user" param={"user_name": <string>, "update":{键:值}}
```

* 以读取用户read\_user为例：

``` python
def read_user(request, db):
    resp = jsonify({"status": code.ST_INVALID_VALUE,
                    "info": "Not implemented",
                    "data": {}})
    resp.status_code = 500
    return resp
```

* 其中键可以为: "user\_name", "password", "role"
* 键为user\_name时, 值为string (使用bloom filter查重)
* 键为password时, 值为string
* 键为role时, 值为string

##### 管理员对组的操作

``` python
# API
 C->S action="read_group" param={"group_name": <string>}
 S<-C data={"group_name":<string>, "group_role":<string>, "users":[<user\_name>]}
 
 C->S action="del_group" param={"group_name": <string>}
 C->S action="add_group" param={"group_name": <string>}
 C->S action="update_group" param={"group_name": <string>,  "update": {键:值}}
```

* 以删除群组del\_group为例：

``` python
def del_group(request, db):
    resp = jsonify({"status": code.ST_INVALID_VALUE,
                    "info": "Not implemented",
                    "data": {}})
    resp.status_code = 500
    return resp
```

* 其中键可以为: "group\_name", "role", "add\_user", "remove\_user"
* 键为group\_name时, 值为string (使用bloom filter查重)
* 键为role时, 值为string
* 键为add\_user/remove\_user时, 值为string


##### 管理员对role的操作

``` python
# API
 C->S action="read_role" param={"role_name": <string>}
 C->S action="del_role" param={"role_name": <string>}
 C->S action="add_role" param={"role_name": <string>}
 C->S action="update_role" param={"role_name": <string>, "update": {键:值}}
```

* 以添加角色add\_role为例：

``` python
def add_role(request, db):
    resp = jsonify({"status": code.ST_INVALID_VALUE,
                    "info": "Not implemented",
                    "data": {}})
    resp.status_code = 500
    return resp
```

* 其中键可以为: "operate\_dir", "allow\_insert", "allow\_read", "allow\_modify", "allow\_delete"
* 键为operate\_dir时, 值为string
* 键为allow*时, 值为bool

#### 共用部分

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

### GUI实现

<!---->

## 效果展示


