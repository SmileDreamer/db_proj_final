from flask_sqlalchemy import SQLAlchemy
from Crypto import Random
from passlib.hash import bcrypt
import base64
import datetime

database = SQLAlchemy()


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
        database.session.commit()
        return base64.b64encode((self.username + ":" + self.token).encode("utf-8")).decode("utf-8")

    def validate_token(self, token):
        if datetime.datetime.utcnow() > self.token_expire:
            return False
        try:
            token = base64.b64decode(token).decode("utf-8").split(":")[1]
        except KeyError:
            return False
        if self.token == token:
            return True
        else:
            return False

    def get_groups(self):
        subq = database.session.query(UserGroup.group_id).filter(UserGroup.user_id == self.user_id).subquery()
        return database.session.query(Group).filter(Group.group_id.in_(subq)).all()

    def get_user_roles(self):
        subq = database.session.query(UserRole.role_id).filter(UserRole.user_id == self.user_id).subquery()
        return database.session.query(Role).filter(Role.role_id.in_(subq)).all()


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
        subq = database.session.query(UserGroup.user_id).filter(UserGroup.group_id == self.group_id).subquery()
        return database.session.query(User).filter(User.user_id.in_(subq)).all()

    def get_roles(self):
        subq = database.session.query(GroupRole.role_id).filter(GroupRole.group_id == self.group_id).subquery()
        return database.session.query(Role).filter(Role.role_id.in_(subq)).all()


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
    parent_id = database.Column(database.Integer, database.ForeignKey("directory.dir_id"), index=True)

    parent = database.relationship("Directory", backref=database.backref("children", remote_side=dir_id))

    def __init__(self, path, parent_id):
        self.path = path
        self.parent_id = parent_id

    def __repr__(self):
        return "<Directory(dir_id='%d', path='%s')>" % (self.dir_id, self.path)


class Role(database.Model):
    __tablename__ = "role"
    role_id = database.Column(database.Integer,
                              primary_key=True,
                              nullable=False,
                              autoincrement=True)
    role_name = database.Column(database.String(256), nullable=False)
    operate_dir_id = database.Column(database.Integer, database.ForeignKey(Directory.dir_id, ondelete="CASCADE"))
    allow_insert = database.Column(database.Boolean, nullable=False)
    allow_read = database.Column(database.Boolean, nullable=False)
    allow_modify = database.Column(database.Boolean, nullable=False)
    allow_delete = database.Column(database.Boolean, nullable=False)

    # create relationships
    directory = database.relationship("Directory", backref=database.backref("role", passive_deletes=True))

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
        return "<File(hash='%s', name='%s', path='%s')>" % (self.file_hash, self.file_name, self.file_path)


class MetaTable(database.Model):
    __tablename__ = "meta_table"
    meta_table_id = database.Column(database.Integer,
                                    primary_key=True,
                                    nullable=False,
                                    autoincrement=True)
    file_hash = database.Column(database.String(256), database.ForeignKey(File.file_hash, ondelete="CASCADE"))
    key = database.Column(database.String(256), nullable=True)
    value = database.Column(database.String(256), nullable=True)

    # create relationships
    file = database.relationship("File", backref=database.backref("meta_table", passive_deletes=True))

    def __init__(self, file_hash, key, value):
        self.file_hash = file_hash
        self.key = key
        self.value = value

    def __repr__(self):
        return "<MetaTable(id='%d', key='%s', value='%s')>" \
               % (self.meta_table_id, self.key, self.value)


# connection sets
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
