from flask import jsonify, send_file, current_app
from hashlib import sha256
from backend.misc import *
from backend.utils import code
import os
import string


def read_dir(request, db):
    """
    :param request:
    :param db:
    :return:
    """
    if "token" not in request \
            or not validate_request(request, "read_dir", {"dir_root": str, "dir_read_offset": int, "dir_read_num": int}) \
            or request["param"]["dir_read_offset"] < 0 or request["param"]["dir_read_num"] <= 0:
        resp = jsonify({"status": code.ST_INVALID_VALUE,
                        "info": "Request content is invalid",
                        "data": {}})
        resp.status_code = 400
        return resp
    user = get_user(request["token"])
    if not user or not user.validate_token(request["token"]):
        resp = jsonify({"status": code.ST_INVALID_VALUE,
                        "info": "Token is invalid",
                        "data": {}})
        resp.status_code = 401
        return resp

    # query for directory
    dir = Directory.query.filter_by(path=request["param"]["dir_root"]).first()
    if dir is None:
        resp = jsonify({"status": code.ST_INVALID_DIR,
                        "info": "Directory is invalid",
                        "data": {}})
        resp.status_code = 404
        return resp

    if request["param"]["dir_root"].startswith("/user"):
        # query for user roles
        roles = user.get_user_roles()
        for role in roles:
            if role.operate_dir_id == dir.dir_id:
                if role.allow_read:
                    # query for file entries in target directory
                    files = FileDir.query.filter(FileDir.dir_id == dir.dir_id).all()
                    if len(files) < request["param"]["dir_read_offset"]:
                        resp = jsonify({"status": code.ST_INVALID_VALUE,
                                        "info": "Request read offset is too large",
                                        "data": {}})
                        resp.status_code = 400
                        return resp
                    else:
                        real_read_num = len(files) - request["param"]["dir_read_offset"]
                        entries = []
                        for i in range(request["param"]["dir_read_offset"], len(files)):
                            entries.append(files[i].file_name)

                        # query for directory entries in target directory, directory entries are always returned
                        dirs = Directory.query.filter(Directory.parent_id == dir.dir_id).all()
                        for d in dirs:
                            entries.append(d.path)
                        resp = jsonify({"status": code.ST_OK,
                                        "info": "Request successful",
                                        "data": {"dir_root": request["param"]["dir_root"],
                                                 "dir_read_num": request["param"]["dir_read_num"],
                                                 "dir_read_offset": request["param"]["dir_read_offset"],
                                                 "real_read_num": real_read_num,
                                                 "entries": entries}})
                        resp.status_code = 200
                        return resp

                else:
                    resp = jsonify({"status": code.ST_USER_NOT_ALLOWED,
                                    "info": "User doesn't have read permission",
                                    "data": {}})
                    resp.status_code = 401
                    return resp

        resp = jsonify({"status": code.ST_USER_NOT_ALLOWED,
                        "info": "User doesn't have correct role",
                        "data": {}})
        resp.status_code = 401
        return resp
    elif request["param"]["dir_root"].startswith("/group"):
        # query for user group roles
        groups = user.get_groups()
        for group in groups:
            roles = group.get_roles()
            for role in roles:
                if role.operate_dir_id == dir.dir_id:
                    if role.allow_read:
                        # query for entries in target directory
                        files = FileDir.query.filter(FileDir.dir_id == dir.dir_id).all()
                        if len(files) < request["param"]["dir_read_offset"]:
                            resp = jsonify({"status": code.ST_INVALID_VALUE,
                                            "info": "Request read offset is too large",
                                            "data": {}})
                            resp.status_code = 400
                            return resp
                        else:
                            real_read_num = len(files) - request["param"]["dir_read_offset"]
                            entries = []
                            for i in range(request["param"]["dir_read_offset"], len(files)):
                                entries.append(files[i].file_name)

                            # query for directory entries in target directory, directory entries are always returned
                            dirs = Directory.query.filter(Directory.parent_id == dir.dir_id).all()
                            for d in dirs:
                                entries.append(d.path)

                            resp = jsonify({"status": code.ST_OK,
                                            "info": "Request successful",
                                            "data": {"dir_root": request["param"]["dir_root"],
                                                     "dir_read_num": request["param"]["dir_read_num"],
                                                     "dir_read_offset": request["param"]["dir_read_offset"],
                                                     "real_read_num": real_read_num,
                                                     "entries": entries}})
                            resp.status_code = 200
                            return resp
                    else:
                        resp = jsonify({"status": code.ST_USER_NOT_ALLOWED,
                                        "info": "User group doesn't have read permission",
                                        "data": {}})
                        resp.status_code = 401
                        return resp

        resp = jsonify({"status": code.ST_USER_NOT_ALLOWED,
                        "info": "User doesn't have correct role",
                        "data": {}})
        resp.status_code = 401
        return resp


def del_dir(request, db):
    """
    :param request:
    :param db:
    :return:
    """
    if "token" not in request \
            or not validate_request(request, "del_dir", {"dir_root": str, "dir_name": str}):
        resp = jsonify({"status": code.ST_INVALID_VALUE,
                        "info": "Request content is invalid",
                        "data": {}})
        resp.status_code = 400
        return resp
    user = get_user(request["token"])
    if not user or not user.validate_token(request["token"]):
        resp = jsonify({"status": code.ST_INVALID_VALUE,
                        "info": "Token is invalid",
                        "data": {}})
        resp.status_code = 401
        return resp

    # query for directory id
    parent_dir = Directory.query.filter_by(path=request["param"]["dir_root"]).first()
    dir = Directory.query.filter_by(path=request["param"]["dir_root"]+"/"+request["param"]["dir_name"]).first()
    if dir is None:
        resp = jsonify({"status": code.ST_INVALID_DIR,
                        "info": "Directory is invalid",
                        "data": {}})
        resp.status_code = 404
        return resp

    if request["param"]["dir_root"].startswith("/user"):
        # query for user roles
        roles = user.get_user_roles()
        for role in roles:
            if role.operate_dir_id == parent_dir.dir_id:
                if role.allow_delete:
                    # query for directories in target directory
                    dirs = Directory.query.filter(Directory.parent_id == dir.dir_id).first()
                    if dirs is not None:
                        # currently, cascade deletion is not supported, user can only delete leaf nodes
                        resp = jsonify({"status": code.ST_INVALID_DIR,
                                        "info": "Directory is not empty",
                                        "data": {}})
                        resp.status_code = 400
                        return resp
                    else:
                        db.session.delete(dir)
                        db.session.commit()
                        resp = jsonify({"status": code.ST_OK,
                                        "info": "Request successful",
                                        "data": request["param"]})
                        resp.status_code = 200
                        return resp
                else:
                    resp = jsonify({"status": code.ST_USER_NOT_ALLOWED,
                                    "info": "User doesn't have delete permission",
                                    "data": {}})
                    resp.status_code = 401
                    return resp

        resp = jsonify({"status": code.ST_USER_NOT_ALLOWED,
                        "info": "User doesn't have correct role",
                        "data": {}})
        resp.status_code = 401
        return resp
    elif request["param"]["dir_root"].startswith("/group"):
        # query for user group roles
        groups = user.get_groups()
        for group in groups:
            roles = group.get_roles()
            for role in roles:
                if role.operate_dir_id == parent_dir.dir_id:
                    if role.allow_delete:
                        # query for directories in target directory
                        dirs = Directory.query.filter(Directory.parent_id == dir.dir_id).first()
                        if dirs is not None:
                            # currently, cascade deletion is not supported, user can only delete leaf nodes
                            resp = jsonify({"status": code.ST_INVALID_DIR,
                                            "info": "Directory is not empty",
                                            "data": {}})
                            resp.status_code = 400
                            return resp
                        else:
                            db.session.delete(dir)
                            db.session.commit()
                            resp = jsonify({"status": code.ST_OK,
                                            "info": "Request successful",
                                            "data": request["param"]})
                            resp.status_code = 200
                            return resp
                    else:
                        resp = jsonify({"status": code.ST_USER_NOT_ALLOWED,
                                        "info": "User doesn't have delete permission",
                                        "data": {}})
                        resp.status_code = 401
                        return resp

        resp = jsonify({"status": code.ST_USER_NOT_ALLOWED,
                        "info": "User doesn't have correct role",
                        "data": {}})
        resp.status_code = 401
        return resp


def create_dir(request, db):
    """
    :param request:
    :param db:
    :return:
    """
    if "token" not in request \
            or not validate_request(request, "create_dir", {"dir_root": str, "dir_name": str}):
        resp = jsonify({"status": code.ST_INVALID_VALUE,
                        "info": "Request content is invalid",
                        "data": {}})
        resp.status_code = 400
        return resp
    user = get_user(request["token"])
    if not user or not user.validate_token(request["token"]):
        resp = jsonify({"status": code.ST_INVALID_VALUE,
                        "info": "Token is invalid",
                        "data": {}})
        resp.status_code = 401
        return resp

    # query for directory id
    dir = Directory.query.filter_by(path=request["param"]["dir_root"]).first()
    if dir is None:
        resp = jsonify({"status": code.ST_INVALID_DIR,
                        "info": "Directory is invalid",
                        "data": {}})
        resp.status_code = 404
        return resp
    # check for invalid character
    for c in request["param"]["dir_name"]:
        if c.lower() not in string.ascii_lowercase + "0123456789_":
            resp = jsonify({"status": code.ST_INVALID_VALUE,
                            "info": "Directory name contains invalid character",
                            "data": {}})
            resp.status_code = 400
            return resp
    new_path = request["param"]["dir_root"] + "/" + request["param"]["dir_name"]

    if request["param"]["dir_root"].startswith("/user"):
        # query for user roles
        roles = user.get_user_roles()
        for role in roles:
            if role.operate_dir_id == dir.dir_id:
                if role.allow_insert:
                    # query for directories in target directory
                    dirs = Directory.query.filter(Directory.parent_id == dir.dir_id).all()
                    if dirs is not None:
                        # check for duplicate directory
                        for d in dirs:
                            if d.path == new_path:
                                resp = jsonify({"status": code.ST_INVALID_VALUE,
                                                "info": "Target directory already exists",
                                                "data": request["param"]})
                                resp.status_code = 400
                                return resp
                    new_dir = Directory(new_path, dir.dir_id)
                    db.session.add(new_dir)
                    db.session.flush()
                    # inherit permission from parent
                    new_role = Role(role.role_name+"_"+request["param"]["dir_name"], new_dir.dir_id,
                                    role.allow_insert, role.allow_read,
                                    role.allow_modify, role.allow_delete)
                    db.session.add(new_role)
                    db.session.flush()
                    new_relation = UserRole(user.user_id, new_role.role_id)
                    db.session.add(new_relation)
                    db.session.commit()
                    resp = jsonify({"status": code.ST_OK,
                                    "info": "Request successful",
                                    "data": request["param"]})
                    resp.status_code = 200
                    return resp
                else:
                    resp = jsonify({"status": code.ST_USER_NOT_ALLOWED,
                                    "info": "User doesn't have insert permission",
                                    "data": {}})
                    resp.status_code = 401
                    return resp

        resp = jsonify({"status": code.ST_USER_NOT_ALLOWED,
                        "info": "User doesn't have correct role",
                        "data": {}})
        resp.status_code = 401
        return resp
    elif request["param"]["dir_root"].startswith("/group"):
        # query for user group roles
        groups = user.get_groups()
        for group in groups:
            roles = group.get_roles()
            for role in roles:
                if role.operate_dir_id == dir.dir_id:
                    if role.allow_insert:
                        # query for directories in target directory
                        dirs = Directory.query.filter(Directory.parent_id == dir.dir_id).all()
                        if dirs is not None:
                            # check for duplicate directory
                            for d in dirs:
                                if d.path == new_path:
                                    resp = jsonify({"status": code.ST_INVALID_VALUE,
                                                    "info": "Target directory already exists",
                                                    "data": request["param"]})
                                    resp.status_code = 400
                                    return resp
                        new_dir = Directory(new_path, dir.dir_id)
                        db.session.add(new_dir)
                        db.session.flush()
                        # inherit permission from parent
                        new_role = Role(role.role_name + "_" + request["param"]["dir_name"], new_dir.dir_id,
                                        role.allow_insert, role.allow_read,
                                        role.allow_modify, role.allow_delete)
                        db.session.add(new_role)
                        db.session.flush()
                        new_relation = UserRole(user.user_id, new_role.role_id)
                        db.session.add(new_relation)
                        db.session.commit()
                        resp = jsonify({"status": code.ST_OK,
                                        "info": "Request successful",
                                        "data": request["param"]})
                        resp.status_code = 200
                        return resp
                    else:
                        resp = jsonify({"status": code.ST_USER_NOT_ALLOWED,
                                        "info": "User doesn't have insert permission",
                                        "data": {}})
                        resp.status_code = 401
                        return resp

        resp = jsonify({"status": code.ST_USER_NOT_ALLOWED,
                        "info": "User doesn't have correct role",
                        "data": {}})
        resp.status_code = 401
        return resp


def read_file(request, db):
    """
    :param request:
    :param db:
    :return:
    """
    if "token" not in request \
            or not validate_request(request, "read_file", {"dir_root": str, "file_name": str}):
        resp = jsonify({"status": code.ST_INVALID_VALUE,
                        "info": "Request content is invalid",
                        "data": {}})
        resp.status_code = 400
        return resp
    user = get_user(request["token"])
    if not user or not user.validate_token(request["token"]):
        resp = jsonify({"status": code.ST_INVALID_VALUE,
                        "info": "Token is invalid",
                        "data": {}})
        resp.status_code = 401
        return resp

    # query for directory
    dir = Directory.query.filter_by(path=request["param"]["dir_root"]).first()
    if dir is None:
        resp = jsonify({"status": code.ST_INVALID_DIR,
                        "info": "Directory is invalid",
                        "data": {}})
        resp.status_code = 404
        return resp

    if request["param"]["dir_root"].startswith("/user"):
        # query for user roles
        roles = user.get_user_roles()
        for role in roles:
            if role.operate_dir_id == dir.dir_id:
                if role.allow_read:
                    # query for file entries in target directory
                    file = FileDir.query.filter(FileDir.dir_id == dir.dir_id,
                                                FileDir.file_name == request["param"]["file_name"]).first()
                    if file is None:
                        resp = jsonify({"status": code.ST_INVALID_FILE,
                                        "info": "Request file doesn't exist",
                                        "data": {}})
                        resp.status_code = 404
                        return resp
                    else:
                        real_file = File.query.filter(File.file_hash == file.file_hash).first()
                        return send_file(
                            os.path.join(current_app.config['UPLOADED_ITEMS_DEST'], "uploads", real_file.file_path))

                else:
                    resp = jsonify({"status": code.ST_USER_NOT_ALLOWED,
                                    "info": "User doesn't have read permission",
                                    "data": {}})
                    resp.status_code = 401
                    return resp

        resp = jsonify({"status": code.ST_USER_NOT_ALLOWED,
                        "info": "User doesn't have correct role",
                        "data": {}})
        resp.status_code = 401
        return resp
    elif request["param"]["dir_root"].startswith("/group"):
        # query for user group roles
        groups = user.get_groups()
        for group in groups:
            roles = group.get_roles()
            for role in roles:
                if role.operate_dir_id == dir.dir_id:
                    if role.allow_read:
                        # query for file entries in target directory
                        file = FileDir.query.filter(FileDir.dir_id == dir.dir_id,
                                                    FileDir.file_name == request["param"]["file_name"]).first()
                        if file is None:
                            resp = jsonify({"status": code.ST_INVALID_FILE,
                                            "info": "Request file doesn't exist",
                                            "data": {}})
                            resp.status_code = 404
                            return resp
                        else:
                            real_file = File.query.filter(File.file_hash == file.file_hash).first()
                            return send_file(
                                os.path.join(current_app.config['UPLOADED_ITEMS_DEST'], "uploads", real_file.file_path))

                    else:
                        resp = jsonify({"status": code.ST_USER_NOT_ALLOWED,
                                        "info": "User doesn't have read permission",
                                        "data": {}})
                        resp.status_code = 401
                        return resp

        resp = jsonify({"status": code.ST_USER_NOT_ALLOWED,
                        "info": "User doesn't have correct role",
                        "data": {}})
        resp.status_code = 401
        return resp


def del_file(request, db):
    """
    :param request:
    :param db:
    :return:
    """
    if "token" not in request \
            or not validate_request(request, "del_file", {"dir_root": str, "file_name": str}):
        resp = jsonify({"status": code.ST_INVALID_VALUE,
                        "info": "Request content is invalid",
                        "data": {}})
        resp.status_code = 400
        return resp
    user = get_user(request["token"])
    if not user or not user.validate_token(request["token"]):
        resp = jsonify({"status": code.ST_INVALID_VALUE,
                        "info": "Token is invalid",
                        "data": {}})
        resp.status_code = 401
        return resp

    # query for directory id
    dir = Directory.query.filter_by(path=request["param"]["dir_root"]).first()
    if dir is None:
        resp = jsonify({"status": code.ST_INVALID_DIR,
                        "info": "Directory is invalid",
                        "data": {}})
        resp.status_code = 404
        return resp

    if request["param"]["dir_root"].startswith("/user"):
        # query for user roles
        roles = user.get_user_roles()
        for role in roles:
            if role.operate_dir_id == dir.dir_id:
                if role.allow_delete:
                    # query for file entries in target directory
                    file = FileDir.query.filter(FileDir.dir_id == dir.dir_id,
                                                         FileDir.file_name == request["param"]["file_name"]).first()

                    if file is not None:
                        real_file = File.query.filter(File.file_hash == file.file_hash).first()
                        if real_file.file_ref_count == 1:
                            os.remove(
                                os.path.join(current_app.config['UPLOADED_ITEMS_DEST'], "uploads", real_file.file_path))
                            db.session.delete(real_file)
                        db.session.delete(file)
                        db.session.commit()
                        resp = jsonify({"status": code.ST_OK,
                                        "info": "Request successful",
                                        "data": request["param"]})
                        resp.status_code = 200
                        return resp
                    else:
                        resp = jsonify({"status": code.ST_INVALID_VALUE,
                                        "info": "Target file doesn't exist",
                                        "data": {}})
                        resp.status_code = 400
                        return resp
                else:
                    resp = jsonify({"status": code.ST_USER_NOT_ALLOWED,
                                    "info": "User doesn't have delete permission",
                                    "data": {}})
                    resp.status_code = 401
                    return resp

        resp = jsonify({"status": code.ST_USER_NOT_ALLOWED,
                        "info": "User doesn't have correct role",
                        "data": {}})
        resp.status_code = 401
        return resp
    elif request["param"]["dir_root"].startswith("/group"):
        # query for user group roles
        groups = user.get_groups()
        for group in groups:
            roles = group.get_roles()
            for role in roles:
                if role.operate_dir_id == dir.dir_id:
                    if role.allow_delete:
                        # query for file entries in target directory
                        file = FileDir.query.filter(FileDir.dir_id == dir.dir_id,
                                                    FileDir.file_name == request["param"]["file_name"]).first()

                        if file is not None:
                            real_file = File.query.filter(File.file_hash == file.file_hash).first()
                            if real_file.file_ref_count == 1:
                                os.remove(
                                    os.path.join(current_app.config['UPLOADED_ITEMS_DEST'], "uploads",
                                                 real_file.file_path))
                                db.session.delete(real_file)
                            db.session.delete(file)
                            db.session.commit()
                            resp = jsonify({"status": code.ST_OK,
                                            "info": "Request successful",
                                            "data": request["param"]})
                            resp.status_code = 200
                            return resp
                        else:
                            resp = jsonify({"status": code.ST_INVALID_VALUE,
                                            "info": "Target file doesn't exist",
                                            "data": {}})
                            resp.status_code = 400
                            return resp
                    else:
                        resp = jsonify({"status": code.ST_USER_NOT_ALLOWED,
                                        "info": "User doesn't have delete permission",
                                        "data": {}})
                        resp.status_code = 401
                        return resp

        resp = jsonify({"status": code.ST_USER_NOT_ALLOWED,
                        "info": "User doesn't have correct role",
                        "data": {}})
        resp.status_code = 401
        return resp


def mv_file(request, db):
    """
    :param request:
    :param db:
    :return:
    """
    if "token" not in request \
            or not validate_request(request, "mv_file", {"dir_root": str, "file_name": str,
                                                         "dest_root": str, "dest_name": str}):
        resp = jsonify({"status": code.ST_INVALID_VALUE,
                        "info": "Request content is invalid",
                        "data": {}})
        resp.status_code = 400
        return resp
    user = get_user(request["token"])
    if not user or not user.validate_token(request["token"]):
        resp = jsonify({"status": code.ST_INVALID_VALUE,
                        "info": "Token is invalid",
                        "data": {}})
        resp.status_code = 401
        return resp

    # query for directory
    src_dir = Directory.query.filter_by(path=request["param"]["dir_root"]).first()
    dst_dir = Directory.query.filter_by(path=request["param"]["dest_root"]).first()
    if src_dir is None or dst_dir is None:
        resp = jsonify({"status": code.ST_INVALID_DIR,
                        "info": "Directory is invalid",
                        "data": {}})
        resp.status_code = 404
        return resp

    src_allow_read = False
    src_allow_delete = False
    dst_allow_insert = False
    if request["param"]["dir_root"].startswith("/user"):
        # query for user roles
        roles = user.get_user_roles()
        for role in roles:
            if role.operate_dir_id == src_dir.dir_id:
                src_allow_read = role.allow_read
                src_allow_delete = role.allow_delete
    elif request["param"]["dir_root"].startswith("/group"):
        # query for user group roles
        groups = user.get_groups()
        for group in groups:
            roles = group.get_roles()
            for role in roles:
                if role.operate_dir_id == src_dir.dir_id:
                    src_allow_read = role.allow_read
                    src_allow_delete = role.allow_delete

    if request["param"]["dest_root"].startswith("/user"):
        # query for user roles
        roles = user.get_user_roles()
        for role in roles:
            if role.operate_dir_id == dst_dir.dir_id:
                dst_allow_insert = role.allow_insert
    elif request["param"]["dest_root"].startswith("/group"):
        # query for user group roles
        groups = user.get_groups()
        for group in groups:
            roles = group.get_roles()
            for role in roles:
                if role.operate_dir_id == dst_dir.dir_id:
                    dst_allow_insert = role.allow_insert

    if src_allow_read and src_allow_delete and dst_allow_insert:
        # query for file entries in source directory and target directory
        src_file = FileDir.query.filter(FileDir.dir_id == src_dir.dir_id,
                                        FileDir.file_name == request["param"]["file_name"]).first()
        dst_file = FileDir.query.filter(FileDir.dir_id == dst_dir.dir_id,
                                        FileDir.file_name == request["param"]["dest_name"]).first()
        if src_file is not None and dst_file is None:
            db.session.delete(src_file)
            new_relation = FileDir(dst_dir.dir_id, src_file.file_hash, request["param"]["dest_name"])
            db.session.add(new_relation)
            db.session.commit()
            resp = jsonify({"status": code.ST_OK,
                            "info": "Request successful",
                            "data": request["param"]})
            resp.status_code = 200
            return resp
        elif src_file is None:
            resp = jsonify({"status": code.ST_INVALID_VALUE,
                            "info": "Source file doesn't exist",
                            "data": {}})
            resp.status_code = 400
            return resp
        elif dst_file is not None:
            resp = jsonify({"status": code.ST_INVALID_VALUE,
                            "info": "Destination file already exist",
                            "data": {}})
            resp.status_code = 400
            return resp

    else:
        resp = jsonify({"status": code.ST_USER_NOT_ALLOWED,
                        "info": "User doesn't have permission",
                        "data": {}})
        resp.status_code = 401
        return resp


def copy_file(request, db):
    """
    :param request:
    :param db:
    :return:
    """
    if "token" not in request \
            or not validate_request(request, "copy_file", {"dir_root": str, "file_name": str,
                                                         "dest_root": str, "dest_name": str}):
        resp = jsonify({"status": code.ST_INVALID_VALUE,
                        "info": "Request content is invalid",
                        "data": {}})
        resp.status_code = 400
        return resp
    user = get_user(request["token"])
    if not user or not user.validate_token(request["token"]):
        resp = jsonify({"status": code.ST_INVALID_VALUE,
                        "info": "Token is invalid",
                        "data": {}})
        resp.status_code = 401
        return resp

    # query for directory
    src_dir = Directory.query.filter_by(path=request["param"]["dir_root"]).first()
    dst_dir = Directory.query.filter_by(path=request["param"]["dest_root"]).first()
    if src_dir is None or dst_dir is None:
        resp = jsonify({"status": code.ST_INVALID_DIR,
                        "info": "Directory is invalid",
                        "data": {}})
        resp.status_code = 404
        return resp

    src_allow_read = False
    dst_allow_insert = False
    if request["param"]["dir_root"].startswith("/user"):
        # query for user roles
        roles = user.get_user_roles()
        for role in roles:
            if role.operate_dir_id == src_dir.dir_id:
                src_allow_read = role.allow_read
    elif request["param"]["dir_root"].startswith("/group"):
        # query for user group roles
        groups = user.get_groups()
        for group in groups:
            roles = group.get_roles()
            for role in roles:
                if role.operate_dir_id == src_dir.dir_id:
                    src_allow_read = role.allow_read

    if request["param"]["dest_root"].startswith("/user"):
        # query for user roles
        roles = user.get_user_roles()
        for role in roles:
            if role.operate_dir_id == dst_dir.dir_id:
                dst_allow_insert = role.allow_insert
    elif request["param"]["dest_root"].startswith("/group"):
        # query for user group roles
        groups = user.get_groups()
        for group in groups:
            roles = group.get_roles()
            for role in roles:
                if role.operate_dir_id == dst_dir.dir_id:
                    dst_allow_insert = role.allow_insert

    if src_allow_read and dst_allow_insert:
        # query for file entries in source directory and target directory
        src_file = FileDir.query.filter(FileDir.dir_id == src_dir.dir_id,
                                        FileDir.file_name == request["param"]["file_name"]).first()
        dst_file = FileDir.query.filter(FileDir.dir_id == dst_dir.dir_id,
                                        FileDir.file_name == request["param"]["dest_name"]).first()
        if src_file is not None and dst_file is None:
            new_relation = FileDir(dst_dir.dir_id, src_file.file_hash, request["param"]["dest_name"])
            db.session.add(new_relation)
            db.session.commit()
            resp = jsonify({"status": code.ST_OK,
                            "info": "Request successful",
                            "data": request["param"]})
            resp.status_code = 200
            return resp
        elif src_file is None:
            resp = jsonify({"status": code.ST_INVALID_VALUE,
                            "info": "Source file doesn't exist",
                            "data": {}})
            resp.status_code = 400
            return resp
        elif dst_file is not None:
            resp = jsonify({"status": code.ST_INVALID_VALUE,
                            "info": "Destination file already exist",
                            "data": {}})
            resp.status_code = 400
            return resp

    else:
        resp = jsonify({"status": code.ST_USER_NOT_ALLOWED,
                        "info": "User doesn't have read permission",
                        "data": {}})
        resp.status_code = 401
        return resp


def upload_file(request, db, upload_file):
    """
    :param request:
    :param db:
    :return:
    """
    if "token" not in request \
            or not validate_request(request, "upload_file", {"dir_root": str, "file_name": str}):
        resp = jsonify({"status": code.ST_INVALID_VALUE,
                        "info": "Request content is invalid",
                        "data": {}})
        resp.status_code = 400
        return resp
    user = get_user(request["token"])
    if not user or not user.validate_token(request["token"]):
        resp = jsonify({"status": code.ST_INVALID_VALUE,
                        "info": "Token is invalid",
                        "data": {}})
        resp.status_code = 401
        return resp

    # query for directory
    dir = Directory.query.filter_by(path=request["param"]["dir_root"]).first()
    if dir is None:
        resp = jsonify({"status": code.ST_INVALID_DIR,
                        "info": "Directory is invalid",
                        "data": {}})
        resp.status_code = 404
        return resp

    if request["param"]["dir_root"].startswith("/user"):
        # query for user roles
        roles = user.get_user_roles()
        for role in roles:
            if role.operate_dir_id == dir.dir_id:
                if role.allow_insert:
                    # query for file entries in target directory
                    file = FileDir.query.filter(FileDir.dir_id == dir.dir_id,
                                                FileDir.file_name == request["param"]["file_name"]).first()
                    if file is not None:
                        resp = jsonify({"status": code.ST_INVALID_FILE,
                                        "info": "Request file already exists",
                                        "data": {}})
                        resp.status_code = 400
                        return resp
                    else:
                        # caculate hash
                        hasher = sha256()
                        hasher.update(upload_file)
                        hash = hasher.hexdigest()
                        save_path = os.path.join(current_app.config['UPLOADED_ITEMS_DEST'], "uploads", hash)

                        new_file = File(hash, hash)
                        real_file = File.query.filter(File.file_hash == hash).first()
                        if real_file is None:
                            with open(save_path, 'wb') as dest:
                                dest.write(upload_file)
                            db.session.add(new_file)
                        new_relation = FileDir(dir.dir_id, hash, request["param"]["file_name"])
                        db.session.add(new_relation)
                        db.session.commit()
                        resp = jsonify({"status": code.ST_OK,
                                        "info": "Request successful",
                                        "data": request["param"]})
                        resp.status_code = 200
                        return resp

                else:
                    resp = jsonify({"status": code.ST_USER_NOT_ALLOWED,
                                    "info": "User doesn't have read permission",
                                    "data": {}})
                    resp.status_code = 401
                    return resp

        resp = jsonify({"status": code.ST_USER_NOT_ALLOWED,
                        "info": "User doesn't have correct role",
                        "data": {}})
        resp.status_code = 401
        return resp
    elif request["param"]["dir_root"].startswith("/group"):
        # query for user group roles
        groups = user.get_groups()
        for group in groups:
            roles = group.get_roles()
            for role in roles:
                if role.operate_dir_id == dir.dir_id:
                    if role.allow_insert:
                        # query for file entries in target directory
                        file = FileDir.query.filter(FileDir.dir_id == dir.dir_id,
                                                    FileDir.file_name == request["param"]["file_name"]).first()
                        if file is not None:
                            resp = jsonify({"status": code.ST_INVALID_FILE,
                                            "info": "Request file already exists",
                                            "data": {}})
                            resp.status_code = 400
                            return resp
                        else:
                            # caculate hash
                            hasher = sha256()
                            hasher.update(upload_file)
                            hash = hasher.hexdigest()
                            save_path = os.path.join(current_app.config['UPLOADED_ITEMS_DEST'], "uploads", hash)
                            new_file = File(hash, hash)
                            real_file = File.query.filter(File.file_hash == hash).first()
                            if real_file is None:
                                with open(save_path, 'wb') as dest:
                                    dest.write(upload_file)
                                db.session.add(new_file)
                            new_relation = FileDir(dir.dir_id, hash, request["param"]["file_name"])
                            db.session.add(new_relation)
                            db.session.commit()
                            resp = jsonify({"status": code.ST_OK,
                                            "info": "Request successful",
                                            "data": request["param"]})
                            resp.status_code = 200
                            return resp

                    else:
                        resp = jsonify({"status": code.ST_USER_NOT_ALLOWED,
                                        "info": "User doesn't have read permission",
                                        "data": {}})
                        resp.status_code = 401
                        return resp

        resp = jsonify({"status": code.ST_USER_NOT_ALLOWED,
                        "info": "User doesn't have correct role",
                        "data": {}})
        resp.status_code = 401
        return resp


def read_meta(request, db):
    """
    :param request:
    :param db:
    :return:
    """
    if "token" not in request \
            or not validate_request(request, "read_meta", {"dir_root": str, "file_name": str}):
        resp = jsonify({"status": code.ST_INVALID_VALUE,
                        "info": "Request content is invalid",
                        "data": {}})
        resp.status_code = 400
        return resp
    user = get_user(request["token"])
    if not user or not user.validate_token(request["token"]):
        resp = jsonify({"status": code.ST_INVALID_VALUE,
                        "info": "Token is invalid",
                        "data": {}})
        resp.status_code = 401
        return resp

    # query for directory
    dir = Directory.query.filter_by(path=request["param"]["dir_root"]).first()
    if dir is None:
        resp = jsonify({"status": code.ST_INVALID_DIR,
                        "info": "Directory is invalid",
                        "data": {}})
        resp.status_code = 404
        return resp

    if request["param"]["dir_root"].startswith("/user"):
        # query for user roles
        roles = user.get_user_roles()
        for role in roles:
            if role.operate_dir_id == dir.dir_id:
                if role.allow_read:
                    # query for file entries in target directory
                    file = FileDir.query.filter(FileDir.dir_id == dir.dir_id,
                                                FileDir.file_name == request["param"]["file_name"]).first()
                    if file is None:
                        resp = jsonify({"status": code.ST_INVALID_FILE,
                                        "info": "Target file doesn't exist",
                                        "data": {}})
                        resp.status_code = 404
                        return resp
                    else:
                        meta_entries = {}
                        meta = db.session.query(MetaTable).filter(MetaTable.file_hash == file.file_hash).all()
                        if meta is not None:
                            for m in meta:
                                meta_entries[m.key] = m.value
                        resp = jsonify({"status": code.ST_OK,
                                        "info": "Request successful",
                                        "data": {"dir_root": request["param"]["dir_root"],
                                                 "file_name": request["param"]["file_name"],
                                                 "meta": meta_entries}})
                        resp.status_code = 200
                        return resp

                else:
                    resp = jsonify({"status": code.ST_USER_NOT_ALLOWED,
                                    "info": "User doesn't have read permission",
                                    "data": {}})
                    resp.status_code = 401
                    return resp

        resp = jsonify({"status": code.ST_USER_NOT_ALLOWED,
                        "info": "User doesn't have correct role",
                        "data": {}})
        resp.status_code = 401
        return resp
    elif request["param"]["dir_root"].startswith("/group"):
        # query for user group roles
        groups = user.get_groups()
        for group in groups:
            roles = group.get_roles()
            for role in roles:
                if role.operate_dir_id == dir.dir_id:
                    if role.allow_read:
                        # query for file entries in target directory
                        file = FileDir.query.filter(FileDir.dir_id == dir.dir_id,
                                                    FileDir.file_name == request["param"]["file_name"]).first()
                        if file is None:
                            resp = jsonify({"status": code.ST_INVALID_FILE,
                                            "info": "Target file doesn't exist",
                                            "data": {}})
                            resp.status_code = 404
                            return resp
                        else:
                            meta_entries = {}
                            meta = db.session.query(MetaTable).filter(MetaTable.file_hash == file.file_hash).all()
                            if meta is not None:
                                for m in meta:
                                    meta_entries[m.key] = m.value
                            resp = jsonify({"status": code.ST_OK,
                                            "info": "Request successful",
                                            "data": {"dir_root": request["param"]["dir_root"],
                                                     "file_name": request["param"]["file_name"],
                                                     "meta": meta_entries}})
                            resp.status_code = 200
                            return resp

                    else:
                        resp = jsonify({"status": code.ST_USER_NOT_ALLOWED,
                                        "info": "User doesn't have read permission",
                                        "data": {}})
                        resp.status_code = 401
                        return resp

        resp = jsonify({"status": code.ST_USER_NOT_ALLOWED,
                        "info": "User doesn't have correct role",
                        "data": {}})
        resp.status_code = 401
        return resp


def set_meta(request, db):
    """
    :param request:
    :param db:
    :return:
    """
    if "token" not in request \
            or not validate_request(request, "set_meta", {"dir_root": str, "file_name": str,
                                                           "meta_key": str, "meta_val": object}):
        resp = jsonify({"status": code.ST_INVALID_VALUE,
                        "info": "Request content is invalid",
                        "data": {}})
        resp.status_code = 400
        return resp
    user = get_user(request["token"])
    if not user or not user.validate_token(request["token"]):
        resp = jsonify({"status": code.ST_INVALID_VALUE,
                        "info": "Token is invalid",
                        "data": {}})
        resp.status_code = 401
        return resp

    # query for directory
    dir = Directory.query.filter_by(path=request["param"]["dir_root"]).first()
    if dir is None:
        resp = jsonify({"status": code.ST_INVALID_DIR,
                        "info": "Directory is invalid",
                        "data": {}})
        resp.status_code = 404
        return resp

    if request["param"]["dir_root"].startswith("/user"):
        # query for user roles
        roles = user.get_user_roles()
        for role in roles:
            if role.operate_dir_id == dir.dir_id:
                if role.allow_modify:
                    # query for file entries in target directory
                    file = FileDir.query.filter(FileDir.dir_id == dir.dir_id,
                                                FileDir.file_name == request["param"]["file_name"]).first()
                    if file is None:
                        resp = jsonify({"status": code.ST_INVALID_FILE,
                                        "info": "Target file doesn't exist",
                                        "data": {}})
                        resp.status_code = 404
                        return resp
                    else:
                        meta = db.session.query(MetaTable).filter(MetaTable.file_hash == file.file_hash
                                                                  and MetaTable.key == request["param"][
                                                                      "meta_key"]).first()
                        if meta is not None:
                            meta.value = request["param"]["meta_val"]
                            db.session.commit()
                        else:
                            new_meta = MetaTable(file.file_hash, request["param"]["meta_key"],
                                                 request["param"]["meta_val"])
                            db.session.add(new_meta)
                            db.session.commit()
                        resp = jsonify({"status": code.ST_OK,
                                        "info": "Request successful",
                                        "data": request["param"]})
                        resp.status_code = 200
                        return resp

                else:
                    resp = jsonify({"status": code.ST_USER_NOT_ALLOWED,
                                    "info": "User doesn't have read permission",
                                    "data": {}})
                    resp.status_code = 401
                    return resp

        resp = jsonify({"status": code.ST_USER_NOT_ALLOWED,
                        "info": "User doesn't have correct role",
                        "data": {}})
        resp.status_code = 401
        return resp
    elif request["param"]["dir_root"].startswith("/group"):
        # query for user group roles
        groups = user.get_groups()
        for group in groups:
            roles = group.get_roles()
            for role in roles:
                if role.operate_dir_id == dir.dir_id:
                    if role.allow_modify:
                        # query for file entries in target directory
                        file = FileDir.query.filter(FileDir.dir_id == dir.dir_id,
                                                    FileDir.file_name == request["param"]["file_name"]).first()
                        if file is None:
                            resp = jsonify({"status": code.ST_INVALID_FILE,
                                            "info": "Target file doesn't exist",
                                            "data": {}})
                            resp.status_code = 404
                            return resp
                        else:
                            meta = db.session.query(MetaTable).filter(MetaTable.file_hash == file.file_hash
                                                                      and MetaTable.key == request["param"][
                                                                          "meta_key"]).first()
                            if meta is not None:
                                meta.value = request["meta_val"]
                                db.session.commit()
                            else:
                                new_meta = MetaTable(file.file_hash, request["param"]["meta_key"],
                                                     request["param"]["meta_val"])
                                db.session.add(new_meta)
                                db.session.commit()
                            resp = jsonify({"status": code.ST_OK,
                                            "info": "Request successful",
                                            "data": request["param"]})
                            resp.status_code = 200
                            return resp

                    else:
                        resp = jsonify({"status": code.ST_USER_NOT_ALLOWED,
                                        "info": "User doesn't have read permission",
                                        "data": {}})
                        resp.status_code = 401
                        return resp

        resp = jsonify({"status": code.ST_USER_NOT_ALLOWED,
                        "info": "User doesn't have correct role",
                        "data": {}})
        resp.status_code = 401
        return resp
