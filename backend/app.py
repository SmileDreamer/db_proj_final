import json
from flask import Flask, request, jsonify, redirect

from backend.api import file, manage
from backend.models import *
from backend.misc import validate_request
from backend.utils import code

app = Flask(__name__)

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

@app.route("/data")
def app_data_protect():
    return redirect("/login")

@app.route("/data/<path>")
def app_data_protect2():
    return redirect("/login")

@app.route("/")
def app_index():
    return redirect("/login")


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


@app.route("/file", methods=['GET', 'POST'])
def app_file_operation():
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


@app.route("/manage", methods=['GET', 'POST'])
def app_manage_operation():
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
    if not validate_request(req, ["read_user", "del_user", "add_user", "update_user",
                                  "read_group", "del_group", "add_group", "update_group",
                                  "read_role", "del_role", "add_role", "update_role"], {}):
        resp = jsonify({"status": code.ST_INVALID_VALUE,
                        "info": "Request content is invalid",
                        "data": {}})
        resp.status_code = 400
        return resp

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
