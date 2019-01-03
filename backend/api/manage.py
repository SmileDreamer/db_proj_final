from flask import jsonify
from backend.utils import code


def read_user(request, db):
    resp = jsonify({"status": code.ST_INVALID_VALUE,
                    "info": "Not implemented",
                    "data": {}})
    resp.status_code = 500
    return resp


def del_user(request, db):
    resp = jsonify({"status": code.ST_INVALID_VALUE,
                    "info": "Not implemented",
                    "data": {}})
    resp.status_code = 500
    return resp


def add_user(request, db):
    resp = jsonify({"status": code.ST_INVALID_VALUE,
                    "info": "Not implemented",
                    "data": {}})
    resp.status_code = 500
    return resp


def update_user(request, db):
    resp = jsonify({"status": code.ST_INVALID_VALUE,
                    "info": "Not implemented",
                    "data": {}})
    resp.status_code = 500
    return resp


def read_group(request, db):
    resp = jsonify({"status": code.ST_INVALID_VALUE,
                    "info": "Not implemented",
                    "data": {}})
    resp.status_code = 500
    return resp


def del_group(request, db):
    resp = jsonify({"status": code.ST_INVALID_VALUE,
                    "info": "Not implemented",
                    "data": {}})
    resp.status_code = 500
    return resp


def update_group(request, db):
    resp = jsonify({"status": code.ST_INVALID_VALUE,
                    "info": "Not implemented",
                    "data": {}})
    resp.status_code = 500
    return resp


def read_role(request, db):
    resp = jsonify({"status": code.ST_INVALID_VALUE,
                    "info": "Not implemented",
                    "data": {}})
    resp.status_code = 500
    return resp


def del_role(request, db):
    resp = jsonify({"status": code.ST_INVALID_VALUE,
                    "info": "Not implemented",
                    "data": {}})
    resp.status_code = 500
    return resp


def add_role(request, db):
    resp = jsonify({"status": code.ST_INVALID_VALUE,
                    "info": "Not implemented",
                    "data": {}})
    resp.status_code = 500
    return resp


def update_role(request, db):
    resp = jsonify({"status": code.ST_INVALID_VALUE,
                    "info": "Not implemented",
                    "data": {}})
    resp.status_code = 500
    return resp
