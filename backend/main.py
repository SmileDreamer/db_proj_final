from backend import http

http.app.config["SQLALCHEMY_DATABASE_URI"] = "mysql://root:5fwHFZYy@192.168.5.2:3311"
http.app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
http.app.config["UPLOADED_ITEMS_DEST"] = "/home/Administrator/iffi/Projects/DB/proj_final/data"
http.app_init()
http.app.run("127.0.0.1", 8002)