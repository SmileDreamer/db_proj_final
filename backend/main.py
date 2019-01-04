from backend import app

app.app.config["SQLALCHEMY_DATABASE_URI"] = "mysql://root:5fwHFZYy@192.168.5.2:3311/final_proj"
app.app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.app.config["UPLOADED_ITEMS_DEST"] = "/home/Administrator/iffi/Projects/DB/proj_final/data"
app.app_init()
app.app.run("127.0.0.1", 8002)