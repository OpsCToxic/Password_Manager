import sqlite3

with sqlite3.connect("../password_manager.db") as db:
    cursor = db.cursor()

cursor.execute("SELECT * FROM sqlite_schema;")
all_tables = cursor.fetchall()

for table in all_tables:
    print(table)