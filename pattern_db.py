import sqlite3

class PatternDB:
    def __init__(self, db_path='pattern_dict.db'):
        self.conn = sqlite3.connect(db_path)
        self.create_table()

    def create_table(self):
        self.conn.execute('''CREATE TABLE IF NOT EXISTS patterns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE,
            content TEXT,
            reg_date TEXT,
            favorite INTEGER DEFAULT 0
        )''')
        self.conn.commit()

    def add_pattern(self, name, content, reg_date):
        try:
            cur = self.conn.cursor()
            cur.execute("SELECT id FROM patterns WHERE name=?", (name,))
            row = cur.fetchone()
            if row:
                self.conn.execute(
                    "UPDATE patterns SET content=?, reg_date=? WHERE name=?",
                    (content, reg_date, name)
                )
            else:
                self.conn.execute(
                    "INSERT INTO patterns (name, content, reg_date) VALUES (?, ?, ?)",
                    (name, content, reg_date)
                )
            self.conn.commit()
        except Exception as e:
            print("[DB 저장 에러]", e)
            # 다음 줄을 추가!
            import traceback
            traceback.print_exc()
            raise e

    def get_patterns(self, keyword=""):
        cur = self.conn.cursor()
        if keyword:
            cur.execute("SELECT * FROM patterns WHERE name LIKE ? OR content LIKE ? ORDER BY reg_date DESC", 
                        (f'%{keyword}%', f'%{keyword}%'))
        else:
            cur.execute("SELECT * FROM patterns ORDER BY reg_date DESC")
        return cur.fetchall()

    def get_pattern(self, name):
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM patterns WHERE name=?", (name,))
        return cur.fetchone()

    def delete_pattern(self, id):
        self.conn.execute("DELETE FROM patterns WHERE id=?", (id,))
        self.conn.commit()

    def toggle_favorite(self, id):
        cur = self.conn.cursor()
        cur.execute("SELECT favorite FROM patterns WHERE id=?", (id,))
        row = cur.fetchone()
        value = 0 if (row and row[0]) else 1
        self.conn.execute("UPDATE patterns SET favorite=? WHERE id=?", (value, id))
        self.conn.commit()
