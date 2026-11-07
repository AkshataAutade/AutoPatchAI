def get_user(conn, username):
    cur = conn.cursor()
    cur.execute("SELECT id, username FROM users WHERE username = ?", (username,))
    return cur.fetchone()


def search_orders(conn, status):
    cur = conn.cursor()
    cur.execute("SELECT id, total FROM orders WHERE status = ?", (status,))
    return cur.fetchall()


def find_products(conn, term):
    cur = conn.cursor()
    cur.execute(f"SELECT id, name FROM products WHERE name LIKE '%{term}%'")
    return cur.fetchall()
