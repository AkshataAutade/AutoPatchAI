import hashlib
import sqlite3
import unittest

from app import db, utils


class DbTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT)")
        self.conn.execute("CREATE TABLE orders (id INTEGER PRIMARY KEY, total REAL, status TEXT)")
        self.conn.execute("CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT)")
        self.conn.execute("INSERT INTO users (username) VALUES ('alice')")
        self.conn.execute("INSERT INTO orders (total, status) VALUES (10.5, 'paid'), (7.0, 'open')")
        self.conn.execute("INSERT INTO products (name) VALUES ('blue mug')")

    def test_get_user(self):
        self.assertEqual(db.get_user(self.conn, "alice"), (1, "alice"))

    def test_unknown_user(self):
        self.assertIsNone(db.get_user(self.conn, "bob"))

    def test_search_orders(self):
        self.assertEqual(db.search_orders(self.conn, "paid"), [(1, 10.5)])

    def test_find_products(self):
        self.assertEqual(db.find_products(self.conn, "mug"), [(1, "blue mug")])


class UtilsTests(unittest.TestCase):
    def test_parse_discount(self):
        self.assertEqual(utils.parse_discount("0.15"), 0.15)

    def test_cache_key_is_stable(self):
        self.assertEqual(utils.cache_key("a"), utils.cache_key("a"))
        self.assertNotEqual(utils.cache_key("a"), utils.cache_key("b"))

    def test_legacy_signature_matches_stored_md5(self):
        # Signatures already stored by other systems are MD5, so this must not change.
        self.assertEqual(utils.legacy_signature("order:42"),
                         hashlib.md5(b"order:42").hexdigest())


if __name__ == "__main__":
    unittest.main()
