# AutoPatch AI report: vulnerable_app

Found **7** | accepted **4** | rejected **1** | manual review **2**

| # | Rule | Severity | Location | Outcome | Remediation time |
|---|------|----------|----------|---------|------------------|
| 1 | AP002 CWE-95 | critical | app/utils.py:5 | Accepted | 0.140s |
| 2 | AP006 CWE-798 | high | app/config.py:2 | Manual review | 0.000s |
| 3 | AP001 CWE-89 | high | app/db.py:3 | Accepted | 0.150s |
| 4 | AP001 CWE-89 | high | app/db.py:9 | Accepted | 0.149s |
| 5 | AP001 CWE-89 | high | app/db.py:15 | Manual review | 0.001s |
| 6 | AP003 CWE-327 | medium | app/utils.py:10 | Accepted | 0.251s |
| 7 | AP003 CWE-327 | medium | app/utils.py:14 | Rejected (original preserved) | 0.360s |

## 1. eval() on dynamic input (app/utils.py:5)
- Outcome: Accepted. Tests pass and rescan no longer reports it.

```diff
--- a/app/utils.py
+++ b/app/utils.py
@@ -1,8 +1,9 @@
 import hashlib
+import ast
 
 
 def parse_discount(expr):
-    return eval(expr)
+    return ast.literal_eval(expr)
 
 
 def cache_key(text):
```

## 2. Hardcoded credential (app/config.py:2)
- Outcome: Manual review. No supported automatic repair rule.

## 3. SQL injection via dynamically built query (app/db.py:3)
- Outcome: Accepted. Tests pass and rescan no longer reports it.

```diff
--- a/app/db.py
+++ b/app/db.py
@@ -1,6 +1,6 @@
 def get_user(conn, username):
     cur = conn.cursor()
-    cur.execute(f"SELECT id, username FROM users WHERE username = '{username}'")
+    cur.execute("SELECT id, username FROM users WHERE username = ?", (username,))
     return cur.fetchone()
```

## 4. SQL injection via dynamically built query (app/db.py:9)
- Outcome: Accepted. Tests pass and rescan no longer reports it.

```diff
--- a/app/db.py
+++ b/app/db.py
@@ -6,7 +6,7 @@
 
 def search_orders(conn, status):
     cur = conn.cursor()
-    cur.execute("SELECT id, total FROM orders WHERE status = '" + status + "'")
+    cur.execute("SELECT id, total FROM orders WHERE status = ?", (status,))
     return cur.fetchall()
```

## 5. SQL injection via dynamically built query (app/db.py:15)
- Outcome: Manual review. Rule is supported, but this code shape cannot be repaired safely automatically.

## 6. Weak hash algorithm (MD5 / SHA-1) (app/utils.py:10)
- Outcome: Accepted. Tests pass and rescan no longer reports it.

```diff
--- a/app/utils.py
+++ b/app/utils.py
@@ -7,7 +7,7 @@
 
 
 def cache_key(text):
-    return hashlib.sha1(text.encode()).hexdigest()
+    return hashlib.sha256(text.encode()).hexdigest()
 
 
 def legacy_signature(payload):
```

## 7. Weak hash algorithm (MD5 / SHA-1) (app/utils.py:14)
- Outcome: Rejected (original preserved). Automated tests failed after the patch.

```diff
--- a/app/utils.py
+++ b/app/utils.py
@@ -11,4 +11,4 @@
 
 
 def legacy_signature(payload):
-    return hashlib.md5(payload.encode()).hexdigest()
+    return hashlib.sha256(payload.encode()).hexdigest()
```

## Time metrics

| Stage | Seconds |
|-------|---------|
| copy_project | 0.017 |
| baseline_tests | 0.151 |
| scan | 0.003 |
| total | 1.239 |

Mean time per accepted fix (repair + tests + rescan): **0.172s**
