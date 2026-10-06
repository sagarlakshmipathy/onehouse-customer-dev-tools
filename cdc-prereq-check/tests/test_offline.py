"""Offline tests: grant parsing and full check runs against scripted fake connections."""
import re
import unittest

from cdc_prereqs.cli import build_parser
from cdc_prereqs.core import Status
from cdc_prereqs.mysql import MySQLValidator, has_priv, parse_grants
from cdc_prereqs.oracle import OracleValidator


class FakeCursor:
    def __init__(self, conn):
        self.conn, self.rows, self.description = conn, [], None

    def execute(self, sql, params=None):
        self.conn.log.append(sql)
        for pattern, result in self.conn.script:
            if re.search(pattern, sql, re.S | re.I):
                if isinstance(result, Exception):
                    raise result
                self.rows, self.description = list(result), [("c",)]
                return
        raise AssertionError(f"unscripted SQL: {sql}")

    def fetchall(self):
        return self.rows

    def close(self):
        pass


class FakeConn:
    def __init__(self, script, version="19.0.0.0.0"):
        self.script, self.log, self.version = script, [], version

    def cursor(self):
        return FakeCursor(self)

    def rollback(self):
        pass

    def close(self):
        pass


def run(cls, script, argv):
    args = build_parser().parse_args([cls.name, "--host", "db", "--password", "x"] + argv)
    v = cls(args)
    v.connect = lambda: FakeConn(script)
    return {o.id: o.result for o in v.run(["database"])}


class GrantParsing(unittest.TestCase):
    def test_global_and_db_level(self):
        scopes = parse_grants([
            "GRANT SELECT, RELOAD, SHOW DATABASES, REPLICATION SLAVE, REPLICATION CLIENT ON *.* TO `cdc_user`@`%`",
            "GRANT LOCK TABLES ON `shop`.* TO `cdc_user`@`%`",
            "GRANT INSERT, UPDATE ON `shop`.`onehouse_heartbeat` TO `cdc_user`@`%`",
        ])
        self.assertTrue(has_priv(scopes, "RELOAD"))
        self.assertFalse(has_priv(scopes, "LOCK TABLES"))
        self.assertTrue(has_priv(scopes, "LOCK TABLES", "shop.*"))
        self.assertTrue(has_priv(scopes, "UPDATE", "shop.*", "shop.onehouse_heartbeat"))

    def test_new_names_and_all(self):
        self.assertTrue(has_priv(parse_grants(["GRANT REPLICATION REPLICA ON *.* TO x"]), "REPLICATION SLAVE"))
        self.assertTrue(has_priv(parse_grants(["GRANT ALL PRIVILEGES ON *.* TO `a`@`%` WITH GRANT OPTION"]), "RELOAD"))

    def test_column_privileges_ignored_safely(self):
        scopes = parse_grants(["GRANT SELECT (id, name), UPDATE ON `shop`.`t` TO x"])
        self.assertEqual(scopes["shop.t"], {"SELECT", "UPDATE"})


MYSQL_GOOD = [
    (r"SHOW GLOBAL VARIABLES", [("log_bin", "ON"), ("binlog_format", "ROW"), ("binlog_row_image", "FULL"),
                                ("gtid_mode", "ON"), ("enforce_gtid_consistency", "ON"),
                                ("innodb_lock_wait_timeout", "600")]),
    (r"SELECT VERSION", [("8.0.35",)]),
    (r"rds_show_configuration", [("binlog retention hours", "24", "")]),
    (r"SHOW GRANTS", [("GRANT SELECT, RELOAD, SHOW DATABASES, REPLICATION SLAVE, REPLICATION CLIENT, "
                       "LOCK TABLES ON *.* TO `cdc_user`@`%`",),
                      ("GRANT INSERT, UPDATE ON `shop`.`onehouse_heartbeat` TO `cdc_user`@`%`",)]),
    (r"TABLE_NAME = %s", [(1,)]),
    (r"information_schema.TABLES t", [("shop", "orders", "InnoDB", 1), ("shop", "onehouse_heartbeat", "InnoDB", 1)]),
]


class MySQLRun(unittest.TestCase):
    def test_all_pass(self):
        res = run(MySQLValidator, MYSQL_GOOD, ["--database", "shop"])
        bad = {k: r.message for k, r in res.items() if r.status != Status.PASS}
        self.assertEqual(bad, {})

    def test_failures(self):
        script = [(r"SHOW GLOBAL VARIABLES", [("log_bin", "ON"), ("binlog_format", "MIXED"),
                                             ("gtid_mode", "OFF_PERMISSIVE"), ("enforce_gtid_consistency", "OFF")]),
                  (r"rds_show_configuration", [("binlog retention hours", None, "")]),
                  (r"SHOW GRANTS", [("GRANT SELECT ON *.* TO x",)]),
                  (r"information_schema.TABLES t", [("shop", "events", "InnoDB", 0)]),
                  (r"TABLE_NAME = %s", [])] + MYSQL_GOOD
        res = run(MySQLValidator, script, ["--database", "shop"])
        for cid in ("database.binlog_format", "database.gtid", "database.binlog_retention",
                    "database.grants", "database.tables", "database.heartbeat"):
            self.assertEqual(res[cid].status, Status.FAIL, cid)
        self.assertIn("RELOAD", res["database.grants"].message)
        self.assertEqual(res["database.lock_wait_timeout"].status, Status.WARN)


class OracleRun(unittest.TestCase):
    def script(self, **over):
        vdb = over.get("vdb", [("ARCHIVELOG", "YES", "YES", "NO")])
        return [
            (r"SELECT CDB FROM V\$DATABASE", over.get("cdb", [("NO",)])),
            (r"FROM V\$DATABASE", vdb),
            (r"SESSION_PRIVS", [(p,) for p in over.get("privs", (
                "CREATE SESSION", "SELECT ANY TRANSACTION", "LOGMINING", "CREATE TABLE", "CREATE SEQUENCE",
                "SELECT ANY TABLE", "FLASHBACK ANY TABLE", "LOCK ANY TABLE"))]),
            (r"rds_configuration", over.get("retention", [("24",)])),
            (r"ALL_PROCEDURES", [("DBMS_LOGMNR",), ("DBMS_LOGMNR_D",)]),
            (r"FROM V\$LOGMNR_CONTENTS", Exception("ORA-01306: dbms_logmnr.start_logmnr() must be invoked")),
            (r"SELECT 1 FROM V\$", [(1,)]),
            (r"ALL_TAB_COLUMNS", [("APP", "ORDERS", "CREATED_AT")]),
            (r"t.TABLE_NAME = :t", [(1,)]),
            (r"FROM ALL_TABLES t", [("APP", "ORDERS", 1)]),
        ]

    def test_pass_with_timestamp9_warning(self):
        res = run(OracleValidator, self.script(), ["--database", "ORCL", "--user", "app"])
        self.assertEqual(res["database.unsupported_types"].status, Status.WARN)
        bad = {k: r.message for k, r in res.items() if r.status not in (Status.PASS, Status.WARN)}
        self.assertEqual(bad, {})

    def test_failures(self):
        res = run(OracleValidator, self.script(vdb=[("NOARCHIVELOG", "NO", "NO", "NO")], cdb=[("YES",)],
                                               privs=("CREATE SESSION",), retention=[("0",)]),
                  ["--database", "ORCL", "--user", "app"])
        for cid in ("database.archivelog", "database.supplemental_logging", "database.cdb_pdb",
                    "database.archive_retention", "database.system_privileges"):
            self.assertEqual(res[cid].status, Status.FAIL, cid)
        self.assertIn("SET CONTAINER", res["database.system_privileges"].message)

    def test_view_denied(self):
        script = [(r"FROM V\$TRANSACTION", Exception("ORA-00942: table or view does not exist"))] + self.script()
        res = run(OracleValidator, script, ["--database", "ORCL", "--user", "app"])
        self.assertEqual(res["database.logminer_views"].status, Status.FAIL)
        self.assertIn("V_$TRANSACTION", res["database.logminer_views"].fix)


if __name__ == "__main__":
    unittest.main()
