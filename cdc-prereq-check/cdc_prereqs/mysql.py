"""MySQL CDC prerequisites.

Docs: https://docs.onehouse.ai/product/ingest-data/sources/mysql-cdc
"""
from __future__ import annotations

import re

from .aws import AwsInfraChecks
from .core import Result, SourceValidator, check, csv_list, fail, ok, plural, preview, skip, warn

GLOBAL_PRIVS = ("SELECT", "RELOAD", "SHOW DATABASES", "REPLICATION SLAVE", "REPLICATION CLIENT", "LOCK TABLES")
# MySQL 8.0.22+ may print the new names.
ALIASES = {"REPLICATION REPLICA": "REPLICATION SLAVE"}
GRANT_RE = re.compile(r"^GRANT (.+?) ON (\S+) TO ", re.IGNORECASE)


def parse_grants(lines: list[str]) -> dict[str, set[str]]:
    """Map 'db.table' scope ('*.*', 'shop.*', 'shop.t1') to the set of privileges."""
    scopes: dict[str, set[str]] = {}
    for line in lines:
        m = GRANT_RE.match(line)
        if not m:
            continue
        scope = m.group(2).replace("`", "").lower()
        privs = {ALIASES.get(p.strip().upper(), p.strip().upper()) for p in re.sub(r"\(.*?\)", "", m.group(1)).split(",")}
        scopes.setdefault(scope, set()).update(privs)
    return scopes


def has_priv(scopes: dict[str, set[str]], priv: str, *candidates: str) -> bool:
    for scope in ("*.*",) + candidates:
        got = scopes.get(scope.lower(), set())
        if priv in got or "ALL PRIVILEGES" in got or "ALL" in got:
            return True
    return False


class MySQLValidator(SourceValidator, AwsInfraChecks):
    name = "mysql"
    label = "MySQL"
    docs_url = "https://docs.onehouse.ai/product/ingest-data/sources/mysql-cdc"
    default_port = 3306
    supported_clouds = ("aws",)
    driver_hint = "pymysql"

    rds_engines = ("mysql", "aurora-mysql", "mariadb")
    rds_params = {"binlog_format": "ROW", "gtid-mode": "ON", "enforce_gtid_consistency": "ON"}
    rds_needs_backups = True

    @classmethod
    def add_arguments(cls, parser):
        parser.add_argument("--min-binlog-hours", type=int, default=24,
                            help="warn when binlog retention is shorter than this (default: 24)")

    def connect(self):
        import pymysql
        return pymysql.connect(host=self.args.host, port=self.port, user=self.args.user,
                               password=self.password(), database=self.args.database or None,
                               connect_timeout=self.args.connect_timeout, autocommit=True)

    # ---- helpers ------------------------------------------------------
    def _vars(self) -> dict[str, str]:
        cached = getattr(self, "_vars_cache", None)
        if cached is None:
            cached = self._vars_cache = {k.lower(): v for k, v in self.query("SHOW GLOBAL VARIABLES")}
        return cached

    def _grants(self) -> tuple[dict[str, set[str]], list[str]]:
        lines = [r[0] for r in self.query("SHOW GRANTS FOR CURRENT_USER()")]
        return parse_grants(lines), lines

    def _databases(self) -> list[str]:
        wanted = csv_list(self.args.tables)
        dbs = {t.split(".", 1)[0] for t in wanted if "." in t}
        if self.args.database:
            dbs.add(self.args.database)
        return sorted(dbs)

    def _tables(self) -> list[tuple]:
        """[(db, table, engine, has_pk)] for the target tables."""
        dbs = self._databases()
        if not dbs:
            return []
        marks = ",".join(["%s"] * len(dbs))
        rows = self.query(f"""
            SELECT t.TABLE_SCHEMA, t.TABLE_NAME, t.ENGINE,
                   EXISTS (SELECT 1 FROM information_schema.TABLE_CONSTRAINTS c
                           WHERE c.TABLE_SCHEMA = t.TABLE_SCHEMA AND c.TABLE_NAME = t.TABLE_NAME
                             AND c.CONSTRAINT_TYPE = 'PRIMARY KEY')
            FROM information_schema.TABLES t
            WHERE t.TABLE_TYPE = 'BASE TABLE' AND t.TABLE_SCHEMA IN ({marks})
            ORDER BY 1, 2""", dbs)
        wanted = csv_list(self.args.tables)
        if not wanted:
            return rows
        index = {f"{r[0]}.{r[1]}": r for r in rows}
        self._missing_tables = [t for t in wanted if t not in index]
        return [index[t] for t in wanted if t in index]

    def _expect_var(self, name: str, expected: str, fix: str) -> Result:
        value = self._vars().get(name)
        if value is None:
            return fail(f"{name} is not available on this server")
        if value.upper() == expected.upper():
            return ok(f"{name} = {value}")
        return fail(f"{name} = {value} (expected {expected})", fix)

    # ---- database-layer checks ---------------------------------------
    @check("database.version", "MySQL version")
    def check_version(self) -> Result:
        return ok(f"MySQL {self.scalar('SELECT VERSION()')}")

    @check("database.log_bin", "Binary logging is on")
    def check_log_bin(self) -> Result:
        return self._expect_var("log_bin", "ON",
                                "On RDS, turn on automated backups (retention >= 1 day); binlogs need them.")

    @check("database.binlog_format", "binlog_format = ROW")
    def check_binlog_format(self) -> Result:
        return self._expect_var("binlog_format", "ROW", "Set binlog_format = ROW in the parameter group.")

    @check("database.binlog_row_image", "binlog_row_image = FULL")
    def check_binlog_row_image(self) -> Result:
        value = self._vars().get("binlog_row_image", "FULL")
        if value.upper() == "FULL":
            return ok(f"binlog_row_image = {value}")
        return warn(f"binlog_row_image = {value}; updates will not carry full rows",
                    "Set binlog_row_image = FULL in the parameter group.")

    @check("database.gtid", "gtid_mode = ON and enforce_gtid_consistency = ON")
    def check_gtid(self) -> Result:
        mode = self._vars().get("gtid_mode", "OFF")
        enforce = self._vars().get("enforce_gtid_consistency", "OFF")
        msg = f"gtid_mode = {mode}, enforce_gtid_consistency = {enforce}"
        if mode.upper() == "ON" and enforce.upper() == "ON":
            return ok(msg)
        return fail(msg, "Set gtid-mode = ON and enforce_gtid_consistency = ON in the parameter group.")

    @check("database.lock_wait_timeout", "innodb_lock_wait_timeout (optional, 600)")
    def check_lock_wait(self) -> Result:
        value = int(self._vars().get("innodb_lock_wait_timeout", 50))
        if value >= 600:
            return ok(f"innodb_lock_wait_timeout = {value}")
        return warn(f"innodb_lock_wait_timeout = {value}; the docs suggest 600 for large snapshots",
                    "Set innodb_lock_wait_timeout = 600 in the parameter group (optional).")

    @check("database.binlog_retention", "Binlog retention")
    def check_binlog_retention(self) -> Result:
        threshold = self.args.min_binlog_hours
        try:
            rows = self.query("CALL mysql.rds_show_configuration")
        except Exception:  # noqa: BLE001 - not RDS
            self._rollback()
            rows = None
        if rows is not None:
            conf = {r[0]: r[1] for r in rows}
            hours = conf.get("binlog retention hours")
            if hours in (None, "NULL", "0", 0):
                return fail("RDS binlog retention hours is NULL, so RDS purges binlogs within minutes",
                            f"CALL mysql.rds_set_configuration('binlog retention hours', {threshold});")
            hours = int(hours)
        else:
            secs = int(self._vars().get("binlog_expire_logs_seconds") or 0)
            days = int(float(self._vars().get("expire_logs_days") or 0))
            hours = secs // 3600 if secs else days * 24
            if not hours:
                return ok("binlogs never expire automatically")
        if hours < threshold:
            return warn(f"binlog retention is {hours} h (< {threshold} h); a long outage can lose the position")
        return ok(f"binlog retention is {hours} h")

    @check("database.grants", "CDC user global privileges")
    def check_grants(self) -> Result:
        scopes, lines = self._grants()
        dbs = [f"{d}.*" for d in self._databases()]
        missing = []
        for priv in GLOBAL_PRIVS:
            # SELECT and LOCK TABLES also work at database level.
            extra = dbs if priv in ("SELECT", "LOCK TABLES") else ()
            if not has_priv(scopes, priv, *extra):
                missing.append(priv)
        roles_note = [l for l in lines if l.upper().startswith("GRANT `") or l.upper().startswith("GRANT '")]
        details = lines + (["note: privileges granted through roles are not expanded"] if roles_note else [])
        if missing:
            return fail(f"missing {', '.join(missing)}",
                        "GRANT SELECT, RELOAD, SHOW DATABASES, REPLICATION SLAVE, REPLICATION CLIENT, "
                        "LOCK TABLES ON *.* TO '<user>'@'%';", details)
        return ok("user has every required privilege", details)

    @check("database.tables", "Tables have a primary key")
    def check_tables(self) -> Result:
        if not self._databases():
            return skip("pass --database or --tables db.table")
        tables = self._tables()
        missing = getattr(self, "_missing_tables", [])
        if not tables and not missing:
            return warn(f"no tables visible in {', '.join(self._databases())}")
        no_pk = [f"{t[0]}.{t[1]}" for t in tables if not t[3]]
        non_innodb = [f"{t[0]}.{t[1]} ({t[2]})" for t in tables if t[2] and t[2].upper() != "INNODB"]
        if missing or no_pk:
            return fail(f"{len(missing) + len(no_pk)} of {len(tables) + len(missing)} tables are not ready",
                        "Add a primary key to each table.",
                        preview([f"missing or not visible: {t}" for t in missing] +
                                [f"no primary key: {t}" for t in no_pk], 30))
        if non_innodb:
            return warn(f"snapshots lock non-InnoDB tables; found {plural(non_innodb, 'table')}",
                        details=preview(non_innodb))
        return ok(f"all {plural(tables, 'table')} have a primary key")

    @check("database.heartbeat", "onehouse_heartbeat table")
    def check_heartbeat(self) -> Result:
        db, table = self.args.database, self.args.heartbeat_table
        if not db:
            return skip("pass --database (the database that holds the heartbeat table)")
        rows = self.query("""
            SELECT EXISTS (SELECT 1 FROM information_schema.TABLE_CONSTRAINTS c
                           WHERE c.TABLE_SCHEMA = t.TABLE_SCHEMA AND c.TABLE_NAME = t.TABLE_NAME
                             AND c.CONSTRAINT_TYPE = 'PRIMARY KEY')
            FROM information_schema.TABLES t WHERE t.TABLE_SCHEMA = %s AND t.TABLE_NAME = %s""", (db, table))
        if not rows:
            return fail(f"{db}.{table} does not exist (or the user cannot see it)",
                        f"CREATE TABLE {db}.{table} (id INT DEFAULT 1 PRIMARY KEY, updated_at TIMESTAMP);\n"
                        f"GRANT INSERT, UPDATE ON {db}.{table} TO '<user>'@'%';\n"
                        f"INSERT INTO {db}.{table} (id) VALUES (1) ON DUPLICATE KEY UPDATE updated_at = CURRENT_TIMESTAMP;")
        scopes, _ = self._grants()
        lacking = [p for p in ("INSERT", "UPDATE") if not has_priv(scopes, p, f"{db}.*", f"{db}.{table}")]
        problems = (["no primary key"] if not rows[0][0] else []) + [f"no {p}" for p in lacking]
        if problems:
            return fail(f"{db}.{table}: {', '.join(problems)}",
                        f"GRANT INSERT, UPDATE ON {db}.{table} TO '<user>'@'%';")
        return ok(f"{db}.{table} exists with a primary key; user can INSERT and UPDATE")
