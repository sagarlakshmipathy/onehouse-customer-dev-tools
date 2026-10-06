"""Postgres CDC prerequisites.

Docs: https://docs.onehouse.ai/product/ingest-data/sources/postgres-cdc
"""
from __future__ import annotations

from .aws import AwsInfraChecks
from .core import Result, SourceValidator, check, csv_list, fail, ok, plural, preview, skip, warn

MEMBERSHIPS_SQL = """
WITH RECURSIVE m(oid) AS (
    SELECT oid FROM pg_roles WHERE rolname = current_user
    UNION
    SELECT a.roleid FROM pg_auth_members a JOIN m ON a.member = m.oid
)
SELECT r.rolname FROM m JOIN pg_roles r ON r.oid = m.oid
"""

TABLES_SQL = """
SELECT n.nspname, c.relname, c.relreplident,
       EXISTS (SELECT 1 FROM pg_constraint k WHERE k.conrelid = c.oid AND k.contype = 'p') AS has_pk,
       has_table_privilege(c.oid, 'SELECT') AS can_select
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN ('r', 'p') AND NOT c.relispartition AND n.nspname = ANY(%s)
ORDER BY 1, 2
"""


class PostgresValidator(SourceValidator, AwsInfraChecks):
    name = "postgres"
    label = "Postgres"
    docs_url = "https://docs.onehouse.ai/product/ingest-data/sources/postgres-cdc"
    default_port = 5432
    supported_clouds = ("aws", "gcp")
    driver_hint = "psycopg2-binary"

    rds_engines = ("postgres", "aurora-postgresql")
    rds_params = {"rds.logical_replication": "1"}

    @classmethod
    def add_arguments(cls, parser):
        parser.add_argument("--schemas", default="public",
                            help="comma-separated schemas to scan for tables (default: public)")
        parser.add_argument("--publication", default="alltables",
                            help="publication name Onehouse will use (default: alltables)")
        parser.add_argument("--heartbeat-schema", default="public")

    def connect(self):
        import psycopg2
        conn = psycopg2.connect(host=self.args.host, port=self.port, user=self.args.user,
                                password=self.password(), dbname=self.args.database,
                                connect_timeout=self.args.connect_timeout,
                                application_name="onehouse-cdc-prereq-check")
        conn.set_session(readonly=True, autocommit=True)
        return conn

    # ---- helpers ------------------------------------------------------
    def _setting(self, name: str):
        return self.scalar("SELECT current_setting(%s, true)", (name,))

    def _roles(self) -> set[str]:
        cached = getattr(self, "_roles_cache", None)
        if cached is None:
            cached = self._roles_cache = {r[0] for r in self.query(MEMBERSHIPS_SQL)}
        return cached

    def _platform(self) -> str:
        if self._setting("rds.logical_replication") is not None:
            return "rds"
        if self._setting("cloudsql.logical_decoding") is not None:
            return "cloudsql"
        return "self-managed"

    def _tables(self) -> list[tuple]:
        """[(schema, table, replident, has_pk, can_select)] for the target tables."""
        wanted = csv_list(self.args.tables)
        schemas = sorted({t.split(".", 1)[0] for t in wanted if "." in t} or set(csv_list(self.args.schemas)))
        rows = self.query(TABLES_SQL, (schemas,))
        if not wanted:
            return rows
        index = {f"{r[0]}.{r[1]}": r for r in rows}
        missing = [t for t in wanted if t not in index]
        if missing:
            self._missing_tables = missing
        return [index[t] for t in wanted if t in index]

    # ---- database-layer checks ---------------------------------------
    @check("database.version", "Postgres version (10+ for pgoutput)")
    def check_version(self) -> Result:
        num = int(self.scalar("SHOW server_version_num"))
        ver = self.scalar("SHOW server_version")
        if num < 100000:
            return fail(f"Postgres {ver} is too old; logical decoding with pgoutput needs 10+")
        return ok(f"Postgres {ver} ({self._platform()})")

    @check("database.wal_level", "wal_level = logical (logical replication in effect)")
    def check_wal_level(self) -> Result:
        level = self.scalar("SHOW wal_level")
        if level == "logical":
            return ok("wal_level = logical")
        fix = {
            "rds": "Set rds.logical_replication = 1 in the parameter group, then reboot.",
            "cloudsql": "Set the cloudsql.logical_decoding flag to on, then restart.",
        }.get(self._platform(), "Set wal_level = logical in postgresql.conf, then restart.")
        return fail(f"wal_level = {level}", fix)

    @check("database.platform_flag", "Managed-service logical decoding flag")
    def check_platform_flag(self) -> Result:
        platform = self._platform()
        if platform == "rds":
            v = self._setting("rds.logical_replication")
            return ok("rds.logical_replication = on") if v == "on" else \
                fail(f"rds.logical_replication = {v}", "Set it to 1 in the parameter group and reboot.")
        if platform == "cloudsql":
            v = self._setting("cloudsql.logical_decoding")
            return ok("cloudsql.logical_decoding = on") if v == "on" else \
                fail(f"cloudsql.logical_decoding = {v}", "Set the database flag to on and restart.")
        return skip("self-managed Postgres: wal_level covers it")

    @check("database.replication_role", "CDC user can open a replication connection")
    def check_replication_role(self) -> Result:
        rolsuper, rolrepl = self.query(
            "SELECT rolsuper, rolreplication FROM pg_roles WHERE rolname = current_user")[0]
        roles = self._roles()
        via = [r for r in ("rds_replication", "rds_superuser") if r in roles]
        if rolsuper:
            via.append("SUPERUSER")
        if rolrepl:
            via.append("REPLICATION attribute")
        if not via:
            return fail("user has no replication privilege",
                        {"rds": "GRANT rds_superuser TO <user>;  -- as in the docs (rds_replication also works)",
                         "cloudsql": "ALTER USER <user> WITH REPLICATION;"}
                        .get(self._platform(), "ALTER USER <user> WITH REPLICATION;"))
        return ok(f"replication allowed via {', '.join(via)}")

    @check("database.superuser_role", "Managed superuser role from the docs")
    def check_superuser_role(self) -> Result:
        platform = self._platform()
        role = {"rds": "rds_superuser", "cloudsql": "cloudsqlsuperuser"}.get(platform)
        if not role:
            return skip("self-managed Postgres: no managed superuser role")
        if role in self._roles():
            return ok(f"user is a member of {role}")
        return warn(f"user is not a member of {role}, which the docs grant",
                    f"GRANT {role} TO <user>;")

    @check("database.replication_slots", "Free replication slot and WAL sender")
    def check_slots(self) -> Result:
        max_slots = int(self._setting("max_replication_slots"))
        max_senders = int(self._setting("max_wal_senders"))
        slots = self.query("""
            SELECT slot_name, plugin, active,
                   pg_size_pretty(pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn))
            FROM pg_replication_slots ORDER BY 1""")
        details = [f"max_replication_slots={max_slots}, used={len(slots)}, max_wal_senders={max_senders}"]
        details += [f"slot {s[0]} plugin={s[1]} active={s[2]} retained_wal={s[3]}" for s in slots]
        if max_senders == 0 or len(slots) >= max_slots:
            return fail("no free replication slot or WAL sender",
                        "Raise max_replication_slots / max_wal_senders, or drop unused slots.", details)
        inactive = [s[0] for s in slots if not s[2]]
        if inactive:
            return warn(f"inactive slots keep WAL and can fill the disk: {', '.join(inactive)}",
                        "Drop slots that no consumer uses: SELECT pg_drop_replication_slot('<name>');",
                        details)
        return ok(f"{max_slots - len(slots)} free slot(s)", details)

    @check("database.publication", "Publication exists and covers the tables")
    def check_publication(self) -> Result:
        name = self.args.publication
        rows = self.query("SELECT puballtables, pubinsert, pubupdate, pubdelete FROM pg_publication "
                          "WHERE pubname = %s", (name,))
        if not rows:
            return fail(f"publication {name!r} does not exist",
                        f"CREATE PUBLICATION {name} FOR ALL TABLES;")
        alltables, ins, upd, dele = rows[0]
        ops = [op for op, on in (("insert", ins), ("update", upd), ("delete", dele)) if not on]
        if ops:
            return fail(f"publication {name!r} does not publish {', '.join(ops)}",
                        f"ALTER PUBLICATION {name} SET (publish = 'insert, update, delete');")
        if alltables:
            return ok(f"publication {name!r} is FOR ALL TABLES")
        published = {f"{s}.{t}" for s, t in self.query(
            "SELECT schemaname, tablename FROM pg_publication_tables WHERE pubname = %s", (name,))}
        missing = [f"{t[0]}.{t[1]}" for t in self._tables() if f"{t[0]}.{t[1]}" not in published]
        if missing:
            return fail(f"publication {name!r} leaves out {plural(missing, 'table')}",
                        f"ALTER PUBLICATION {name} ADD TABLE <table>;  -- or recreate FOR ALL TABLES",
                        preview(missing))
        return ok(f"publication {name!r} covers all {plural(list(published), 'table')}")

    @check("database.schema_usage", "USAGE on the source schemas")
    def check_schema_usage(self) -> Result:
        schemas = sorted({t[0] for t in self._tables()} | set(csv_list(self.args.schemas)))
        rows = self.query("SELECT nspname, has_schema_privilege(nspname, 'USAGE') FROM pg_namespace "
                          "WHERE nspname = ANY(%s)", (schemas,))
        found = {r[0]: r[1] for r in rows}
        bad = [s for s in schemas if not found.get(s)]
        if bad:
            return fail(f"no USAGE on {', '.join(bad)} (or the schema does not exist)",
                        "GRANT USAGE ON SCHEMA <schema> TO <user>;")
        return ok(f"USAGE on {', '.join(schemas)}")

    @check("database.tables", "Tables have a primary key and are readable")
    def check_tables(self) -> Result:
        tables = self._tables()
        missing = getattr(self, "_missing_tables", [])
        if not tables and not missing:
            return warn(f"no tables found in schema(s) {self.args.schemas}")
        no_pk = [f"{t[0]}.{t[1]}" for t in tables if not t[3]]
        no_sel = [f"{t[0]}.{t[1]}" for t in tables if not t[4]]
        repl_nothing = [f"{t[0]}.{t[1]}" for t in tables if t[2] == "n"]
        details = ([f"missing: {t}" for t in missing] + [f"no primary key: {t}" for t in no_pk]
                   + [f"no SELECT: {t}" for t in no_sel] + [f"REPLICA IDENTITY NOTHING: {t}" for t in repl_nothing])
        if missing or no_pk or no_sel or repl_nothing:
            return fail(f"{len(set(missing + no_pk + no_sel + repl_nothing))} of "
                        f"{len(tables) + len(missing)} tables are not ready",
                        "Add a primary key and GRANT SELECT ON <table> TO <user>;", preview(details, 30))
        return ok(f"all {plural(tables, 'table')} have a primary key and are readable")

    @check("database.unsupported_types", "No DECIMAL / NUMERIC columns (unsupported)")
    def check_numeric(self) -> Result:
        names = [f"{t[0]}.{t[1]}" for t in self._tables()]
        if not names:
            return skip("no tables to inspect")
        # pg_attribute, not information_schema: the latter hides columns the user cannot read yet.
        rows = self.query("""
            SELECT n.nspname || '.' || c.relname, a.attname
            FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE a.attnum > 0 AND NOT a.attisdropped AND a.atttypid = 'numeric'::regtype
              AND n.nspname || '.' || c.relname = ANY(%s)
            ORDER BY 1, 2""", (names,))
        if rows:
            return warn(f"Onehouse does not support DECIMAL/NUMERIC; found {plural(rows, 'column')}",
                        "Cast these columns, or exclude the tables.", preview([f"{r[0]}.{r[1]}" for r in rows]))
        return ok("no DECIMAL/NUMERIC columns")

    @check("database.heartbeat", "onehouse_heartbeat table")
    def check_heartbeat(self) -> Result:
        schema, table = self.args.heartbeat_schema, self.args.heartbeat_table
        rows = self.query("""
            SELECT EXISTS (SELECT 1 FROM pg_constraint k WHERE k.conrelid = c.oid AND k.contype = 'p'),
                   has_table_privilege(c.oid, 'INSERT'), has_table_privilege(c.oid, 'UPDATE')
            FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = %s AND c.relname = %s""", (schema, table))
        create = (f"CREATE TABLE {schema}.{table} (id INTEGER DEFAULT 1 PRIMARY KEY, updated_at timestamp);\n"
                  f"INSERT INTO {schema}.{table} DEFAULT VALUES ON CONFLICT (id) DO UPDATE SET updated_at=NOW();")
        if not rows:
            return fail(f"{schema}.{table} does not exist", create)
        has_pk, can_ins, can_upd = rows[0]
        problems = [p for p, bad in (("no primary key", not has_pk), ("no INSERT", not can_ins),
                                     ("no UPDATE", not can_upd)) if bad]
        if problems:
            return fail(f"{schema}.{table}: {', '.join(problems)}",
                        f"GRANT INSERT, UPDATE ON {schema}.{table} TO <user>;")
        return ok(f"{schema}.{table} exists with a primary key; user can INSERT and UPDATE")
