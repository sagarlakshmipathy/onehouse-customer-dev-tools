"""Oracle CDC prerequisites.

Docs: https://docs.onehouse.ai/product/ingest-data/sources/oracle-cdc
User privileges follow the Debezium Oracle connector guide that the docs reference.
"""
from __future__ import annotations

from .aws import AwsInfraChecks
from .core import Result, SourceValidator, check, csv_list, fail, ok, plural, preview, skip, warn

# System privileges from the Debezium Oracle connector guide.
REQUIRED_SYS_PRIVS = ("CREATE SESSION", "SELECT ANY TRANSACTION", "LOGMINING", "CREATE TABLE", "CREATE SEQUENCE")
# Each has a per-table alternative, so missing ones only warn.
ANY_TABLE_PRIVS = ("SELECT ANY TABLE", "FLASHBACK ANY TABLE", "LOCK ANY TABLE")
REQUIRED_VIEWS = ("V$DATABASE", "V$LOG", "V$LOG_HISTORY", "V$LOGFILE", "V$ARCHIVED_LOG",
                  "V$ARCHIVE_DEST_STATUS", "V$TRANSACTION", "V$MYSTAT", "V$STATNAME",
                  "V$LOGMNR_LOGS", "V$LOGMNR_CONTENTS", "V$LOGMNR_PARAMETERS")
REQUIRED_PACKAGES = ("DBMS_LOGMNR", "DBMS_LOGMNR_D")
RETENTION_HOURS = {"prod": 12, "nonprod": 4}


class OracleValidator(SourceValidator, AwsInfraChecks):
    name = "oracle"
    label = "Oracle"
    docs_url = "https://docs.onehouse.ai/product/ingest-data/sources/oracle-cdc"
    default_port = 1521
    supported_clouds = ("aws",)
    driver_hint = "oracledb"

    rds_engines = ("oracle",)
    rds_needs_backups = True

    @classmethod
    def add_arguments(cls, parser):
        parser.add_argument("--schemas", help="comma-separated schemas (owners) to scan; default: the CDC user")
        parser.add_argument("--pdb", help="PDB name you will enter in Onehouse (CDB only)")
        parser.add_argument("--heartbeat-schema", help="owner of the heartbeat table; default: the CDC user")
        parser.add_argument("--env", choices=sorted(RETENTION_HOURS), default="prod",
                            help="sets the archive-log retention minimum: prod 12 h, nonprod 4 h")

    def connect(self):
        import oracledb  # thin mode: no Oracle Instant Client needed
        return oracledb.connect(user=self.args.user, password=self.password(),
                                dsn=f"{self.args.host}:{self.port}/{self.args.database}",
                                tcp_connect_timeout=self.args.connect_timeout)

    # ---- helpers ------------------------------------------------------
    def _user(self) -> str:
        return self.args.user.upper()

    def _schemas(self) -> list[str]:
        wanted = csv_list(self.args.tables)
        owners = {t.split(".", 1)[0].upper() for t in wanted if "." in t}
        return sorted(owners or {s.upper() for s in csv_list(self.args.schemas)} or {self._user()})

    def _vdatabase(self) -> dict:
        cached = getattr(self, "_vdb", None)
        if cached is None:
            cols = ["LOG_MODE", "SUPPLEMENTAL_LOG_DATA_MIN", "SUPPLEMENTAL_LOG_DATA_PK", "SUPPLEMENTAL_LOG_DATA_ALL"]
            row = self.query(f"SELECT {', '.join(cols)} FROM V$DATABASE")[0]
            cached = dict(zip(cols, row))
            try:
                cached["CDB"] = self.scalar("SELECT CDB FROM V$DATABASE")
            except Exception:  # noqa: BLE001 - 11g has no CDB column
                cached["CDB"] = "NO"
            self._vdb = cached
        return cached

    def _session_privs(self) -> set[str]:
        cached = getattr(self, "_privs", None)
        if cached is None:
            cached = self._privs = {r[0] for r in self.query("SELECT PRIVILEGE FROM SESSION_PRIVS")}
        return cached

    def _tables(self) -> list[tuple]:
        """[(owner, table, has_pk)] for the target tables."""
        owners = self._schemas()
        binds = {f"o{i}": o for i, o in enumerate(owners)}
        rows = self.query(f"""
            SELECT t.OWNER, t.TABLE_NAME,
                   CASE WHEN EXISTS (SELECT 1 FROM ALL_CONSTRAINTS c WHERE c.OWNER = t.OWNER
                        AND c.TABLE_NAME = t.TABLE_NAME AND c.CONSTRAINT_TYPE = 'P') THEN 1 ELSE 0 END
            FROM ALL_TABLES t
            WHERE t.OWNER IN ({', '.join(':' + k for k in binds)})
              AND t.NESTED = 'NO' AND t.SECONDARY = 'N' AND t.TABLE_NAME NOT LIKE 'BIN$%'
              AND t.IOT_TYPE IS NULL AND t.TEMPORARY = 'N'
            ORDER BY 1, 2""", binds)
        wanted = [t.upper() for t in csv_list(self.args.tables)]
        if not wanted:
            return rows
        index = {f"{r[0]}.{r[1]}": r for r in rows}
        self._missing_tables = [t for t in wanted if t not in index]
        return [index[t] for t in wanted if t in index]

    # ---- database-layer checks ---------------------------------------
    @check("database.version", "Oracle version")
    def check_version(self) -> Result:
        return ok(f"Oracle {self.conn.version}")

    @check("database.v_database", "SELECT on V$DATABASE")
    def check_v_database(self) -> Result:
        try:
            self._vdatabase()
        except Exception as e:  # noqa: BLE001
            return fail(f"cannot read V$DATABASE: {str(e).splitlines()[0]}",
                        "GRANT SELECT ON V_$DATABASE TO <user>;")
        return ok("user can read V$DATABASE")

    @check("database.archivelog", "Database runs in ARCHIVELOG mode")
    def check_archivelog(self) -> Result:
        mode = self._vdatabase()["LOG_MODE"]
        if mode == "ARCHIVELOG":
            return ok("LOG_MODE = ARCHIVELOG")
        return fail(f"LOG_MODE = {mode}",
                    "On RDS, turn on automated backups. Self-managed: SHUTDOWN IMMEDIATE; STARTUP MOUNT; "
                    "ALTER DATABASE ARCHIVELOG; ALTER DATABASE OPEN;")

    @check("database.supplemental_logging", "Supplemental logging")
    def check_supplemental(self) -> Result:
        v = self._vdatabase()
        details = [f"MIN={v['SUPPLEMENTAL_LOG_DATA_MIN']} PK={v['SUPPLEMENTAL_LOG_DATA_PK']} "
                   f"ALL={v['SUPPLEMENTAL_LOG_DATA_ALL']}"]
        if v["SUPPLEMENTAL_LOG_DATA_MIN"] not in ("YES", "IMPLICIT"):
            return fail("minimal supplemental logging is off",
                        "ALTER DATABASE ADD SUPPLEMENTAL LOG DATA;  -- RDS: "
                        "EXEC rdsadmin.rdsadmin_util.alter_supplemental_logging('ADD');", details)
        if "YES" in (v["SUPPLEMENTAL_LOG_DATA_PK"], v["SUPPLEMENTAL_LOG_DATA_ALL"]):
            return ok("database-level supplemental logging covers all tables", details)
        # Option 3 in the docs: table-level logging only.
        tables = self._tables()
        if not tables:
            return warn("no database-level PK/ALL logging, and no tables to check at table level", details=details)
        logged = {(r[0], r[1]) for r in self.query("""
            SELECT OWNER, TABLE_NAME FROM ALL_LOG_GROUPS
            WHERE LOG_GROUP_TYPE IN ('PRIMARY KEY LOGGING', 'ALL COLUMN LOGGING')""")}
        missing = [f"{t[0]}.{t[1]}" for t in tables if (t[0], t[1]) not in logged]
        if missing:
            return fail(f"no supplemental logging on {plural(missing, 'table')}",
                        "ALTER TABLE <owner>.<table> ADD SUPPLEMENTAL LOG DATA (PRIMARY KEY) COLUMNS;  "
                        "-- or ALTER DATABASE ADD SUPPLEMENTAL LOG DATA (ALL) COLUMNS;",
                        details + preview(missing))
        return ok(f"table-level supplemental logging on all {plural(tables, 'table')}", details)

    @check("database.cdb_pdb", "CDB / PDB setting matches")
    def check_cdb(self) -> Result:
        cdb = self._vdatabase()["CDB"] == "YES"
        pdb = self.args.pdb
        if cdb and not pdb:
            pdbs = [r[0] for r in self.query("SELECT NAME FROM V$PDBS WHERE NAME <> 'PDB$SEED'")] \
                if "SELECT ANY DICTIONARY" in self._session_privs() else []
            return fail("this is a CDB: Onehouse needs a PDB name", "Pass --pdb and enter the same PDB in Onehouse.",
                        [f"PDB: {p}" for p in pdbs])
        if not cdb and pdb:
            return fail("this is a non-CDB: leave the PDB name empty in Onehouse")
        return ok(f"CDB with PDB {pdb}" if cdb else "non-CDB; no PDB name needed")

    @check("database.archive_retention", "Archive-log retention")
    def check_archive_retention(self) -> Result:
        minimum = RETENTION_HOURS[self.args.env]
        try:
            hours = self.scalar("SELECT VALUE FROM rdsadmin.rds_configuration "
                                "WHERE NAME = 'archivelog retention hours'")
            source = "RDS setting"
        except Exception:  # noqa: BLE001 - not RDS
            self._rollback()
            hours = self.scalar("""
                SELECT ROUND((SYSDATE - MIN(FIRST_TIME)) * 24) FROM V$ARCHIVED_LOG
                WHERE DELETED = 'NO' AND STANDBY_DEST = 'NO'""")
            source = "oldest archive log on disk"
        hours = int(hours or 0)
        msg = f"{hours} h ({source}); {self.args.env} needs {minimum} h"
        if hours >= minimum:
            return ok(msg)
        return fail(msg, f"EXEC rdsadmin.rdsadmin_util.set_configuration('archivelog retention hours', {minimum});"
                         "  -- RDS. Self-managed: change the RMAN deletion policy.")

    @check("database.system_privileges", "CDC user system privileges")
    def check_sys_privs(self) -> Result:
        privs = self._session_privs()
        needed = list(REQUIRED_SYS_PRIVS)
        if self._vdatabase()["CDB"] == "YES":
            needed.append("SET CONTAINER")
        major = int(str(self.conn.version).split(".")[0])
        if major < 12:
            needed.remove("LOGMINING")  # 11g uses EXECUTE_CATALOG_ROLE instead
        missing = [p for p in needed if p not in privs]
        missing_any = [p for p in ANY_TABLE_PRIVS if p not in privs]
        details = [f"missing (per-table grants can replace it): {p}" for p in missing_any]
        if missing:
            return fail(f"missing {', '.join(missing)}", "GRANT " + ", ".join(missing) + " TO <user>;",
                        details)
        if missing_any:
            return warn("no ANY TABLE privileges; per-table SELECT / FLASHBACK grants must cover every table",
                        "GRANT SELECT, FLASHBACK ON <owner>.<table> TO <user>;  -- or GRANT "
                        + ", ".join(missing_any) + " TO <user>;", details)
        return ok("all required system privileges are present")

    @check("database.logminer_views", "SELECT on LogMiner V$ views")
    def check_views(self) -> Result:
        denied = []
        for view in REQUIRED_VIEWS:
            try:
                self.query(f"SELECT 1 FROM {view} WHERE ROWNUM = 1")
            except Exception as e:  # noqa: BLE001
                code = getattr(getattr(e, "args", [None])[0], "code", None)
                if code == 942 or "ORA-00942" in str(e):
                    denied.append(view)
                # Other errors (e.g. ORA-01306 outside a LogMiner session) still prove access.
        if denied:
            return fail(f"cannot read {plural(denied, 'view')}",
                        "\n".join(f"GRANT SELECT ON {v.replace('V$', 'V_$')} TO <user>;" for v in denied))
        return ok(f"user can read all {len(REQUIRED_VIEWS)} LogMiner views")

    @check("database.logminer_packages", "EXECUTE on DBMS_LOGMNR packages")
    def check_packages(self) -> Result:
        visible = {r[0] for r in self.query(
            "SELECT DISTINCT OBJECT_NAME FROM ALL_PROCEDURES WHERE OWNER = 'SYS' "
            "AND OBJECT_NAME IN ('DBMS_LOGMNR', 'DBMS_LOGMNR_D')")}
        missing = [p for p in REQUIRED_PACKAGES if p not in visible]
        if missing:
            return fail(f"no EXECUTE on {', '.join(missing)}",
                        "\n".join(f"GRANT EXECUTE ON SYS.{p} TO <user>;" for p in missing))
        return ok("user can execute DBMS_LOGMNR and DBMS_LOGMNR_D")

    @check("database.tables", "Tables have a primary key and are readable")
    def check_tables(self) -> Result:
        tables = self._tables()
        missing = getattr(self, "_missing_tables", [])
        if not tables and not missing:
            return warn(f"no tables found for owner(s) {', '.join(self._schemas())}")
        no_pk = [f"{t[0]}.{t[1]}" for t in tables if not t[2]]
        unreadable = []
        if "SELECT ANY TABLE" not in self._session_privs():
            for owner, table, _ in tables:
                try:
                    self.query(f'SELECT 1 FROM "{owner}"."{table}" WHERE 1 = 0')
                except Exception:  # noqa: BLE001
                    unreadable.append(f"{owner}.{table}")
        if missing or no_pk or unreadable:
            return fail(f"{len(set(missing + no_pk + unreadable))} of {len(tables) + len(missing)} tables are not ready",
                        "Add a primary key, and GRANT SELECT ON <owner>.<table> TO <user>;",
                        preview([f"missing or not visible: {t}" for t in missing] +
                                [f"no primary key: {t}" for t in no_pk] +
                                [f"no SELECT: {t}" for t in unreadable], 30))
        return ok(f"all {plural(tables, 'table')} have a primary key and are readable")

    @check("database.unsupported_types", "TIMESTAMP(9) columns (truncated to microseconds)")
    def check_timestamp9(self) -> Result:
        tables = self._tables()
        if not tables:
            return skip("no tables to inspect")
        wanted = {(t[0], t[1]) for t in tables}
        rows = [r for r in self.query("""
            SELECT OWNER, TABLE_NAME, COLUMN_NAME FROM ALL_TAB_COLUMNS
            WHERE DATA_TYPE LIKE 'TIMESTAMP(9)%'""") if (r[0], r[1]) in wanted]
        if rows:
            return warn(f"Onehouse keeps microseconds only; found {plural(rows, 'TIMESTAMP(9) column')}",
                        details=preview([f"{r[0]}.{r[1]}.{r[2]}" for r in rows]))
        return ok("no TIMESTAMP(9) columns")

    @check("database.heartbeat", "onehouse_heartbeat table")
    def check_heartbeat(self) -> Result:
        owner = (self.args.heartbeat_schema or self._user()).upper()
        table = self.args.heartbeat_table.upper()
        rows = self.query("""
            SELECT CASE WHEN EXISTS (SELECT 1 FROM ALL_CONSTRAINTS c WHERE c.OWNER = t.OWNER
                        AND c.TABLE_NAME = t.TABLE_NAME AND c.CONSTRAINT_TYPE = 'P') THEN 1 ELSE 0 END
            FROM ALL_TABLES t WHERE t.OWNER = :o AND t.TABLE_NAME = :t""", {"o": owner, "t": table})
        if not rows:
            return fail(f"{owner}.{table} does not exist (or the user cannot see it)",
                        f"CREATE TABLE {owner}.{table} (id NUMBER DEFAULT 1 PRIMARY KEY, updated_at TIMESTAMP);")
        if not rows[0][0]:
            return fail(f"{owner}.{table} has no primary key")
        return ok(f"{owner}.{table} exists with a primary key")
