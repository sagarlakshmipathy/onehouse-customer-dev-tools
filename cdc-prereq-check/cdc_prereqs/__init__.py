"""Onehouse CDC source prerequisite checker."""
from .mysql import MySQLValidator
from .oracle import OracleValidator
from .postgres import PostgresValidator

__version__ = "0.1.0"

# To add a source: subclass SourceValidator (+ AwsInfraChecks), mark checks with @check, register here.
SOURCES = {v.name: v for v in (PostgresValidator, MySQLValidator, OracleValidator)}
