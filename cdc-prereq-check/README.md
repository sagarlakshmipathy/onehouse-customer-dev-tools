# Onehouse CDC prerequisite check

This tool checks that a database is ready to be a Onehouse CDC source. It reads the
requirements from the Onehouse docs and tests each one. When a check fails, the tool
prints the command that fixes it.

| Source   | Docs                                                                 | Clouds   |
|----------|----------------------------------------------------------------------|----------|
| Postgres | https://docs.onehouse.ai/product/ingest-data/sources/postgres-cdc    | AWS, GCP |
| MySQL    | https://docs.onehouse.ai/product/ingest-data/sources/mysql-cdc       | AWS      |
| Oracle   | https://docs.onehouse.ai/product/ingest-data/sources/oracle-cdc      | AWS      |

The tool does not write to your database. It only reads settings, catalogs and grants.

## What it checks

The checks run in three layers. Run all of them, or select some with `--layers`.

| Layer      | What it proves                                                                 | Needs                         |
|------------|--------------------------------------------------------------------------------|-------------------------------|
| `network`  | The machine that runs the tool can open a TCP connection to the database.       | `--host` or `--rds-instance`  |
| `infra`    | The cloud setup is correct: RDS parameter group, pending reboot, backups, Glue schema registry, and the network path from the Onehouse EKS cluster to the database. | AWS credentials |
| `database` | The database settings, the CDC user grants, the publication or change log, the heartbeat table, and primary keys on every table. | SQL login as the CDC user |

To see every check, run `./cdc-prereq-check <source> --list-checks`.

### How the infra layer tests the network path

The `infra.reachability` check uses
[VPC Reachability Analyzer](https://docs.aws.amazon.com/vpc/latest/reachability/what-is-reachability-analyzer.html).
It traces the path from a node of the Onehouse EKS cluster to the network interface of
the RDS instance on the database port. It examines security groups, network ACLs, route
tables, VPC peering and transit gateways. It does not send packets, so you do not have
to start an instance in the VPC.

- The tool picks a running EKS node as the source. If no node runs, it uses an interface
  that has the EKS cluster security group.
- When the path is blocked, the tool shows the component that blocks it, for example
  `ENI_SG_RULES_MISMATCH SecurityGroup=shop-db-sg`.
- The tool deletes the analyzer path and its result when it finishes. To keep them for
  the AWS console, add `--keep-reachability-path`.
- AWS charges about USD 0.10 for each analysis. To skip it, add `--skip-reachability-analyzer`.

## Run it in AWS CloudShell

AWS CloudShell has Python 3 and `boto3`, and it uses your console credentials.

1. Open CloudShell in the region of the database.
   To also run the `database` layer on a private database, create a
   [CloudShell VPC environment](https://docs.aws.amazon.com/cloudshell/latest/userguide/creating-vpc-environment.html)
   in the VPC of the database.
2. Get the tool and install the driver for your source:

   ```bash
   git clone https://github.com/sagarlakshmipathy/onehouse-customer-dev-tools.git
   cd onehouse-customer-dev-tools/cdc-prereq-check
   pip3 install --user psycopg2-binary   # Postgres
   pip3 install --user pymysql           # MySQL
   pip3 install --user oracledb          # Oracle (no Oracle client needed)
   ```

3. Run the check. The tool asks for the password of the CDC user:

   ```bash
   ./cdc-prereq-check postgres \
     --rds-instance my-postgres-db \
     --onehouse-request-prefix 1a2b3c4d \
     --database appdb
   ```

   `--rds-instance` sets the host and port from the RDS endpoint.
   `--onehouse-request-prefix` names the EKS cluster `onehouse-customer-cluster-<prefix>`.
   You can also give the cluster name with `--eks-cluster`.

If CloudShell cannot reach the database, run only the infra layer there:

```bash
./cdc-prereq-check mysql --rds-instance shop-db --eks-cluster onehouse-customer-cluster-1a2b3c4d --layers infra
```

Then run the database layer from a host that can log in to the database, for example a
bastion host:

```bash
CDC_DB_PASSWORD='...' ./cdc-prereq-check mysql --host shop-db.xxxx.rds.amazonaws.com --database shop --layers database
```

## Examples

```bash
# Postgres: check only some tables, with a custom publication
./cdc-prereq-check postgres --host db.internal --database appdb \
  --tables public.orders,public.customers --publication onehouse_pub

# Oracle on a CDB: give the PDB that you will enter in Onehouse
./cdc-prereq-check oracle --rds-instance orcl-prod --database ORCL --user C##CDC_USER \
  --pdb ORCLPDB1 --schemas APP,SALES --env prod

# JSON output for automation (exit code 1 when a check fails)
./cdc-prereq-check postgres --host db.internal --database appdb --format json > result.json
```

## Results and exit codes

| Status  | Meaning                                                              |
|---------|----------------------------------------------------------------------|
| `PASS`  | The prerequisite is met.                                             |
| `WARN`  | Onehouse can run, but read the message. An example is NUMERIC columns, which Onehouse does not support. |
| `FAIL`  | The prerequisite is not met. Do the `fix:` step, then run the tool again. |
| `SKIP`  | The check does not apply, or an input is missing (the message tells you which). |
| `ERROR` | The check could not run. The message shows the error.                |

The exit code is `1` when a check has the status `FAIL` or `ERROR`, `2` for a usage error,
and `0` for all other results.

## Password

The tool takes the password from one of these, in this order:

1. `--password` (not recommended: other users can see it in the process list)
2. The `CDC_DB_PASSWORD` environment variable
3. A prompt

## AWS permissions for the infra layer

All calls are read-only, except the Reachability Analyzer calls. Those calls create
and then delete a network insights path and its analysis.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadOnly",
      "Effect": "Allow",
      "Action": [
        "rds:DescribeDBInstances", "rds:DescribeDBParameters",
        "rds:DescribeDBClusters", "rds:DescribeDBClusterParameters",
        "eks:DescribeCluster",
        "ec2:DescribeInstances", "ec2:DescribeNetworkInterfaces",
        "glue:ListRegistries"
      ],
      "Resource": "*"
    },
    {
      "Sid": "ReachabilityAnalyzer",
      "Effect": "Allow",
      "Action": [
        "ec2:CreateNetworkInsightsPath", "ec2:DeleteNetworkInsightsPath",
        "ec2:StartNetworkInsightsAnalysis", "ec2:DeleteNetworkInsightsAnalysis",
        "ec2:DescribeNetworkInsightsAnalyses", "ec2:CreateTags",
        "ec2:Describe*", "elasticloadbalancing:Describe*",
        "directconnect:Describe*", "tiros:CreateQuery", "tiros:GetQueryAnswer", "tiros:GetQueryExplanation"
      ],
      "Resource": "*"
    }
  ]
}
```

Reachability Analyzer needs the `Describe*` and `tiros:*` permissions to read the network
components on the path.

## Add a new source

1. Create `cdc_prereqs/<source>.py` with a class that extends `SourceValidator` and
   `AwsInfraChecks`.
2. Set `name`, `label`, `docs_url`, `default_port`, `supported_clouds` and `driver_hint`.
   Set `rds_engines`, `rds_params` and `rds_needs_backups` for the infra layer.
3. Implement `connect()`. Add flags in `add_arguments()`.
4. Mark each check method with `@check("database.<id>", "<title>")`. Return `ok()`,
   `warn()`, `fail()` or `skip()`. Never write to the database.
5. Add the class to `SOURCES` in `cdc_prereqs/__init__.py`.

The network checks, login check, infra checks, CLI and report work with no more code.

## Tests

```bash
python3 -m unittest discover -s tests
```

The tests use scripted fake connections and the botocore `Stubber`. They do not need a
database or AWS credentials.

## Limits

- The infra layer supports AWS only. On GCP, the `infra` checks show `SKIP`, and the
  `network` and `database` checks still run.
- The `network` check tests the path from the machine that runs the tool. The
  `infra.reachability` check tests the path from the Onehouse cluster.
- MySQL privileges that come from roles do not show in `SHOW GRANTS` without `USING`.
  The tool tells you when it finds roles.
