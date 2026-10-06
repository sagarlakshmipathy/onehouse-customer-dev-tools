"""AWS infra-layer checks, shared by every source.

Network reachability uses VPC Reachability Analyzer. It traces the path from an
ENI of the Onehouse EKS cluster to the ENI of the RDS instance. It evaluates
security groups, NACLs, route tables, peering and transit gateways without
sending packets, so nothing has to be launched inside the VPC.

Source plugins tune these checks with class attributes:
  rds_engines        engine prefixes that the plugin accepts (e.g. ("postgres", "aurora-postgresql"))
  rds_params         {parameter_name: expected_value} the parameter group must carry
  rds_needs_backups  True when the change log (binlog / archivelog) needs automated backups
"""
from __future__ import annotations

import socket
import time

from .core import Result, Skip, check, fail, ok, preview, warn

ANALYZER_TIMEOUT_S = 300
PATH_TAG = "onehouse-cdc-prereq-check"


class AwsInfraChecks:
    rds_engines: tuple[str, ...] = ()
    rds_params: dict[str, str] = {}
    rds_needs_backups: bool = False

    # ---- plumbing -----------------------------------------------------
    def _aws_session(self):
        if self.args.cloud != "aws":
            raise Skip(f"AWS infra checks do not apply to --cloud {self.args.cloud}")
        cached = getattr(self, "_boto_session", None)
        if cached:
            return cached
        try:
            import boto3
        except ImportError:
            raise Skip("boto3 is not installed (pip install boto3)")
        self._boto_session = boto3.Session(profile_name=self.args.aws_profile,
                                           region_name=self.args.aws_region)
        return self._boto_session

    def _client(self, name):
        return self._aws_session().client(name)

    def _rds_instance(self) -> dict:
        if not self.args.rds_instance:
            raise Skip("pass --rds-instance to run RDS checks")
        cached = getattr(self, "_rds_cache", None)
        if cached is None:
            resp = self._client("rds").describe_db_instances(DBInstanceIdentifier=self.args.rds_instance)
            cached = self._rds_cache = resp["DBInstances"][0]
        return cached

    def _eks_cluster_name(self) -> str:
        if self.args.eks_cluster:
            return self.args.eks_cluster
        if self.args.onehouse_request_prefix:
            return f"onehouse-customer-cluster-{self.args.onehouse_request_prefix}"
        raise Skip("pass --eks-cluster or --onehouse-request-prefix to run cluster-path checks")

    def _param_values(self, inst: dict) -> dict[str, tuple[str | None, str]]:
        """Return {name: (value, group)}; instance group wins over Aurora cluster group."""
        rds = self._client("rds")
        values: dict[str, tuple[str | None, str]] = {}

        def load(paginator_name, key, group):
            for page in rds.get_paginator(paginator_name).paginate(**{key: group}):
                for p in page["Parameters"]:
                    if p["ParameterName"] in self.rds_params and p.get("ParameterValue") is not None:
                        values.setdefault(p["ParameterName"], (p["ParameterValue"], group))

        for g in inst.get("DBParameterGroups", []):
            load("describe_db_parameters", "DBParameterGroupName", g["DBParameterGroupName"])
        if inst.get("DBClusterIdentifier"):
            cluster = rds.describe_db_clusters(DBClusterIdentifier=inst["DBClusterIdentifier"])["DBClusters"][0]
            load("describe_db_cluster_parameters", "DBClusterParameterGroupName",
                 cluster["DBClusterParameterGroup"])
        return values

    # ---- checks -------------------------------------------------------
    @check("infra.cloud", "Cloud supported for this source", layer="infra")
    def check_cloud_supported(self) -> Result:
        if self.args.cloud in self.supported_clouds:
            return ok(f"{self.label} CDC supports {self.args.cloud.upper()}")
        return fail(f"{self.label} CDC does not support {self.args.cloud.upper()} "
                    f"(supported: {', '.join(c.upper() for c in self.supported_clouds)})")

    @check("infra.schema_registry", "Glue schema registry", layer="infra")
    def check_glue_registry(self) -> Result:
        glue = self._client("glue")
        names = [r["RegistryName"]
                 for page in glue.get_paginator("list_registries").paginate()
                 for r in page["Registries"]]
        wanted = self.args.glue_registry
        if wanted:
            if wanted in names:
                return ok(f"Glue schema registry {wanted!r} exists")
            return fail(f"Glue schema registry {wanted!r} not found", details=preview(names))
        if names:
            return ok(f"found {len(names)} Glue schema registr{'y' if len(names) == 1 else 'ies'}",
                      preview(names))
        return fail("no Glue schema registry in this region",
                    "Create one: aws glue create-registry --registry-name <name>")

    @check("infra.rds.instance", "RDS instance state and engine", layer="infra")
    def check_rds_instance(self) -> Result:
        inst = self._rds_instance()
        engine, status = inst["Engine"], inst["DBInstanceStatus"]
        msg = f"{inst['DBInstanceIdentifier']}: engine {engine} {inst['EngineVersion']}, status {status}"
        if self.rds_engines and not engine.startswith(self.rds_engines):
            return fail(msg, f"This instance is not a {self.label} engine.")
        if status != "available":
            return warn(msg, "Wait until the instance is 'available'.")
        return ok(msg)

    @check("infra.rds.params", "RDS parameter group values", layer="infra")
    def check_rds_params(self) -> Result:
        if not self.rds_params:
            raise Skip(f"no parameter-group requirements for {self.label}")
        inst = self._rds_instance()
        values = self._param_values(inst)
        bad, good = [], []
        for name, expected in self.rds_params.items():
            value, group = values.get(name, (None, "-"))
            line = f"{name} = {value if value is not None else '<engine default>'} (expected {expected}, group {group})"
            (good if value is not None and value.lower() == expected.lower() else bad).append(line)
        if bad:
            return fail(f"{plural_params(bad)} not set as the docs require",
                        "Use a custom parameter group, set the values, and reboot.", bad + good)
        return ok("all required parameters are set", good)

    @check("infra.rds.pending_reboot", "Parameter changes applied", layer="infra")
    def check_rds_pending_reboot(self) -> Result:
        inst = self._rds_instance()
        pending = [f"{g['DBParameterGroupName']}: {g['ParameterApplyStatus']}"
                   for g in inst.get("DBParameterGroups", []) if g["ParameterApplyStatus"] != "in-sync"]
        if pending:
            return fail("parameter group changes are not in effect yet",
                        "Reboot the instance so static parameters take effect.", pending)
        return ok("parameter groups are in-sync")

    @check("infra.rds.backups", "Automated backups (needed for change-log retention)", layer="infra")
    def check_rds_backups(self) -> Result:
        if not self.rds_needs_backups:
            raise Skip(f"not required for {self.label}")
        days = self._rds_instance().get("BackupRetentionPeriod", 0)
        if days > 0:
            return ok(f"backup retention is {days} day(s)")
        return fail("automated backups are off, so RDS does not keep the change log",
                    "Set the backup retention period to 1 day or more.")

    @check("infra.reachability", "EKS -> database path (VPC Reachability Analyzer)", layer="infra")
    def check_reachability(self) -> Result:
        if self.args.skip_reachability_analyzer:
            raise Skip("--skip-reachability-analyzer was set")
        ec2 = self._client("ec2")
        source, source_desc = self._analyzer_source(ec2)
        dest_eni, dest_ip = self._analyzer_destination(ec2)

        path_id = analysis_id = None
        try:
            path_id = ec2.create_network_insights_path(
                Source=source, Destination=dest_eni, Protocol="tcp", DestinationPort=self.port,
                TagSpecifications=[{"ResourceType": "network-insights-path",
                                    "Tags": [{"Key": "Name", "Value": PATH_TAG}]}],
            )["NetworkInsightsPath"]["NetworkInsightsPathId"]
            analysis_id = ec2.start_network_insights_analysis(
                NetworkInsightsPathId=path_id)["NetworkInsightsAnalysis"]["NetworkInsightsAnalysisId"]
            analysis = self._wait_for_analysis(ec2, analysis_id)
        finally:
            if not self.args.keep_reachability_path:
                _cleanup(ec2, path_id, analysis_id)

        where = f"{source_desc} -> {dest_eni} ({dest_ip}) tcp/{self.port}"
        if analysis["Status"] != "succeeded":
            return fail(f"analysis {analysis['Status']}: {analysis.get('StatusMessage', '')}", details=[where])
        if analysis.get("NetworkPathFound"):
            return ok("network path found", [where] + _hops(analysis))
        return fail("no network path from the EKS cluster to the database",
                    "Fix the blocking component listed below (security group, NACL, route, or peering).",
                    [where] + _explanations(analysis))

    # ---- reachability helpers ----------------------------------------
    def _analyzer_source(self, ec2) -> tuple[str, str]:
        if self.args.source_eni:
            return self.args.source_eni, f"ENI {self.args.source_eni}"
        name = self._eks_cluster_name()
        vpc_cfg = self._client("eks").describe_cluster(name=name)["cluster"]["resourcesVpcConfig"]

        # 1. A running worker node: pods use node ENIs (VPC CNI), so this is the real path.
        reservations = ec2.describe_instances(Filters=[
            {"Name": "tag-key", "Values": [f"kubernetes.io/cluster/{name}"]},
            {"Name": "instance-state-name", "Values": ["running"]},
        ])["Reservations"]
        instances = [i for r in reservations for i in r["Instances"]]
        if instances:
            iid = instances[0]["InstanceId"]
            return iid, f"EKS node {iid} ({name})"

        # 2. No nodes running: fall back to an ENI that carries the cluster security group.
        enis = ec2.describe_network_interfaces(Filters=[
            {"Name": "group-id", "Values": [vpc_cfg["clusterSecurityGroupId"]]},
            {"Name": "subnet-id", "Values": vpc_cfg["subnetIds"]},
        ])["NetworkInterfaces"]
        if enis:
            eni = enis[0]["NetworkInterfaceId"]
            return eni, f"cluster-SG ENI {eni} ({name}, no running nodes)"
        raise Skip(f"no node or cluster-SG ENI found for {name}; pass --source-eni")

    def _analyzer_destination(self, ec2) -> tuple[str, str]:
        if self.args.dest_eni:
            return self.args.dest_eni, "given"
        inst = self._rds_instance()
        address = inst["Endpoint"]["Address"]
        ip = socket.gethostbyname(address)
        vpc = inst["DBSubnetGroup"]["VpcId"]
        for flt in ("addresses.private-ip-address", "association.public-ip"):
            enis = ec2.describe_network_interfaces(Filters=[
                {"Name": flt, "Values": [ip]}, {"Name": "vpc-id", "Values": [vpc]}])["NetworkInterfaces"]
            if enis:
                return enis[0]["NetworkInterfaceId"], enis[0]["PrivateIpAddress"]
        raise Skip(f"no ENI in {vpc} owns {ip} ({address}); pass --dest-eni")

    @staticmethod
    def _wait_for_analysis(ec2, analysis_id) -> dict:
        deadline = time.monotonic() + ANALYZER_TIMEOUT_S
        while True:
            a = ec2.describe_network_insights_analyses(
                NetworkInsightsAnalysisIds=[analysis_id])["NetworkInsightsAnalyses"][0]
            if a["Status"] != "running" or time.monotonic() > deadline:
                return a
            time.sleep(5)


def plural_params(items: list) -> str:
    return f"{len(items)} parameter{'' if len(items) == 1 else 's'}"


def _cleanup(ec2, path_id, analysis_id) -> None:
    for fn, kw in ((ec2.delete_network_insights_analysis, {"NetworkInsightsAnalysisId": analysis_id}),
                   (ec2.delete_network_insights_path, {"NetworkInsightsPathId": path_id})):
        if list(kw.values())[0]:
            try:
                fn(**kw)
            except Exception:  # noqa: BLE001 - best effort
                pass


def _name(component: dict | None) -> str:
    if not component:
        return ""
    return component.get("Name") or component.get("Id") or ""


def _hops(analysis: dict) -> list[str]:
    hops = []
    for comp in analysis.get("ForwardPathComponents", []):
        label = _name(comp.get("Component"))
        if comp.get("SecurityGroupRule"):
            r = comp["SecurityGroupRule"]
            label += f" (sg rule {r.get('Direction')} {r.get('Protocol')} {r.get('PortRange', '')})"
        if label:
            hops.append(f"  via {label}")
    return hops[:20]


def _explanations(analysis: dict) -> list[str]:
    lines = []
    for ex in analysis.get("Explanations", []):
        parts = [ex.get("ExplanationCode", "?")]
        for key in ("Component", "SecurityGroup", "Acl", "RouteTable", "Subnet", "Vpc",
                    "VpcPeeringConnection", "TransitGateway"):
            if ex.get(key):
                parts.append(f"{key}={_name(ex[key])}")
        if ex.get("Port") or ex.get("PortRanges"):
            parts.append(f"ports={ex.get('Port') or ex.get('PortRanges')}")
        lines.append("  " + " ".join(parts))
    return lines or ["  (the analyzer returned no explanation codes)"]
