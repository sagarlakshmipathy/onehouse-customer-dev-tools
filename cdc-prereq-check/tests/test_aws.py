"""Infra-layer tests with botocore Stubber: exact AWS calls, no network."""
import unittest
from unittest import mock

import boto3
from botocore.stub import ANY, Stubber

from cdc_prereqs.cli import build_parser
from cdc_prereqs.core import Status
from cdc_prereqs.mysql import MySQLValidator

INSTANCE = {
    "DBInstanceIdentifier": "shop-db", "Engine": "mysql", "EngineVersion": "8.0.35",
    "DBInstanceStatus": "available", "BackupRetentionPeriod": 0,
    "Endpoint": {"Address": "shop-db.abc.us-west-2.rds.amazonaws.com", "Port": 3306},
    "DBSubnetGroup": {"VpcId": "vpc-db"},
    "DBParameterGroups": [{"DBParameterGroupName": "shop-pg", "ParameterApplyStatus": "pending-reboot"}],
}


class AwsInfra(unittest.TestCase):
    def setUp(self):
        args = build_parser().parse_args(["mysql", "--aws-region", "us-west-2", "--rds-instance", "shop-db",
                                          "--onehouse-request-prefix", "abc123"])
        self.v = MySQLValidator(args)
        session = boto3.Session(region_name="us-west-2", aws_access_key_id="x", aws_secret_access_key="x")
        self.clients = {n: session.client(n) for n in ("rds", "ec2", "eks", "glue")}
        self.stubs = {n: Stubber(c) for n, c in self.clients.items()}
        self.v._boto_session = mock.Mock(client=lambda n: self.clients[n])

    def outcomes(self, only):
        for s in self.stubs.values():
            s.activate()
        with mock.patch("socket.gethostbyname", return_value="10.1.2.3"), mock.patch("time.sleep"):
            res = {o.id: o.result for o in self.v.run(["infra"], [only])}
        for s in self.stubs.values():
            s.assert_no_pending_responses()
        return res

    def test_rds_checks(self):
        rds = self.stubs["rds"]
        rds.add_response("describe_db_instances", {"DBInstances": [INSTANCE]}, {"DBInstanceIdentifier": "shop-db"})
        rds.add_response("describe_db_parameters", {"Parameters": [
            {"ParameterName": "binlog_format", "ParameterValue": "ROW"},
            {"ParameterName": "gtid-mode", "ParameterValue": "OFF"},
        ]}, {"DBParameterGroupName": "shop-pg"})
        res = self.outcomes("infra.rds")
        self.assertEqual(res["infra.rds.instance"].status, Status.PASS)
        self.assertEqual(res["infra.rds.params"].status, Status.FAIL)
        self.assertIn("2 parameters", res["infra.rds.params"].message)  # gtid-mode wrong, enforce_gtid unset
        self.assertEqual(res["infra.rds.pending_reboot"].status, Status.FAIL)
        self.assertEqual(res["infra.rds.backups"].status, Status.FAIL)

    def test_reachability_blocked_and_cleanup(self):
        rds, ec2, eks = self.stubs["rds"], self.stubs["ec2"], self.stubs["eks"]
        eks.add_response("describe_cluster", {"cluster": {"name": "onehouse-customer-cluster-abc123",
            "resourcesVpcConfig": {"clusterSecurityGroupId": "sg-eks", "subnetIds": ["subnet-1"], "vpcId": "vpc-eks"}}},
            {"name": "onehouse-customer-cluster-abc123"})
        ec2.add_response("describe_instances", {"Reservations": [{"Instances": [{"InstanceId": "i-node1"}]}]}, None)
        rds.add_response("describe_db_instances", {"DBInstances": [INSTANCE]}, {"DBInstanceIdentifier": "shop-db"})
        ec2.add_response("describe_network_interfaces",
                         {"NetworkInterfaces": [{"NetworkInterfaceId": "eni-db", "PrivateIpAddress": "10.1.2.3"}]},
                         {"Filters": [{"Name": "addresses.private-ip-address", "Values": ["10.1.2.3"]},
                                      {"Name": "vpc-id", "Values": ["vpc-db"]}]})
        ec2.add_response("create_network_insights_path", {"NetworkInsightsPath": {"NetworkInsightsPathId": "nip-1"}},
                         {"Source": "i-node1", "Destination": "eni-db", "Protocol": "tcp",
                          "DestinationPort": 3306, "TagSpecifications": ANY})
        ec2.add_response("start_network_insights_analysis",
                         {"NetworkInsightsAnalysis": {"NetworkInsightsAnalysisId": "nia-1"}},
                         {"NetworkInsightsPathId": "nip-1"})
        ec2.add_response("describe_network_insights_analyses",
                         {"NetworkInsightsAnalyses": [{"Status": "running"}]}, None)
        ec2.add_response("describe_network_insights_analyses", {"NetworkInsightsAnalyses": [{
            "Status": "succeeded", "NetworkPathFound": False,
            "Explanations": [{"ExplanationCode": "ENI_SG_RULES_MISMATCH",
                              "SecurityGroup": {"Id": "sg-db", "Name": "shop-db-sg"},
                              "Component": {"Id": "eni-db"}}]}]}, None)
        ec2.add_response("delete_network_insights_analysis", {}, {"NetworkInsightsAnalysisId": "nia-1"})
        ec2.add_response("delete_network_insights_path", {}, {"NetworkInsightsPathId": "nip-1"})
        res = self.outcomes("infra.reachability")
        r = res["infra.reachability"]
        self.assertEqual(r.status, Status.FAIL, r.message)
        self.assertTrue(any("ENI_SG_RULES_MISMATCH" in d and "shop-db-sg" in d for d in r.details), r.details)
        self.assertIn("EKS node i-node1", r.details[0])


if __name__ == "__main__":
    unittest.main()
