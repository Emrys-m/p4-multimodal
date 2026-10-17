#!/usr/bin/env python3
"""Verified three-path baseline controller used as the student starter.

The baseline installs ordinary IPv4 and IPv6 forwarding only. Follow the
milestones in STUDENT_TODO.md to add multicast scheduling, gateway roles,
fault injection and counter reads. Keep this file runnable after every step.
"""

import argparse
import grpc
import os
import sys
from time import sleep

# Import P4Runtime lib from parent utils dir
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 'utils/'))
import p4runtime_lib.bmv2
from p4runtime_lib.error_utils import printGrpcError
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper
from p4.v1 import p4runtime_pb2


def writeArp_matchRules(p4info_helper, sw, match_fields_1, match_fields_2, action_params):
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.arp_match",
        match_fields={
            "hdr.arp.oper": match_fields_1,
            "hdr.arp.tpa": match_fields_2
        },
        action_name="MyIngress.send_arp_reply",
        action_params=action_params
    )
    sw.WriteTableEntry(table_entry)


def writeIpv4_lpmRules(p4info_helper, sw, match_fields, action_params):
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.ipv4_lpm",
        match_fields={
            "hdr.ipv4.dstAddr": match_fields
        },
        action_name="MyIngress.ipv4_forward",
        action_params=action_params
    )
    sw.WriteTableEntry(table_entry)


def writeIpv6_lpmRules(p4info_helper, sw, match_fields, action_params):
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.ipv6_lpm",
        match_fields={
            "hdr.ipv6.dstAddr": match_fields
        },
        action_name="MyIngress.ipv6_forward",
        action_params=action_params
    )
    sw.WriteTableEntry(table_entry)


def writeMulticastGroup(p4info_helper, sw, group_id, replicas):
    """replicas: list of (egress_port, instance) tuples"""
    req = p4runtime_pb2.WriteRequest()
    req.device_id = sw.device_id
    req.election_id.low = 1
    req.election_id.high = 0

    update = req.updates.add()
    update.type = p4runtime_pb2.Update.INSERT
    mcast_entry = update.entity.packet_replication_engine_entry.multicast_group_entry
    mcast_entry.multicast_group_id = group_id
    for (port, instance) in replicas:
        replica = mcast_entry.replicas.add()
        replica.egress_port = port
        replica.instance = instance

    sw.client_stub.Write(req)
    print("Installed multicast group %d on %s" % (group_id, sw.name))


def writePolymorphicSchedule(p4info_helper, sw, match_fields, action_params):
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.polymorphic_schedule",
        match_fields=match_fields,
        action_name="MyIngress.start_polymorphic",
        action_params=action_params
    )
    sw.WriteTableEntry(table_entry)


def writeFaultCorrupt(p4info_helper, sw, modality_id, sequence_number, mask):
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.fault_table",
        match_fields={
            "hdr.polyShim.modality_id": modality_id,
            "hdr.polyShim.sequence_number": sequence_number,
        },
        action_name="MyIngress.corrupt_data",
        action_params={"mask": mask}
    )
    sw.WriteTableEntry(table_entry)
    print("Installed fault corrupt mode=%d seq=%d mask=0x%x on %s"
          % (modality_id, sequence_number, mask, sw.name))


def writeFaultDrop(p4info_helper, sw, modality_id, sequence_number):
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.fault_table",
        match_fields={
            "hdr.polyShim.modality_id": modality_id,
            "hdr.polyShim.sequence_number": sequence_number,
        },
        action_name="MyIngress.drop",
        action_params={}
    )
    sw.WriteTableEntry(table_entry)
    print("Installed fault drop mode=%d seq=%d on %s"
          % (modality_id, sequence_number, sw.name))
          
def writeDestinationGateway(p4info_helper, sw, ingress_port):
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.destination_gateway",
        match_fields={
            "standard_metadata.ingress_port": ingress_port,
        },
        action_name="MyIngress.set_destination_gateway",
        action_params={}
    )
    sw.WriteTableEntry(table_entry)


def install_faults(p4info_helper, switches, faults):
    """faults: list of strings like 'corrupt:1:1:0x1' or 'drop:2:1'."""
    for spec in faults:
        parts = spec.split(":")
        kind = parts[0]
        mode = int(parts[1])
        seq = int(parts[2])
        if mode == 1:
            sw = switches["s11"]
        elif mode == 2:
            sw = switches["s21"]
        elif mode == 3:
            sw = switches["s31"]
        else:
            raise ValueError("unknown modality %d" % mode)

        if kind == "corrupt":
            mask = int(parts[3], 0)
            writeFaultCorrupt(p4info_helper, sw, mode, seq, mask)
        elif kind == "drop":
            writeFaultDrop(p4info_helper, sw, mode, seq)
        else:
            raise ValueError("unknown fault kind %s" % kind)


def main(p4info_file_path, bmv2_file_path, faults):
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    try:
        s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s1', address='127.0.0.1:50051', device_id=0,
            proto_dump_file='logs/s1-p4runtime-requests.txt')
        s2 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s2', address='127.0.0.1:50052', device_id=1,
            proto_dump_file='logs/s2-p4runtime-requests.txt')
        s11 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s11', address='127.0.0.1:50053', device_id=2,
            proto_dump_file='logs/s11-p4runtime-requests.txt')
        s12 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s12', address='127.0.0.1:50054', device_id=3,
            proto_dump_file='logs/s12-p4runtime-requests.txt')
        s21 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s21', address='127.0.0.1:50055', device_id=4,
            proto_dump_file='logs/s21-p4runtime-requests.txt')
        s22 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s22', address='127.0.0.1:50056', device_id=5,
            proto_dump_file='logs/s22-p4runtime-requests.txt')
        s31 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s31', address='127.0.0.1:50057', device_id=6,
            proto_dump_file='logs/s31-p4runtime-requests.txt')
        s32 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s32', address='127.0.0.1:50058', device_id=7,
            proto_dump_file='logs/s32-p4runtime-requests.txt')
        s41 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s41', address='127.0.0.1:50059', device_id=8,
            proto_dump_file='logs/s41-p4runtime-requests.txt')
        s42 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s42', address='127.0.0.1:50060', device_id=9,
            proto_dump_file='logs/s42-p4runtime-requests.txt')

        switches = {
            "s1": s1, "s2": s2, "s11": s11, "s12": s12,
            "s21": s21, "s22": s22, "s31": s31, "s32": s32,
            "s41": s41, "s42": s42,
        }

        for sw in switches.values():
            sw.MasterArbitrationUpdate()
            sw.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                           bmv2_json_file_path=bmv2_file_path)

        writeArp_matchRules(p4info_helper, s1, [1], ["10.0.1.10", 32], {"macAddr": "08:00:00:00:01:00"})
        writeArp_matchRules(p4info_helper, s2, [1], ["10.0.2.20", 32], {"macAddr": "08:00:00:00:02:00"})

        # IPv4
        writeIpv4_lpmRules(p4info_helper, s1, ["10.0.2.2", 32], {"dstAddr": "08:00:00:00:11:00", "port": 2})
        writeIpv4_lpmRules(p4info_helper, s11, ["10.0.2.2", 32], {"dstAddr": "08:00:00:00:12:00", "port": 2})
        writeIpv4_lpmRules(p4info_helper, s12, ["10.0.2.2", 32], {"dstAddr": "08:00:00:00:02:00", "port": 2})
        writeIpv4_lpmRules(p4info_helper, s2, ["10.0.2.2", 32], {"dstAddr": "08:00:00:00:02:02", "port": 1})

        writeIpv4_lpmRules(p4info_helper, s2, ["10.0.1.1", 32], {"dstAddr": "08:00:00:00:12:00", "port": 2})
        writeIpv4_lpmRules(p4info_helper, s12, ["10.0.1.1", 32], {"dstAddr": "08:00:00:00:11:00", "port": 1})
        writeIpv4_lpmRules(p4info_helper, s11, ["10.0.1.1", 32], {"dstAddr": "08:00:00:00:01:00", "port": 1})
        writeIpv4_lpmRules(p4info_helper, s1, ["10.0.1.1", 32], {"dstAddr": "08:00:00:00:01:01", "port": 1})

        # IPv6
        writeIpv6_lpmRules(p4info_helper, s1, ["fe80::5678", 128], {"dstAddr": "08:00:00:00:11:00", "port": 3})
        writeIpv6_lpmRules(p4info_helper, s21, ["fe80::5678", 128], {"dstAddr": "08:00:00:00:12:00", "port": 2})
        writeIpv6_lpmRules(p4info_helper, s22, ["fe80::5678", 128], {"dstAddr": "08:00:00:00:02:00", "port": 2})
        writeIpv6_lpmRules(p4info_helper, s2, ["fe80::5678", 128], {"dstAddr": "08:00:00:00:02:02", "port": 1})

        writeIpv6_lpmRules(p4info_helper, s2, ["fe80::1234", 128], {"dstAddr": "08:00:00:00:12:00", "port": 3})
        writeIpv6_lpmRules(p4info_helper, s22, ["fe80::1234", 128], {"dstAddr": "08:00:00:00:11:00", "port": 1})
        writeIpv6_lpmRules(p4info_helper, s21, ["fe80::1234", 128], {"dstAddr": "08:00:00:00:01:00", "port": 1})
        writeIpv6_lpmRules(p4info_helper, s1, ["fe80::1234", 128], {"dstAddr": "08:00:00:00:01:01", "port": 1})

        # multicast group 10
        writeMulticastGroup(p4info_helper, s1, group_id=10,
                            replicas=[(2, 1), (3, 2), (4, 3)])
        writeMulticastGroup(p4info_helper, s2, group_id=10,
                            replicas=[(2, 1), (3, 2), (4, 3)])
	
	        # 目的网关角色：S1/S2 的端口 2/3/4
        writeDestinationGateway(p4info_helper, s1, 2)
        writeDestinationGateway(p4info_helper, s1, 3)
        writeDestinationGateway(p4info_helper, s1, 4)
        writeDestinationGateway(p4info_helper, s2, 2)
        writeDestinationGateway(p4info_helper, s2, 3)
        writeDestinationGateway(p4info_helper, s2, 4)
	
        # S1 正向
        writePolymorphicSchedule(p4info_helper, s1,
            match_fields={
                "standard_metadata.ingress_port": 1,
                "hdr.ipv4.dstAddr": "10.0.2.2",
                "hdr.udp.dstPort": 5000,
            },
            action_params={"dir": 0})

        # S2 反向
        writePolymorphicSchedule(p4info_helper, s2,
            match_fields={
                "standard_metadata.ingress_port": 1,
                "hdr.ipv4.dstAddr": "10.0.1.1",
                "hdr.udp.dstPort": 5000,
            },
            action_params={"dir": 1})

        # fault table
        if faults:
            install_faults(p4info_helper, switches, faults)

    except KeyboardInterrupt:
        print(" Shutting down.")
    except grpc.RpcError as e:
        printGrpcError(e)

    ShutdownAllSwitchConnections()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/polymorphic.p4.p4info.txtpb')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/polymorphic.json')
    parser.add_argument('--fault', help='fault spec, e.g. corrupt:1:1:0x1 or drop:2:1',
                        type=str, action="append", required=False, default=[])
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print("\np4info file not found: %s\nHave you run 'make'?" % args.p4info)
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print("\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json)
        parser.exit(1)
    main(args.p4info, args.bmv2_json, args.fault)
