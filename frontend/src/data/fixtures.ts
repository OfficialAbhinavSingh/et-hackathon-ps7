// AUTO-GENERATED from python data/fixtures/ (feat/3-4-schemas-and-fixtures).
// Field names/shapes byte-match the backend JSON so the live swap never hits a
// parser mismatch. Regenerate if the python fixtures change. See contracts.ts.
import type { AnomalyEvent, EnrichedIncident } from "../types/contracts";

export const ANOMALY_FIXTURES: AnomalyEvent[] = [
  {
    "schema_version": "1.0",
    "event_id": "evt_0001",
    "timestamp": "2026-07-10T12:07:00Z",
    "src_ip": "10.0.0.5",
    "dst_ip": "203.0.113.10",
    "anomaly_score": 0.93,
    "is_anomaly": true,
    "top_features": [
      "flow_duration",
      "bytes_out",
      "dst_port"
    ],
    "raw_features": {
      "flow_duration": 12000,
      "bytes_out": 4500000,
      "dst_port": 4444
    }
  },
  {
    "schema_version": "1.0",
    "event_id": "evt_0002",
    "timestamp": "2026-07-10T12:14:00Z",
    "src_ip": "10.0.0.12",
    "dst_ip": "10.0.0.1",
    "anomaly_score": 0.12,
    "is_anomaly": false,
    "top_features": [
      "packet_count",
      "flow_duration",
      "bytes_in"
    ],
    "raw_features": {
      "packet_count": 40,
      "flow_duration": 800,
      "bytes_in": 12000,
      "dst_port": 443
    }
  },
  {
    "schema_version": "1.0",
    "event_id": "evt_0003",
    "timestamp": "2026-07-10T12:21:00Z",
    "src_ip": "10.0.0.7",
    "dst_ip": "198.51.100.23",
    "anomaly_score": 0.88,
    "is_anomaly": true,
    "top_features": [
      "bytes_out",
      "unique_dst_ports",
      "conn_rate"
    ],
    "raw_features": {
      "bytes_out": 3800000,
      "unique_dst_ports": 22,
      "conn_rate": 14.5,
      "dst_port": 8080
    }
  },
  {
    "schema_version": "1.0",
    "event_id": "evt_0004",
    "timestamp": "2026-07-10T12:28:00Z",
    "src_ip": "10.0.0.20",
    "dst_ip": "10.0.0.2",
    "anomaly_score": 0.05,
    "is_anomaly": false,
    "top_features": [
      "flow_duration",
      "packet_count",
      "bytes_in"
    ],
    "raw_features": {
      "flow_duration": 300,
      "packet_count": 18,
      "bytes_in": 4200,
      "dst_port": 80
    }
  },
  {
    "schema_version": "1.0",
    "event_id": "evt_0005",
    "timestamp": "2026-07-10T12:35:00Z",
    "src_ip": "10.0.0.9",
    "dst_ip": "203.0.113.44",
    "anomaly_score": 0.97,
    "is_anomaly": true,
    "top_features": [
      "syn_count",
      "unique_dst_ports",
      "conn_rate"
    ],
    "raw_features": {
      "syn_count": 512,
      "unique_dst_ports": 40,
      "conn_rate": 30.2,
      "dst_port": 22
    }
  },
  {
    "schema_version": "1.0",
    "event_id": "evt_0006",
    "timestamp": "2026-07-10T13:42:00Z",
    "src_ip": "10.0.0.15",
    "dst_ip": "10.0.0.4",
    "anomaly_score": 0.31,
    "is_anomaly": false,
    "top_features": [
      "bytes_in",
      "flow_duration",
      "packet_count"
    ],
    "raw_features": {
      "bytes_in": 51000,
      "flow_duration": 900,
      "packet_count": 60,
      "dst_port": 3306
    }
  },
  {
    "schema_version": "1.0",
    "event_id": "evt_0007",
    "timestamp": "2026-07-10T13:49:00Z",
    "src_ip": "10.0.0.3",
    "dst_ip": "198.51.100.7",
    "anomaly_score": 0.76,
    "is_anomaly": true,
    "top_features": [
      "bytes_out",
      "dst_port",
      "payload_entropy"
    ],
    "raw_features": {
      "bytes_out": 1200000,
      "dst_port": 6667,
      "payload_entropy": 7.8
    }
  },
  {
    "schema_version": "1.0",
    "event_id": "evt_0008",
    "timestamp": "2026-07-10T13:56:00Z",
    "src_ip": "10.0.0.18",
    "dst_ip": "10.0.0.1",
    "anomaly_score": 0.09,
    "is_anomaly": false,
    "top_features": [
      "packet_count",
      "bytes_out",
      "flow_duration"
    ],
    "raw_features": {
      "packet_count": 22,
      "bytes_out": 3000,
      "flow_duration": 400,
      "dst_port": 53
    }
  },
  {
    "schema_version": "1.0",
    "event_id": "evt_0009",
    "timestamp": "2026-07-10T13:03:00Z",
    "src_ip": "10.0.0.6",
    "dst_ip": "203.0.113.99",
    "anomaly_score": 0.95,
    "is_anomaly": true,
    "top_features": [
      "bytes_out",
      "flow_duration",
      "unique_dst_ports"
    ],
    "raw_features": {
      "bytes_out": 8200000,
      "flow_duration": 20000,
      "unique_dst_ports": 35,
      "dst_port": 445
    }
  },
  {
    "schema_version": "1.0",
    "event_id": "evt_0010",
    "timestamp": "2026-07-10T13:10:00Z",
    "src_ip": "10.0.0.22",
    "dst_ip": "10.0.0.3",
    "anomaly_score": 0.44,
    "is_anomaly": false,
    "top_features": [
      "conn_rate",
      "packet_count",
      "bytes_in"
    ],
    "raw_features": {
      "conn_rate": 5.1,
      "packet_count": 30,
      "bytes_in": 9000,
      "dst_port": 21
    }
  },
  {
    "schema_version": "1.0",
    "event_id": "evt_0011",
    "timestamp": "2026-07-10T13:17:00Z",
    "src_ip": "10.0.0.11",
    "dst_ip": "198.51.100.51",
    "anomaly_score": 0.82,
    "is_anomaly": true,
    "top_features": [
      "syn_count",
      "dst_port",
      "conn_rate"
    ],
    "raw_features": {
      "syn_count": 900,
      "dst_port": 3389,
      "conn_rate": 18.4
    }
  },
  {
    "schema_version": "1.0",
    "event_id": "evt_0012",
    "timestamp": "2026-07-10T14:24:00Z",
    "src_ip": "10.0.0.14",
    "dst_ip": "10.0.0.5",
    "anomaly_score": 0.07,
    "is_anomaly": false,
    "top_features": [
      "flow_duration",
      "bytes_in",
      "packet_count"
    ],
    "raw_features": {
      "flow_duration": 200,
      "bytes_in": 2100,
      "packet_count": 10,
      "dst_port": 443
    }
  },
  {
    "schema_version": "1.0",
    "event_id": "evt_0013",
    "timestamp": "2026-07-10T14:31:00Z",
    "src_ip": "10.0.0.8",
    "dst_ip": "203.0.113.61",
    "anomaly_score": 0.91,
    "is_anomaly": true,
    "top_features": [
      "payload_entropy",
      "bytes_out",
      "unique_dst_ports"
    ],
    "raw_features": {
      "payload_entropy": 7.9,
      "bytes_out": 5100000,
      "unique_dst_ports": 28,
      "dst_port": 4444
    }
  },
  {
    "schema_version": "1.0",
    "event_id": "evt_0014",
    "timestamp": "2026-07-10T14:38:00Z",
    "src_ip": "10.0.0.19",
    "dst_ip": "10.0.0.2",
    "anomaly_score": 0.15,
    "is_anomaly": false,
    "top_features": [
      "packet_count",
      "flow_duration",
      "bytes_out"
    ],
    "raw_features": {
      "packet_count": 35,
      "flow_duration": 650,
      "bytes_out": 2800,
      "dst_port": 25
    }
  },
  {
    "schema_version": "1.0",
    "event_id": "evt_0015",
    "timestamp": "2026-07-10T14:45:00Z",
    "src_ip": "10.0.0.4",
    "dst_ip": "198.51.100.88",
    "anomaly_score": 0.71,
    "is_anomaly": true,
    "top_features": [
      "conn_rate",
      "unique_dst_ports",
      "syn_count"
    ],
    "raw_features": {
      "conn_rate": 12.3,
      "unique_dst_ports": 19,
      "syn_count": 640,
      "dst_port": 23
    }
  },
  {
    "schema_version": "1.0",
    "event_id": "evt_0016",
    "timestamp": "2026-07-10T14:52:00Z",
    "src_ip": "10.0.0.17",
    "dst_ip": "10.0.0.6",
    "anomaly_score": 0.28,
    "is_anomaly": false,
    "top_features": [
      "bytes_in",
      "packet_count",
      "flow_duration"
    ],
    "raw_features": {
      "bytes_in": 30500,
      "packet_count": 25,
      "flow_duration": 480,
      "dst_port": 3306
    }
  },
  {
    "schema_version": "1.0",
    "event_id": "evt_0017",
    "timestamp": "2026-07-10T14:59:00Z",
    "src_ip": "10.0.0.2",
    "dst_ip": "203.0.113.14",
    "anomaly_score": 0.99,
    "is_anomaly": true,
    "top_features": [
      "bytes_out",
      "syn_count",
      "dst_port"
    ],
    "raw_features": {
      "bytes_out": 9600000,
      "syn_count": 1100,
      "dst_port": 4444
    }
  },
  {
    "schema_version": "1.0",
    "event_id": "evt_0018",
    "timestamp": "2026-07-10T15:06:00Z",
    "src_ip": "10.0.0.21",
    "dst_ip": "10.0.0.7",
    "anomaly_score": 0.18,
    "is_anomaly": false,
    "top_features": [
      "flow_duration",
      "packet_count",
      "bytes_in"
    ],
    "raw_features": {
      "flow_duration": 500,
      "packet_count": 20,
      "bytes_in": 5400,
      "dst_port": 80
    }
  },
  {
    "schema_version": "1.0",
    "event_id": "evt_0019",
    "timestamp": "2026-07-10T15:13:00Z",
    "src_ip": "10.0.0.10",
    "dst_ip": "198.51.100.32",
    "anomaly_score": 0.85,
    "is_anomaly": true,
    "top_features": [
      "unique_dst_ports",
      "conn_rate",
      "bytes_out"
    ],
    "raw_features": {
      "unique_dst_ports": 33,
      "conn_rate": 21.7,
      "bytes_out": 2900000,
      "dst_port": 8080
    }
  },
  {
    "schema_version": "1.0",
    "event_id": "evt_0020",
    "timestamp": "2026-07-10T15:20:00Z",
    "src_ip": "10.0.0.16",
    "dst_ip": "10.0.0.9",
    "anomaly_score": 0.38,
    "is_anomaly": false,
    "top_features": [
      "packet_count",
      "bytes_in",
      "duration_ratio"
    ],
    "raw_features": {
      "packet_count": 28,
      "bytes_in": 15200,
      "duration_ratio": 0.6,
      "dst_port": 22
    }
  }
];

export const ENRICHED_FIXTURES: EnrichedIncident[] = [
  {
    "schema_version": "1.0",
    "event_id": "evt_0001",
    "attack_technique": {
      "id": "T1048",
      "name": "Exfiltration Over Alternative Protocol"
    },
    "confidence": 0.87,
    "severity": "high",
    "cve_refs": [
      "CVE-2024-1234"
    ],
    "certin_refs": [
      "CIAD-2024-0012"
    ],
    "narrative": "Large outbound transfer on non-standard port 4444 after hours, consistent with exfiltration over an alternative protocol.",
    "predicted_next": {
      "tactic": "Lateral Movement",
      "note": "watch east-west traffic from 10.0.0.5"
    },
    "suggested_action": "isolate_host"
  },
  {
    "schema_version": "1.0",
    "event_id": "evt_0002",
    "attack_technique": {
      "id": "T1071.001",
      "name": "Application Layer Protocol: Web Protocols"
    },
    "confidence": 0.15,
    "severity": "low",
    "cve_refs": [],
    "certin_refs": [],
    "narrative": "Traffic profile matches routine HTTPS; no retrieved technique matches strongly, confidence kept low.",
    "predicted_next": null,
    "suggested_action": "monitor"
  },
  {
    "schema_version": "1.0",
    "event_id": "evt_0003",
    "attack_technique": {
      "id": "T1071.001",
      "name": "Application Layer Protocol: Web Protocols"
    },
    "confidence": 0.81,
    "severity": "high",
    "cve_refs": [
      "CVE-2023-4567"
    ],
    "certin_refs": [],
    "narrative": "Sustained outbound flow to many destination ports over 8080 with high connection rate, consistent with C2 beaconing over an alternate HTTP port.",
    "predicted_next": {
      "tactic": "Command and Control",
      "note": "watch for repeated beacon intervals from 10.0.0.7"
    },
    "suggested_action": "block_ip"
  },
  {
    "schema_version": "1.0",
    "event_id": "evt_0004",
    "attack_technique": {
      "id": "T1071.001",
      "name": "Application Layer Protocol: Web Protocols"
    },
    "confidence": 0.1,
    "severity": "low",
    "cve_refs": [],
    "certin_refs": [],
    "narrative": "Short flow, low packet count on port 80 \u2014 indistinguishable from routine browsing traffic.",
    "predicted_next": null,
    "suggested_action": "monitor"
  },
  {
    "schema_version": "1.0",
    "event_id": "evt_0005",
    "attack_technique": {
      "id": "T1110.001",
      "name": "Brute Force: Password Guessing"
    },
    "confidence": 0.93,
    "severity": "critical",
    "cve_refs": [
      "CVE-2020-14145"
    ],
    "certin_refs": [
      "CIAD-2024-0031"
    ],
    "narrative": "High SYN count against port 22 across 40 distinct destinations indicates SSH password-guessing sweep.",
    "predicted_next": {
      "tactic": "Lateral Movement",
      "note": "watch for successful SSH auth from 10.0.0.9 enabling pivoting"
    },
    "suggested_action": "isolate_host"
  },
  {
    "schema_version": "1.0",
    "event_id": "evt_0006",
    "attack_technique": {
      "id": "T1005",
      "name": "Data from Local System"
    },
    "confidence": 0.25,
    "severity": "low",
    "cve_refs": [],
    "certin_refs": [],
    "narrative": "Elevated inbound bytes on MySQL port 3306; no strong grounding evidence of malicious staging.",
    "predicted_next": null,
    "suggested_action": "monitor"
  },
  {
    "schema_version": "1.0",
    "event_id": "evt_0007",
    "attack_technique": {
      "id": "T1071",
      "name": "Application Layer Protocol"
    },
    "confidence": 0.78,
    "severity": "high",
    "cve_refs": [
      "CVE-2019-11500"
    ],
    "certin_refs": [],
    "narrative": "High-entropy payload over IRC port 6667 with large outbound transfer, consistent with IRC-based command and control.",
    "predicted_next": {
      "tactic": "Command and Control",
      "note": "watch for repeated connections to 198.51.100.7"
    },
    "suggested_action": "block_ip"
  },
  {
    "schema_version": "1.0",
    "event_id": "evt_0008",
    "attack_technique": {
      "id": "T1071.004",
      "name": "Application Layer Protocol: DNS"
    },
    "confidence": 0.12,
    "severity": "low",
    "cve_refs": [],
    "certin_refs": [],
    "narrative": "Low packet count, short flow duration on port 53 \u2014 consistent with routine DNS resolution.",
    "predicted_next": null,
    "suggested_action": "monitor"
  },
  {
    "schema_version": "1.0",
    "event_id": "evt_0009",
    "attack_technique": {
      "id": "T1210",
      "name": "Exploitation of Remote Services"
    },
    "confidence": 0.92,
    "severity": "critical",
    "cve_refs": [
      "CVE-2017-0144"
    ],
    "certin_refs": [
      "CIAD-2024-0044"
    ],
    "narrative": "Large outbound SMB transfer (port 445) to 35 distinct destinations, consistent with SMB exploitation and rapid lateral spread.",
    "predicted_next": {
      "tactic": "Exfiltration",
      "note": "large SMB transfer volume suggests staged data ready for exfiltration"
    },
    "suggested_action": "isolate_host"
  },
  {
    "schema_version": "1.0",
    "event_id": "evt_0010",
    "attack_technique": {
      "id": "T1105",
      "name": "Ingress Tool Transfer"
    },
    "confidence": 0.35,
    "severity": "low",
    "cve_refs": [],
    "certin_refs": [],
    "narrative": "Mild connection-rate anomaly on FTP port 21; consistent with, but not conclusive of, tool staging.",
    "predicted_next": null,
    "suggested_action": "monitor"
  },
  {
    "schema_version": "1.0",
    "event_id": "evt_0011",
    "attack_technique": {
      "id": "T1110.001",
      "name": "Brute Force: Password Guessing"
    },
    "confidence": 0.8,
    "severity": "high",
    "cve_refs": [
      "CVE-2019-0708"
    ],
    "certin_refs": [
      "CIAD-2024-0052"
    ],
    "narrative": "Elevated SYN count and connection rate against RDP port 3389, consistent with credential brute-forcing.",
    "predicted_next": {
      "tactic": "Lateral Movement",
      "note": "successful RDP auth on 10.0.0.11 would enable lateral movement"
    },
    "suggested_action": "block_ip"
  },
  {
    "schema_version": "1.0",
    "event_id": "evt_0012",
    "attack_technique": {
      "id": "T1071.001",
      "name": "Application Layer Protocol: Web Protocols"
    },
    "confidence": 0.11,
    "severity": "low",
    "cve_refs": [],
    "certin_refs": [],
    "narrative": "Short-lived low-volume flow on port 443 \u2014 consistent with routine HTTPS.",
    "predicted_next": null,
    "suggested_action": "monitor"
  },
  {
    "schema_version": "1.0",
    "event_id": "evt_0013",
    "attack_technique": {
      "id": "T1571",
      "name": "Non-Standard Port"
    },
    "confidence": 0.89,
    "severity": "critical",
    "cve_refs": [
      "CVE-2024-1234"
    ],
    "certin_refs": [
      "CIAD-2024-0012"
    ],
    "narrative": "High-entropy payload and large outbound transfer over non-standard port 4444 across 28 destinations, consistent with Meterpreter-style C2.",
    "predicted_next": {
      "tactic": "Command and Control",
      "note": "watch 10.0.0.8 for repeated connections on non-standard ports"
    },
    "suggested_action": "isolate_host"
  },
  {
    "schema_version": "1.0",
    "event_id": "evt_0014",
    "attack_technique": {
      "id": "T1071.003",
      "name": "Application Layer Protocol: Mail Protocols"
    },
    "confidence": 0.12,
    "severity": "low",
    "cve_refs": [],
    "certin_refs": [],
    "narrative": "Small flow on SMTP port 25 \u2014 consistent with routine outbound mail.",
    "predicted_next": null,
    "suggested_action": "monitor"
  },
  {
    "schema_version": "1.0",
    "event_id": "evt_0015",
    "attack_technique": {
      "id": "T1110.001",
      "name": "Brute Force: Password Guessing"
    },
    "confidence": 0.68,
    "severity": "medium",
    "cve_refs": [
      "CVE-2016-10229"
    ],
    "certin_refs": [],
    "narrative": "Elevated SYN count and connection rate against Telnet port 23 across 19 destinations, consistent with default-credential scanning.",
    "predicted_next": {
      "tactic": "Lateral Movement",
      "note": "watch for successful telnet auth from 10.0.0.4"
    },
    "suggested_action": "block_ip"
  },
  {
    "schema_version": "1.0",
    "event_id": "evt_0016",
    "attack_technique": {
      "id": "T1071.001",
      "name": "Application Layer Protocol: Web Protocols"
    },
    "confidence": 0.22,
    "severity": "low",
    "cve_refs": [],
    "certin_refs": [],
    "narrative": "Mild inbound-byte anomaly on MySQL port 3306; no strong grounding for a specific technique.",
    "predicted_next": null,
    "suggested_action": "monitor"
  },
  {
    "schema_version": "1.0",
    "event_id": "evt_0017",
    "attack_technique": {
      "id": "T1571",
      "name": "Non-Standard Port"
    },
    "confidence": 0.95,
    "severity": "critical",
    "cve_refs": [
      "CVE-2024-1234"
    ],
    "certin_refs": [
      "CIAD-2024-0012"
    ],
    "narrative": "Very large outbound transfer and elevated SYN count over non-standard port 4444, the highest-confidence exfiltration signal in this set.",
    "predicted_next": {
      "tactic": "Exfiltration",
      "note": "high outbound volume from 10.0.0.2 may indicate active data theft in progress"
    },
    "suggested_action": "isolate_host"
  },
  {
    "schema_version": "1.0",
    "event_id": "evt_0018",
    "attack_technique": {
      "id": "T1071.001",
      "name": "Application Layer Protocol: Web Protocols"
    },
    "confidence": 0.14,
    "severity": "low",
    "cve_refs": [],
    "certin_refs": [],
    "narrative": "Short flow, low packet count on port 80 \u2014 consistent with routine browsing traffic.",
    "predicted_next": null,
    "suggested_action": "monitor"
  },
  {
    "schema_version": "1.0",
    "event_id": "evt_0019",
    "attack_technique": {
      "id": "T1071.001",
      "name": "Application Layer Protocol: Web Protocols"
    },
    "confidence": 0.83,
    "severity": "high",
    "cve_refs": [
      "CVE-2023-4567"
    ],
    "certin_refs": [],
    "narrative": "Sustained outbound flow to 33 distinct destination ports over 8080 with high connection rate, consistent with C2 beaconing.",
    "predicted_next": {
      "tactic": "Command and Control",
      "note": "watch for repeated beacon intervals from 10.0.0.10"
    },
    "suggested_action": "block_ip"
  },
  {
    "schema_version": "1.0",
    "event_id": "evt_0020",
    "attack_technique": {
      "id": "T1021.004",
      "name": "Remote Services: SSH"
    },
    "confidence": 0.3,
    "severity": "low",
    "cve_refs": [],
    "certin_refs": [],
    "narrative": "Mild anomaly on SSH port 22 with low duration ratio; insufficient grounding for a high-confidence call.",
    "predicted_next": null,
    "suggested_action": "monitor"
  }
];
