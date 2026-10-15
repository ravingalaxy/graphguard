"""
Seed Data Generator for GraphGuard scenarios.
Provides realistic incident scenarios with rich node and edge topologies.
"""

from typing import Dict, List, Any
import time


class SeedData:
    """Provides seed scenarios for testing and judging GraphGuard."""

    @staticmethod
    def get_scenario_0447() -> Dict[str, Any]:
        """Scenario 1: SQL Injection Breach on Payment Gateway (APT29)"""
        now = int(time.time())
        return {
            "scenario_id": "INC-2026-0447",
            "title": "SQL Injection in Payment Gateway API",
            "severity": "CRITICAL",
            "description": "Exploit detected targeting Payment Gateway API v2.1 leading to database exfiltration and unauthorized access to cardholder data.",
            "nodes": [
                {
                    "id": "INC-2026-0447",
                    "label": "INCIDENT",
                    "props": {
                        "incr_id": "INC-2026-0447",
                        "ticket_id": "SEC-8821",
                        "severity": "CRITICAL",
                        "status": "INVESTIGATING",
                        "first_seen": now - 3600,
                        "last_seen": now,
                        "title": "SQL Injection in Payment Gateway API",
                        "description": "Exploit targeting Payment Gateway v2.1"
                    }
                },
                {
                    "id": "SYS-PAYMENT-01",
                    "label": "SYSTEM",
                    "props": {
                        "id": "SYS-PAYMENT-01",
                        "name": "Payment Gateway API v2.1",
                        "domain": "payments.internal.net",
                        "is_critical": True,
                        "has_internet_exposure": True,
                        "last_patched": now - 86400 * 30
                    }
                },
                {
                    "id": "SYS-DB-PRIMARY",
                    "label": "SYSTEM",
                    "props": {
                        "id": "SYS-DB-PRIMARY",
                        "name": "Primary Customer DB",
                        "domain": "db-cluster.internal.net",
                        "is_critical": True,
                        "has_internet_exposure": False,
                        "last_patched": now - 86400 * 15
                    }
                },
                {
                    "id": "COMP-AUTH-MOD",
                    "label": "COMPONENT",
                    "props": {
                        "id": "COMP-AUTH-MOD",
                        "name": "Auth Middleware Module",
                        "deployed_at": now - 86400 * 60,
                        "affected": True
                    }
                },
                {
                    "id": "COMP-PAY-HANDLER",
                    "label": "COMPONENT",
                    "props": {
                        "id": "COMP-PAY-HANDLER",
                        "name": "Transaction Handler v2.1",
                        "deployed_at": now - 86400 * 45,
                        "affected": True
                    }
                },
                {
                    "id": "USER-ADMIN-01",
                    "label": "USER",
                    "props": {
                        "id": "USER-ADMIN-01",
                        "email": "a.vance@company.com",
                        "role": "ADMIN",
                        "location": "US-East",
                        "access_hash": "sha256_883a0f1"
                    }
                },
                {
                    "id": "USER-DEV-02",
                    "label": "USER",
                    "props": {
                        "id": "USER-DEV-02",
                        "email": "m.chen@company.com",
                        "role": "DEOP",
                        "location": "US-West",
                        "access_hash": "sha256_118c39d"
                    }
                },
                {
                    "id": "USER-OPS-03",
                    "label": "USER",
                    "props": {
                        "id": "USER-OPS-03",
                        "email": "s.kumar@company.com",
                        "role": "READ_ONLY",
                        "location": "EU-Central",
                        "access_hash": "sha256_992e441"
                    }
                },
                {
                    "id": "THREAT-APT29",
                    "label": "THREAT",
                    "props": {
                        "tlp_level": "RED",
                        "actor": "APT29 (Cozy Bear)",
                        "technique": "SQL Injection (T1190)",
                        "confidence": 0.94
                    }
                },
                {
                    "id": "IND-IP-ATTACKER",
                    "label": "INDICATOR",
                    "props": {
                        "type": "IP",
                        "value": "209.149.88.102",
                        "source": "SIEM Alert Feed",
                        "first_seen": now - 3600,
                        "last_seen": now - 1800
                    }
                },
                {
                    "id": "IND-MALICIOUS-PAYLOAD",
                    "label": "INDICATOR",
                    "props": {
                        "type": "PAYLOAD",
                        "value": "' UNION SELECT username, password_hash FROM users--",
                        "source": "WAF Logs",
                        "first_seen": now - 3200,
                        "last_seen": now - 2000
                    }
                },
                {
                    "id": "INC-2025-0912",
                    "label": "INCIDENT",
                    "props": {
                        "incr_id": "INC-2025-0912",
                        "ticket_id": "SEC-4110",
                        "severity": "HIGH",
                        "status": "RESOLVED",
                        "first_seen": now - 86400 * 365,
                        "last_seen": now - 86400 * 364,
                        "title": "SQLi Attempt on Legacy Billing API",
                        "description": "Historical SQLi targeting billing service"
                    }
                }
            ],
            "edges": [
                {"from": "INC-2026-0447", "to": "SYS-PAYMENT-01", "type": "AFFECTS", "props": {}},
                {"from": "INC-2026-0447", "to": "SYS-DB-PRIMARY", "type": "AFFECTS", "props": {}},
                {"from": "SYS-PAYMENT-01", "to": "COMP-AUTH-MOD", "type": "CONTAINS", "props": {}},
                {"from": "SYS-PAYMENT-01", "to": "COMP-PAY-HANDLER", "type": "CONTAINS", "props": {}},
                {"from": "INC-2026-0447", "to": "USER-ADMIN-01", "type": "AFFECTED", "props": {}},
                {"from": "INC-2026-0447", "to": "USER-DEV-02", "type": "AFFECTED", "props": {}},
                {"from": "USER-ADMIN-01", "to": "SYS-PAYMENT-01", "type": "AUTHORIZED_TO", "props": {}},
                {"from": "USER-DEV-02", "to": "SYS-DB-PRIMARY", "type": "AUTHORIZED_TO", "props": {}},
                {"from": "INC-2026-0447", "to": "THREAT-APT29", "type": "LINKS_TO", "props": {}},
                {"from": "INC-2026-0447", "to": "IND-IP-ATTACKER", "type": "LINKS_TO", "props": {}},
                {"from": "INC-2026-0447", "to": "IND-MALICIOUS-PAYLOAD", "type": "LINKS_TO", "props": {}},
                {"from": "SYS-PAYMENT-01", "to": "THREAT-APT29", "type": "EXPOSED_BY", "props": {}},
                {"from": "THREAT-APT29", "to": "IND-IP-ATTACKER", "type": "USED_TOOL", "props": {}},
                {"from": "THREAT-APT29", "to": "IND-MALICIOUS-PAYLOAD", "type": "USED_TOOL", "props": {}},
                {"from": "INC-2026-0447", "to": "INC-2025-0912", "type": "SIMILAR_TO", "props": {"similarity": 0.88}}
            ]
        }

    @staticmethod
    def get_scenario_0891() -> Dict[str, Any]:
        """Scenario 2: Ransomware Lateral Movement in Corp AD (LAPSUS$)"""
        now = int(time.time())
        return {
            "scenario_id": "INC-2026-0891",
            "title": "Ransomware Lateral Movement in Active Directory",
            "severity": "CRITICAL",
            "description": "LAPSUS$ threat group executing credential dumping via Mimikatz to spread BlackCat ransomware across Domain Controllers.",
            "nodes": [
                {
                    "id": "INC-2026-0891",
                    "label": "INCIDENT",
                    "props": {
                        "incr_id": "INC-2026-0891",
                        "ticket_id": "SEC-9104",
                        "severity": "CRITICAL",
                        "status": "INVESTIGATING",
                        "first_seen": now - 7200,
                        "last_seen": now,
                        "title": "Active Directory Ransomware Propagation",
                        "description": "Mimikatz credential dump detected on DC-01"
                    }
                },
                {
                    "id": "SYS-DC-01",
                    "label": "SYSTEM",
                    "props": {
                        "id": "SYS-DC-01",
                        "name": "Primary Domain Controller",
                        "domain": "ad.corp.net",
                        "is_critical": True,
                        "has_internet_exposure": False,
                        "last_patched": now - 86400 * 10
                    }
                },
                {
                    "id": "SYS-WORKSTATION-44",
                    "label": "SYSTEM",
                    "props": {
                        "id": "SYS-WORKSTATION-44",
                        "name": "Finance Workstation 44",
                        "domain": "workstations.corp.net",
                        "is_critical": False,
                        "has_internet_exposure": True,
                        "last_patched": now - 86400 * 90
                    }
                },
                {
                    "id": "THREAT-LAPSUS",
                    "label": "THREAT",
                    "props": {
                        "tlp_level": "RED",
                        "actor": "LAPSUS$ Group",
                        "technique": "OS Credential Dumping (T1003)",
                        "confidence": 0.91
                    }
                },
                {
                    "id": "IND-HASH-MIMI",
                    "label": "INDICATOR",
                    "props": {
                        "type": "HASH",
                        "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                        "source": "EDR Alert",
                        "first_seen": now - 7200,
                        "last_seen": now - 3600
                    }
                },
                {
                    "id": "USER-FINANCE-DIR",
                    "label": "USER",
                    "props": {
                        "id": "USER-FINANCE-DIR",
                        "email": "r.taylor@company.com",
                        "role": "ADMIN",
                        "location": "UK-London",
                        "access_hash": "sha256_771f22a"
                    }
                },
                {
                    "id": "COMP-AD-SERVICE",
                    "label": "COMPONENT",
                    "props": {
                        "id": "COMP-AD-SERVICE",
                        "name": "Active Directory Service",
                        "deployed_at": now - 86400 * 120,
                        "affected": True
                    }
                },
                {
                    "id": "COMP-KERBEROS",
                    "label": "COMPONENT",
                    "props": {
                        "id": "COMP-KERBEROS",
                        "name": "Kerberos Auth Module",
                        "deployed_at": now - 86400 * 90,
                        "affected": True
                    }
                }
            ],
            "edges": [
                {"from": "INC-2026-0891", "to": "SYS-DC-01", "type": "AFFECTS", "props": {}},
                {"from": "INC-2026-0891", "to": "SYS-WORKSTATION-44", "type": "AFFECTS", "props": {}},
                {"from": "SYS-DC-01", "to": "COMP-AD-SERVICE", "type": "CONTAINS", "props": {}},
                {"from": "SYS-DC-01", "to": "COMP-KERBEROS", "type": "CONTAINS", "props": {}},
                {"from": "INC-2026-0891", "to": "USER-FINANCE-DIR", "type": "AFFECTED", "props": {}},
                {"from": "INC-2026-0891", "to": "THREAT-LAPSUS", "type": "LINKS_TO", "props": {}},
                {"from": "INC-2026-0891", "to": "IND-HASH-MIMI", "type": "LINKS_TO", "props": {}},
                {"from": "THREAT-LAPSUS", "to": "IND-HASH-MIMI", "type": "USED_TOOL", "props": {}},
                {"from": "SYS-DC-01", "to": "THREAT-LAPSUS", "type": "EXPOSED_BY", "props": {}},
                {"from": "USER-FINANCE-DIR", "to": "SYS-WORKSTATION-44", "type": "AUTHORIZED_TO", "props": {}},
                {"from": "USER-FINANCE-DIR", "to": "SYS-DC-01", "type": "AUTHORIZED_TO", "props": {}}
            ]
        }

    @staticmethod
    def get_all_scenarios() -> List[Dict[str, Any]]:
        return [
            SeedData.get_scenario_0447(),
            SeedData.get_scenario_0891()
        ]
