# attacks/base.py
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from core.models import AttackPayload, TestResult, RiskLevel
from core.enums import AttackType, ToolType


@dataclass
class AttackPluginMetadata:
    """Metadata for plugin registration"""
    name: str
    version: str
    description: str
    attack_type: AttackType
    supported_tools: List[ToolType]
    risk_level: RiskLevel
    author: str


class AttackPlugin(ABC):
    """Abstract base class for all attack plugins"""

    metadata: AttackPluginMetadata

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.results: List[TestResult] = []

    @abstractmethod
    def generate_payloads(self, target_info: Dict) -> List[AttackPayload]:
        """Generate adversarial payloads for the target"""
        pass

    @abstractmethod
    def evaluate_response(self, payload: AttackPayload, response: Dict) -> TestResult:
        """Determine if payload triggered a vulnerability"""
        pass

    async def execute(self, executor, target_info: Dict) -> List[TestResult]:
        """Full execution pipeline for this attack type"""
        payloads = self.generate_payloads(target_info)
        results = []

        for payload in payloads:
            try:
                # Execute via provided executor
                response = await executor.send_request(payload)

                # Evaluate result
                result = self.evaluate_response(payload, response)
                results.append(result)

            except Exception as e:
                results.append(TestResult(
                    payload_id=payload.id,
                    success=False,
                    vulnerable=False,
                    error=str(e),
                    risk_level=self.metadata.risk_level
                ))

        self.results = results
        return results

    def get_summary(self) -> Dict:
        """Generate plugin-level summary"""
        total = len(self.results)
        vulnerable = sum(1 for r in self.results if r.vulnerable)
        return {
            "plugin": self.metadata.name,
            "version": self.metadata.version,
            "total_tests": total,
            "vulnerabilities_found": vulnerable,
            "success_rate": (total - vulnerable) / total if total > 0 else 1.0
        }