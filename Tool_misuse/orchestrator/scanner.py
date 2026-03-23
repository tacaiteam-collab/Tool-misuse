# orchestrator/scanner.py
import asyncio
import logging
from typing import List, Dict, Optional
from datetime import datetime

from config.settings import settings
from config.safety import SafetyLock
from attacks.registry import AttackRegistry
from executors.factory import ExecutorFactory
from validators.composite_validator import CompositeValidator
from reporters.factory import ReporterFactory
from core.models import ScanSession, Finding
from utils.logger import setup_structured_logging

logger = logging.getLogger(__name__)


class SecurityScanner:
    """Main orchestration engine for multi-vector LLM security testing"""

    def __init__(self, target_url: str, api_key: Optional[str] = None):
        self.target_url = target_url
        self.api_key = api_key
        self.safety = SafetyLock(settings.safety)
        self.session = ScanSession(
            target=target_url,
            started_at=datetime.utcnow(),
            dry_run=settings.safety.dry_run_default
        )

        # Initialize components
        self.attack_registry = AttackRegistry()
        self.executor_factory = ExecutorFactory()
        self.validator = CompositeValidator()
        self.reporter_factory = ReporterFactory()

        setup_structured_logging()

    async def validate_scope(self) -> bool:
        """Pre-scan safety validation"""
        if not self.safety.validate_target(self.target_url):
            logger.error("Target not in allowed scope - scan aborted")
            return False

        if not settings.safety.dry_run_default:
            if not self.safety.confirm_authorization():
                logger.info("Authorization denied by user - scan cancelled")
                return False

        logger.info(f"Scope validated for {self.target_url}")
        return True

    async def discover_target_capabilities(self) -> Dict:
        """Optional: Probe target to identify available tools/endpoints"""
        # This could call an OpenAPI spec endpoint or observe behavior
        # For now, return minimal info
        return {
            "url": self.target_url,
            "detected_tools": [],  # Could be populated via reconnaissance
            "api_schema": None  # Could fetch OpenAPI/Swagger spec
        }

    async def run_scan(self, attack_types: Optional[List[str]] = None) -> ScanSession:
        """Execute the full security scan"""

        # 1. Validate scope
        if not await self.validate_scope():
            return self.session

        # 2. Discover target capabilities
        target_info = await self.discover_target_capabilities()

        # 3. Initialize executor
        executor = self.executor_factory.create(
            executor_type="http",  # Could be websocket, langgraph, etc.
            base_url=self.target_url,
            api_key=self.api_key,
            timeout=settings.scan.timeout_seconds,
            rate_limit=settings.scan.max_requests_per_minute
        )

        # 4. Load and execute attack plugins
        selected_attacks = attack_types or settings.scan.attack_types
        logger.info(f"Executing attacks: {selected_attacks}")

        for attack_name in selected_attacks:
            try:
                attack_plugin = self.attack_registry.load(attack_name)
                logger.info(f"Running attack plugin: {attack_plugin.metadata.name}")

                results = await attack_plugin.execute(executor, target_info)
                self.session.results.extend(results)

                # Real-time validation
                for result in results:
                    if result.vulnerable:
                        finding = Finding.from_test_result(result)
                        self.session.findings.append(finding)
                        logger.warning(f"🚨 Vulnerability found: {finding.id}")

            except Exception as e:
                logger.error(f"Failed to execute attack '{attack_name}': {str(e)}")
                self.session.errors.append({
                    "attack": attack_name,
                    "error": str(e),
                    "timestamp": datetime.utcnow().isoformat()
                })

        # 5. Finalize session
        self.session.completed_at = datetime.utcnow()
        self.session.calculate_summary()

        return self.session

    async def generate_reports(self, formats: Optional[List[str]] = None) -> List[str]:
        """Generate reports in configured formats"""
        output_paths = []
        selected_formats = formats or settings.scan.output_formats

        for fmt in selected_formats:
            try:
                reporter = self.reporter_factory.create(fmt, self.session)
                path = await reporter.generate()
                output_paths.append(path)
                logger.info(f"Generated {fmt} report: {path}")
            except Exception as e:
                logger.error(f"Failed to generate {fmt} report: {str(e)}")

        return output_paths