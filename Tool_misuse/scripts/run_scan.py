"""
LLM Security Validator - Production CLI
Usage: python -m scripts.run_scan --url https://app.example.com/api
"""

import sys
import asyncio
import argparse
import logging
from pathlib import Path

from config.settings import settings, Settings
from orchestrator.scanner import SecurityScanner
from utils.logger import setup_cli_logging

logger = logging.getLogger(__name__)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Production LLM Security Validator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Dry run against localhost (safe)
  python -m scripts.run_scan --url http://localhost:8000/api

  # Live scan with specific attacks (requires authorization)
  python -m scripts.run_scan --url https://staging.example.com/api \\
    --live \\
    --attacks prompt_injection,parameter_manipulation \\
    --reports json,sarif

  # Full scan with all configured outputs
  python -m scripts.run_scan --url https://app.example.com/api \\
    --live \\
    --api-key $API_KEY \\
    --timeout 60 \\
    --rate-limit 30 \\
    --reports console,json,html,webhook
        """
    )

    parser.add_argument(
        "--url", "-u",
        required=True,
        help="Target API endpoint URL"
    )
    parser.add_argument(
        "--api-key", "-k",
        default=None,
        help="API key for authentication (optional)"
    )
    parser.add_argument(
        "--live", "-l",
        action="store_true",
        help="Enable live mode (sends real requests). Requires authorization."
    )
    parser.add_argument(
        "--attacks", "-a",
        default=None,
        help="Comma-separated list of attack types to run. Default: from config"
    )
    parser.add_argument(
        "--reports", "-r",
        default=None,
        help="Comma-separated list of report formats. Default: from config"
    )
    parser.add_argument(
        "--timeout", "-t",
        type=int,
        default=None,
        help="Request timeout in seconds (5-300)"
    )
    parser.add_argument(
        "--rate-limit", "-rl",
        type=int,
        default=None,
        help="Max requests per minute (1-600)"
    )
    parser.add_argument(
        "--output-dir", "-o",
        type=Path,
        default=Path("./reports"),
        help="Directory for output reports"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging"
    )

    return parser.parse_args()


async def main():
    args = parse_args()

    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    setup_cli_logging(level=log_level)

    # Override settings with CLI args
    if args.live:
        settings.safety.dry_run_default = False
    if args.timeout:
        settings.scan.timeout_seconds = args.timeout
    if args.rate_limit:
        settings.scan.max_requests_per_minute = args.rate_limit
    if args.attacks:
        settings.scan.attack_types = [a.strip() for a in args.attacks.split(",")]
    if args.reports:
        settings.scan.output_formats = [r.strip() for a in args.reports.split(",")]

    # Update scan config
    settings.scan.target_url = args.url
    settings.scan.api_key = args.api_key

    logger.info(f"Starting LLM Security Validator v1.0")
    logger.info(f"Target: {args.url}")
    logger.info(f"Mode: {'LIVE' if not settings.safety.dry_run_default else 'DRY RUN'}")

    try:
        # Initialize and run scanner
        scanner = SecurityScanner(
            target_url=args.url,
            api_key=args.api_key
        )

        # Execute scan
        session = await scanner.run_scan()

        # Generate reports
        if args.output_dir:
            args.output_dir.mkdir(parents=True, exist_ok=True)
            report_paths = await scanner.generate_reports()

            print("\n SCAN COMPLETE")
            print(f"   Total Tests: {session.summary.total_tests}")
            print(f"   Vulnerabilities: {session.summary.vulnerabilities_found}")
            print(f"   Success Rate: {session.summary.success_rate:.1%}")
            print(f"   Reports: {', '.join(report_paths)}")

            # Exit code based on findings
            if session.summary.vulnerabilities_found > 0:
                logger.warning(" Vulnerabilities detected - review reports")
                sys.exit(1)
            else:
                logger.info(" No vulnerabilities detected")
                sys.exit(0)
        else:
            # Just print summary to console
            print(f"\n Results: {session.summary.vulnerabilities_found} vulnerabilities found")
            sys.exit(0 if session.summary.vulnerabilities_found == 0 else 1)

    except KeyboardInterrupt:
        logger.warning("\n Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.exception(f" Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())