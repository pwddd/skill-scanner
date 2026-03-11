# Copyright 2026 Cisco Systems, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0
"""
ZIP Virus Analyzer for scanning complete ZIP packages using VirusTotal.

This analyzer scans the entire ZIP package file (not individual files within it)
against VirusTotal's database using SHA256 hash lookups. It is designed to detect
malicious ZIP packages before they are extracted.
"""

import logging
from pathlib import Path

from ..models import Finding, Severity, Skill, ThreatCategory
from .virustotal_analyzer import VirusTotalAnalyzer

logger = logging.getLogger(__name__)


class ZipVirusAnalyzer(VirusTotalAnalyzer):
    """
    Analyzer that checks ZIP package files against VirusTotal using hash lookups.

    This analyzer extends VirusTotalAnalyzer to scan complete ZIP files,
    complementing the parent class which scans individual binary files.
    """

    # ZIP and archive file extensions to scan
    ZIP_EXTENSIONS = {
        ".zip",
        ".tar",
        ".gz",
        ".tgz",
        ".tar.gz",
        ".bz2",
        ".7z",
        ".rar",
    }

    def __init__(self, api_key: str | None = None, enabled: bool = True, upload_files: bool = False):
        """
        Initialize ZIP Virus analyzer.

        Args:
            api_key: VirusTotal API key (optional, can be set via environment)
            enabled: Whether the analyzer is enabled (default: True)
            upload_files: If True, upload ZIP files to VT for scanning. If False (default),
                         only check existing hashes (more privacy-friendly)
        """
        # Initialize parent class
        super().__init__(api_key=api_key, enabled=enabled, upload_files=upload_files)
        # Override the analyzer name
        self.name = "zip_virus_analyzer"
        
        if self.api_key:
            logger.info("ZIP Virus Analyzer: VirusTotal API key configured")
        else:
            logger.warning("ZIP Virus Analyzer initialized without API key")

    def analyze(self, skill: Skill) -> list[Finding]:
        """
        Analyze ZIP files in the skill using VirusTotal hash lookups.

        Args:
            skill: The skill to analyze

        Returns:
            List of findings for malicious ZIP files
        """
        if not self.enabled:
            return []

        findings = []

        # Find all ZIP/archive files in the skill
        zip_files = [
            f for f in skill.files 
            if any(f.relative_path.lower().endswith(ext) for ext in self.ZIP_EXTENSIONS)
        ]

        if not zip_files:
            logger.debug("No ZIP files found in skill package")
            return findings

        for skill_file in zip_files:
            try:
                file_path = Path(skill.directory) / skill_file.relative_path
                
                if not file_path.exists():
                    logger.warning("ZIP file not found: %s", skill_file.relative_path)
                    continue

                # Reuse parent class methods for hash calculation and VT query
                file_hash = self._calculate_sha256(file_path)
                file_size = file_path.stat().st_size

                logger.info("Checking ZIP file: %s (SHA256: %s, Size: %d bytes)", 
                           skill_file.relative_path, file_hash, file_size)

                # Reuse parent class VT query method
                vt_result, hash_found = self._query_virustotal(file_hash)

                if hash_found and vt_result is not None:
                    total = vt_result.get("total_engines", 0)
                    malicious = vt_result.get("malicious", 0)
                    suspicious = vt_result.get("suspicious", 0)

                    if malicious > 0 or suspicious > 0:
                        logger.warning(
                            "ZIP file flagged by VT: %d malicious, %d suspicious out of %d vendors",
                            malicious,
                            suspicious,
                            total,
                        )
                        findings.append(
                            self._create_zip_finding(
                                skill_file=skill_file,
                                file_hash=file_hash,
                                file_size=file_size,
                                vt_result=vt_result,
                                is_clean=False
                            )
                        )
                    else:
                        logger.info("ZIP file appears safe: %d/%d vendors flagged", malicious, total)
                        # Create INFO level finding for clean files
                        findings.append(
                            self._create_zip_finding(
                                skill_file=skill_file,
                                file_hash=file_hash,
                                file_size=file_size,
                                vt_result=vt_result,
                                is_clean=True
                            )
                        )

                    if vt_result.get("permalink"):
                        logger.info("VirusTotal Report: %s", vt_result["permalink"])

                elif self.upload_files:
                    logger.warning("ZIP hash not found in VT database - uploading for analysis")
                    # Reuse parent class upload method
                    vt_result = self._upload_and_scan(file_path, file_hash)

                    if vt_result and vt_result.get("malicious", 0) > 0:
                        findings.append(
                            self._create_zip_finding(
                                skill_file=skill_file,
                                file_hash=file_hash,
                                file_size=file_size,
                                vt_result=vt_result,
                                is_clean=False
                            )
                        )
                    elif vt_result:
                        # Create INFO level finding for clean uploaded files
                        findings.append(
                            self._create_zip_finding(
                                skill_file=skill_file,
                                file_hash=file_hash,
                                file_size=file_size,
                                vt_result=vt_result,
                                is_clean=True
                            )
                        )
                else:
                    logger.info("ZIP hash not found in VT database - upload disabled, cannot scan unknown file")

            except Exception as e:
                logger.warning("ZIP virus scan failed for %s: %s", skill_file.relative_path, e)
                continue

        return findings

    def _create_zip_finding(self, skill_file, file_hash: str, file_size: int, vt_result: dict, is_clean: bool = False) -> Finding:
        """
        Create a finding for a ZIP file scan result.

        Args:
            skill_file: The SkillFile object
            file_hash: SHA256 hash of the ZIP file
            file_size: Size of the ZIP file in bytes
            vt_result: VirusTotal scan results
            is_clean: If True, create an INFO level finding for clean files

        Returns:
            Finding object
        """
        malicious_count = vt_result.get("malicious", 0)
        suspicious_count = vt_result.get("suspicious", 0)
        total_engines = vt_result.get("total_engines", 0)
        vt_url = f"https://www.virustotal.com/gui/file/{file_hash}"

        # Format file size for display
        if file_size < 1024:
            size_str = f"{file_size} bytes"
        elif file_size < 1024 * 1024:
            size_str = f"{file_size / 1024:.1f} KB"
        else:
            size_str = f"{file_size / (1024 * 1024):.1f} MB"

        if is_clean:
            # Create INFO level finding for clean files
            return Finding(
                id=f"ZIP_VT_CLEAN_{file_hash[:8]}",
                rule_id="ZIP_VIRUSTOTAL_CLEAN",
                category=ThreatCategory.POLICY_VIOLATION,  # Using policy_violation for informational findings
                severity=Severity.INFO,
                title=f"ZIP package scanned - No threats detected: {skill_file.relative_path}",
                description=(
                    f"VirusTotal scan completed for this ZIP package. "
                    f"0/{total_engines} security vendors flagged this file as malicious. "
                    f"File size: {size_str}. SHA256: {file_hash}. "
                    f"View full report: {vt_url}"
                ),
                file_path=skill_file.relative_path,
                line_number=None,
                snippet=f"ZIP package hash: {file_hash}",
                remediation="No action required. This ZIP package appears to be clean.",
                analyzer="zip_virus",
                metadata={
                    "confidence": 0.95,
                    "references": [vt_url],
                    "file_hash": file_hash,
                    "file_size": file_size,
                    "malicious_count": 0,
                    "suspicious_count": 0,
                    "total_engines": total_engines,
                    "detection_ratio": 0.0,
                    "virustotal_url": vt_url,
                },
            )

        # Determine severity based on detection ratio (for malicious files)
        if total_engines > 0:
            detection_ratio = malicious_count / total_engines
            if detection_ratio >= 0.3:  # 30%+ detection rate
                severity = Severity.CRITICAL
            elif detection_ratio >= 0.1:  # 10-30% detection rate
                severity = Severity.HIGH
            elif suspicious_count > 0:  # Has suspicious flags
                severity = Severity.MEDIUM
            else:
                severity = Severity.LOW
        else:
            severity = Severity.MEDIUM

        return Finding(
            id=f"ZIP_VT_{file_hash[:8]}",
            rule_id="ZIP_VIRUSTOTAL_MALICIOUS",
            category=ThreatCategory.MALWARE,
            severity=severity,
            title=f"Malicious ZIP package detected: {skill_file.relative_path}",
            description=(
                f"VirusTotal detected this ZIP package as potentially malicious. "
                f"{malicious_count}/{total_engines} security vendors flagged this file as malicious"
                + (f", and {suspicious_count} flagged it as suspicious" if suspicious_count > 0 else "")
                + f". File size: {size_str}. SHA256: {file_hash}. "
                f"View full report: {vt_url}"
            ),
            file_path=skill_file.relative_path,
            line_number=None,
            snippet=f"ZIP package hash: {file_hash}",
            remediation=(
                "Remove this ZIP file from the skill package or verify its contents. "
                "ZIP packages flagged by multiple antivirus engines may contain malware or malicious scripts. "
                f"Review the VirusTotal report for detailed detection information: {vt_url}"
            ),
            analyzer="zip_virus",
            metadata={
                "confidence": 0.95 if malicious_count >= 5 else 0.85,
                "references": [vt_url],
                "file_hash": file_hash,
                "file_size": file_size,
                "malicious_count": malicious_count,
                "suspicious_count": suspicious_count,
                "total_engines": total_engines,
                "detection_ratio": round(malicious_count / total_engines, 3) if total_engines > 0 else 0,
                "virustotal_url": vt_url,
            },
        )

