"""
PDF Incident Report Generator (Enterprise SOC Style)
----------------------------------------------------
Thread-safe, EXE-safe, audit-ready.
Supports SINGLE + BATCH incident reporting.
"""

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer,
    Table, TableStyle
)
from reportlab.lib.units import cm
from datetime import datetime
from pathlib import Path
import html
import logging
import threading
from typing import List

from config.settings import PDF_REPORT_DIR
from intelligence.ip_enrichment import enrich_ip


class PDFIncidentReporter:
    """
    Enterprise-grade SOC PDF Incident Reporter
    """

    _lock = threading.Lock()  # 🔒 SOC-safe

    def __init__(self):
        PDF_REPORT_DIR.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger("SOC.PDF")

    # ==================================================
    # SINGLE DETECTION (BACKWARD SAFE)
    # ==================================================

    def generate(self, detection: dict) -> Path:
        """
        Generate ONE PDF for ONE detection.
        """
        if not detection:
            raise ValueError("Detection data is required")

        return self.generate_batch([detection])

    # ==================================================
    # BATCH INCIDENT REPORT (REQUIRED)
    # ==================================================

    def generate_batch(self, detections: List[dict]) -> Path:
        """
        Generate ONE SOC-grade PDF for MULTIPLE detections.
        """

        if not detections:
            raise ValueError("Detections list cannot be empty")

        with self._lock:
            timestamp = datetime.utcnow()
            filename = f"incident_{timestamp.strftime('%Y%m%d_%H%M%S_%f')}.pdf"
            file_path = PDF_REPORT_DIR / filename

            doc = SimpleDocTemplate(
                str(file_path),
                pagesize=A4,
                rightMargin=2 * cm,
                leftMargin=2 * cm,
                topMargin=2 * cm,
                bottomMargin=2 * cm
            )

            styles = getSampleStyleSheet()
            self._register_styles(styles)

            story = []

            # =========================
            # HEADER
            # =========================
            story.append(Paragraph(
                "LOG-BASED SOC PLATFORM<br/><b>SECURITY INCIDENT REPORT</b>",
                styles["Title"]
            ))
            story.append(Spacer(1, 14))

            story.append(Paragraph(
                f"Incident Batch Size: {len(detections)}",
                styles["Normal"]
            ))
            story.append(Spacer(1, 12))

            # =========================
            # INCIDENT SUMMARY TABLE
            # =========================
            summary_data = [[
                "Time", "Severity", "Rule", "Source IP", "IOC"
            ]]

            for d in detections:
                summary_data.append([
                    d.get("time", "N/A"),
                    d.get("severity", "Low"),
                    d.get("rule", "N/A"),
                    d.get("ip", "UNKNOWN"),
                    "YES" if d.get("ioc_hit") else "NO"
                ])

            summary_table = Table(
                summary_data,
                colWidths=[3 * cm, 3 * cm, 5 * cm, 4 * cm, 2 * cm]
            )

            summary_table.setStyle(TableStyle([
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("BACKGROUND", (0, 0), (-1, 0), colors.whitesmoke),
                ("FONT", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("ALIGN", (-1, 1), (-1, -1), "CENTER"),
            ]))

            story.append(Paragraph("Incident Summary", styles["SectionTitle"]))
            story.append(summary_table)
            story.append(Spacer(1, 16))

            # =========================
            # IP ENRICHMENT (FIRST IP)
            # =========================
            primary_ip = detections[0].get("ip", "UNKNOWN")
            enrichment = self._safe_enrich_ip(primary_ip)

            intel_table = Table([
                ["Primary IP", primary_ip],
                ["Private IP", "YES" if enrichment.get("is_private") else "NO"],
                ["Country", enrichment.get("country", "N/A")],
                ["Region", enrichment.get("region", "N/A")],
                ["City", enrichment.get("city", "N/A")],
                ["Organization", enrichment.get("org", "N/A")],
                ["ASN", enrichment.get("asn", "N/A")],
                ["Source", enrichment.get("source", "N/A")],
            ], colWidths=[5 * cm, 10 * cm])

            intel_table.setStyle(TableStyle([
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONT", (0, 0), (0, -1), "Helvetica-Bold"),
            ]))

            story.append(Paragraph("IP Intelligence & Enrichment", styles["SectionTitle"]))
            story.append(intel_table)
            story.append(Spacer(1, 16))

            # =========================
            # RAW LOG EVIDENCE (LIMITED)
            # =========================
            story.append(Paragraph("Evidence Samples", styles["SectionTitle"]))

            for d in detections[:5]:  # 🔒 Limit to prevent bloated PDFs
                raw_log = html.escape(str(d.get("raw", "N/A")))
                story.append(Paragraph(raw_log, styles["CodeBlock"]))
                story.append(Spacer(1, 8))

            # =========================
            # FOOTER
            # =========================
            story.append(Spacer(1, 20))
            story.append(Paragraph(
                f"Generated by Log-Based SOC Platform | UTC {timestamp.isoformat()}",
                styles["Footer"]
            ))

            doc.build(story)

            self.logger.info("PDF incident report generated: %s", file_path.name)
            return file_path

    # ==================================================
    # INTERNAL HELPERS
    # ==================================================

    def _register_styles(self, styles):
        if "SectionTitle" not in styles:
            styles.add(ParagraphStyle(
                name="SectionTitle",
                fontSize=13,
                spaceAfter=8,
                fontName="Helvetica-Bold"
            ))

        if "CodeBlock" not in styles:
            styles.add(ParagraphStyle(
                name="CodeBlock",
                fontSize=9,
                fontName="Courier",
                backColor=colors.whitesmoke,
                leading=12,
                leftIndent=6,
                rightIndent=6,
                spaceBefore=6,
                spaceAfter=6
            ))

        if "Footer" not in styles:
            styles.add(ParagraphStyle(
                name="Footer",
                fontSize=8,
                textColor=colors.grey
            ))

    def _safe_enrich_ip(self, ip: str) -> dict:
        try:
            return enrich_ip(ip) or {}
        except Exception as exc:
            self.logger.warning("IP enrichment failed: %s", exc)
            return {}
