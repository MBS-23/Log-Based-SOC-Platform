"""
Analytics: Anomaly Detection (ML-Assisted)
-----------------------------------------
TF-IDF + KMeans based anomaly indication for logs.

IMPORTANT:
• Advisory ONLY (no security decisions)
• Deterministic output
• SOC-safe bounds
• EXE-compatible

Used for:
- Analyst triage
- Dashboard indicators
- Correlation enrichment
"""

from typing import List
import logging
import numpy as np

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import KMeans

logger = logging.getLogger("SOC.Anomaly")


class AnomalyDetector:
    """
    ML-assisted anomaly detector for log payloads.

    Methodology:
    - TF-IDF vectorization
    - KMeans clustering
    - Smallest cluster MAY indicate anomalies
    """

    # SOC safety limits
    MAX_LOGS = 1000           # Prevent CPU exhaustion
    MIN_ANOMALY_RATIO = 0.05  # Ignore tiny statistical noise

    def __init__(self, clusters: int = 2):
        """
        Initialize anomaly detector.

        Args:
            clusters (int): Number of clusters (default=2).
        """
        if clusters < 2:
            raise ValueError("clusters must be >= 2")

        self.clusters = clusters

        self.vectorizer = TfidfVectorizer(
            stop_words="english",
            max_features=500,
            lowercase=True
        )

        # ⚠ EXE-safe: avoid n_init="auto"
        self.model = KMeans(
            n_clusters=self.clusters,
            random_state=42,
            n_init=10
        )

    # -------------------------------------------------
    # ANOMALY DETECTION
    # -------------------------------------------------

    def detect(self, log_payloads: List[str]) -> List[int]:
        """
        Identify anomalous log entries.

        Args:
            log_payloads (List[str]): List of log messages / payloads.

        Returns:
            List[int]: Indices of payloads considered anomalous.
        """

        # ---------------- SAFETY CHECKS ----------------

        if not log_payloads or len(log_payloads) < self.clusters:
            return []

        # Hard limit for SOC stability
        if len(log_payloads) > self.MAX_LOGS:
            logger.warning(
                "Anomaly detection input truncated (%d → %d)",
                len(log_payloads),
                self.MAX_LOGS
            )
            log_payloads = log_payloads[:self.MAX_LOGS]

        # Clean payloads (prevent vectorizer crash)
        cleaned = [
            str(p).strip()
            for p in log_payloads
            if isinstance(p, str) and p.strip()
        ]

        if len(cleaned) < self.clusters:
            return []

        try:
            # Vectorize logs
            X = self.vectorizer.fit_transform(cleaned)

            # Cluster logs
            labels = self.model.fit_predict(X)

            # Determine smallest cluster
            unique_labels, counts = np.unique(labels, return_counts=True)
            anomaly_cluster = unique_labels[counts.argmin()]

            anomaly_ratio = counts.min() / len(labels)

            # Ignore statistical noise
            if anomaly_ratio < self.MIN_ANOMALY_RATIO:
                logger.debug(
                    "Anomaly cluster too small (ratio=%.3f), ignored",
                    anomaly_ratio
                )
                return []

            return [
                idx
                for idx, label in enumerate(labels)
                if label == anomaly_cluster
            ]

        except Exception as exc:
            # SOC rule: ML must NEVER break pipeline
            logger.error("Anomaly detection failed: %s", exc)
            return []
