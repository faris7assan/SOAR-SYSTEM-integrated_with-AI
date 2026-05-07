"""
AegisNDR - Main Orchestration Engine
Ties all modules together into a single running pipeline.
"""
import logging
import queue
import threading
import time
import signal
import sys
import os

import config
from core.capture import PacketCapture
from core.flow_generator import FlowGenerator
from core.feature_engine import FeatureEngine
from core.detection.rule_engine import RuleEngine
from core.detection.signature_engine import SignatureEngine
from core.detection.ml_engine import MLEngine
from correlation.engine import CorrelationEngine
from scoring.threat_scorer import ThreatScorer
from response.soar import ResponseEngine
from storage.store import AlertStore, FlowStore
from intelligence.threat_intel import ThreatIntelligence
from plugins.loader import PluginManager

logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
    ]
)
logger = logging.getLogger("aegis.engine")


class AegisNDR:
    """
    Central orchestrator.

    Pipeline:
      PacketCapture → FlowGenerator → FeatureEngine
        → [RuleEngine, SignatureEngine, MLEngine, Plugins]
        → CorrelationEngine → ThreatScorer
        → ResponseEngine → Storage
    """

    def __init__(
        self,
        interface:   str  = config.CAPTURE_INTERFACE,
        mock_mode:   bool = True,
        api_enabled: bool = True,
    ):
        self.interface   = interface
        self.mock_mode   = mock_mode
        self.api_enabled = api_enabled
        self._running    = False

        # ── Queues ────────────────────────────────────────────────────
        self.packet_queue: queue.Queue = queue.Queue(maxsize=200_000)

        # ── Core Pipeline ─────────────────────────────────────────────
        self.capture = PacketCapture(
            interface=interface,
            bpf_filter=config.CAPTURE_FILTER,
            packet_queue=self.packet_queue,
            mock_mode=mock_mode,
        )
        self.flow_gen = FlowGenerator(
            packet_queue=self.packet_queue,
            flow_callback=self._on_flow,
            active_timeout=config.FLOW_TIMEOUT_ACTIVE,
            idle_timeout=config.FLOW_TIMEOUT_IDLE,
        )
        self.feature_engine = FeatureEngine()

        # ── Detection Engines ─────────────────────────────────────────
        self.rule_engine  = RuleEngine()
        self.sig_engine   = SignatureEngine()
        self.ml_engine    = MLEngine()
        self.plugin_mgr   = PluginManager(
            plugins_dir=os.path.join(os.path.dirname(__file__), "plugins")
        )

        # ── Intelligence & Correlation ────────────────────────────────
        self.threat_intel   = ThreatIntelligence()
        self.correlator     = CorrelationEngine()
        self.threat_scorer  = ThreatScorer()

        # ── Response & Storage ────────────────────────────────────────
        self.response_eng = ResponseEngine(enabled=config.RESPONSE_ENABLED)
        self.alert_store  = AlertStore()
        self.flow_store   = FlowStore()

        # ── Metrics ───────────────────────────────────────────────────
        self._metrics = {
            "flows_processed":   0,
            "alerts_generated":  0,
            "chains_detected":   0,
            "packets_captured":  0,
            "start_time":        0.0,
        }

        # ── Worker threads ────────────────────────────────────────────
        self._flow_thread: threading.Thread = None

        logger.info("AegisNDR engine initialized")

    # ── Lifecycle ────────────────────────────────────────────────────────────
    def start(self):
        self._running = True
        self._metrics["start_time"] = time.time()

        # Register signal handlers (only if in main thread)
        if threading.current_thread() is threading.main_thread():
            signal.signal(signal.SIGINT,  self._handle_signal)
            signal.signal(signal.SIGTERM, self._handle_signal)
        else:
            logger.debug("Running in non-main thread; skipping signal handler registration.")

        # Init API bindings
        if self.api_enabled:
            self._init_api()

        # Start pipeline
        self.flow_gen.start()

        self._flow_thread = threading.Thread(
            target=self.flow_gen.run_forever,
            daemon=True, name="flow-gen",
        )
        self._flow_thread.start()

        self.capture.start()

        logger.info(
            f"AegisNDR started | interface={self.interface} "
            f"| mock={self.mock_mode} | response={config.RESPONSE_ENABLED}"
        )
        logger.info("Dashboard: http://localhost:8080")
        logger.info("API docs:  http://localhost:8000/docs")

    def stop(self):
        logger.info("Stopping AegisNDR...")
        self._running = False
        self.capture.stop()
        self.flow_gen.stop()
        logger.info("AegisNDR stopped cleanly.")

    def run_forever(self):
        self.start()
        try:
            while self._running:
                self._print_status()
                time.sleep(30)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    # ── Core Pipeline Callback ────────────────────────────────────────────────
    def _on_flow(self, flow):
        """
        Called by FlowGenerator for every completed/expired flow.
        This is the heart of the detection pipeline.
        """
        try:
            # 1. Feature Extraction
            FeatureEngine.extract(flow)

            # 2. Store flow
            self.flow_store.insert(flow)
            self._metrics["flows_processed"] += 1

            # 3. Detection (all engines in parallel)
            all_alerts = []
            all_alerts.extend(self.rule_engine.analyze(flow))
            all_alerts.extend(self.sig_engine.analyze(flow))
            all_alerts.extend(self.ml_engine.analyze(flow))
            all_alerts.extend(self.plugin_mgr.analyze(flow))

            if not all_alerts:
                return

            # 4. Threat Intel enrichment + Scoring
            ti_score = self.threat_intel.reputation_score(flow.src_ip)

            for alert in all_alerts:
                # Check for active attack chain (bonus score)
                chain = self.correlator.ingest(alert)
                chain_bonus = 15.0 if chain else 0.0
                if chain:
                    self._metrics["chains_detected"] += 1

                # Composite scoring
                self.threat_scorer.score_alert(alert, ti_score, chain_bonus)

                # Store
                self.alert_store.insert(alert)
                self._metrics["alerts_generated"] += 1

                # Response playbook
                self.response_eng.handle_alert(alert)

                # Log notable alerts
                if alert.score >= config.SCORE_ALERT_THRESHOLD:
                    logger.warning(
                        f"ALERT [{alert.severity.value}] {alert.alert_type.value} "
                        f"| {alert.src_ip} -> {alert.dst_ip}:{alert.dst_port} "
                        f"| score={alert.score:.0f} | {alert.description[:60]}"
                    )

        except Exception as e:
            logger.error(f"Pipeline error on flow {flow.flow_id}: {e}", exc_info=True)

    # ── API Init ──────────────────────────────────────────────────────────────
    def _init_api(self):
        try:
            from api.app import init_api, set_correlation_engine, update_engine_stats, app
            init_api(
                alert_store=self.alert_store,
                flow_store=self.flow_store,
                threat_scorer=self.threat_scorer,
                response_eng=self.response_eng,
                threat_intel=self.threat_intel,
            )
            set_correlation_engine(self.correlator)

            def _run_api():
                import uvicorn
                uvicorn.run(app, host=config.API_HOST, port=config.API_PORT,
                            log_level="warning")

            threading.Thread(target=_run_api, daemon=True, name="api").start()
            logger.info(f"API started on {config.API_HOST}:{config.API_PORT}")

        except ImportError as e:
            logger.warning(f"API not started (missing deps): {e}")

    # ── Status ────────────────────────────────────────────────────────────────
    def _print_status(self):
        uptime = time.time() - self._metrics["start_time"]
        cap    = self.capture.stats
        fp     = self._metrics["flows_processed"]
        ag     = self._metrics["alerts_generated"]
        cd     = self._metrics["chains_detected"]
        thr    = self.threat_scorer.top_threats(3)

        logger.info(
            f"📈 STATUS | uptime={uptime:.0f}s | "
            f"pkts={cap['captured']} | flows={fp} | "
            f"alerts={ag} | chains={cd}"
        )
        if thr:
            top = thr[0]
            logger.info(
                f"🔴 TOP THREAT: {top['ip']} score={top['score']} "
                f"({top['alert_count']} alerts, last: {top['last_type']})"
            )

    def _handle_signal(self, sig, frame):
        logger.info(f"Signal {sig} received — shutting down")
        self.stop()
        sys.exit(0)

    # ── Public accessors ──────────────────────────────────────────────────────
    @property
    def metrics(self): return dict(self._metrics)
