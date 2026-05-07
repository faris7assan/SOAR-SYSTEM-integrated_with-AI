"""
AegisNDR - Entry Point
"""
import argparse
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))


def main():
    parser = argparse.ArgumentParser(
        description="AegisNDR - Intelligent Network Detection & Response",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run in mock/demo mode (no root required):
  python main.py --mock

  # Run live capture on eth0:
  sudo python main.py --interface eth0

  # Run with attack simulation:
  python main.py --mock --simulate

  # Run with auto-blocking enabled:
  sudo python main.py --interface eth0 --response

  # API only (no capture):
  python main.py --api-only

  # GUI mode:
  python main.py --gui
        """
    )
    parser.add_argument("--interface", "-i", default="eth0",
                        help="Network interface to capture on (default: eth0)")
    parser.add_argument("--mock", action="store_true",
                        help="Run with mock traffic generator (no root needed)")
    parser.add_argument("--simulate", action="store_true",
                        help="Inject attack simulation traffic")
    parser.add_argument("--response", action="store_true",
                        help="Enable automated response (iptables blocking)")
    parser.add_argument("--api-only", action="store_true",
                        help="Start API server only (no capture)")
    parser.add_argument("--gui", action="store_true",
                        help="Start GUI application")
    parser.add_argument("--train", action="store_true",
                        help="Force ML model training and exit")
    parser.add_argument("--no-api", action="store_true",
                        help="Disable API server")
    parser.add_argument("--log-level", default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                        help="Logging level")

    args = parser.parse_args()

    # Handle GUI mode (Default if no major flags provided)
    if args.gui or (not args.api_only and not args.mock and not args.interface and not args.train):
        from gui.app import run_gui
        run_gui()
        return

    # Override config from CLI
    import config
    config.LOG_LEVEL = args.log_level
    if args.response:
        config.RESPONSE_ENABLED = True

    # ── API-only mode ──────────────────────────────────────────────────
    if args.api_only:
        print("🛡️  AegisNDR - API Server Mode")
        from storage.store import AlertStore, FlowStore
        from scoring.threat_scorer import ThreatScorer
        from response.soar import ResponseEngine
        from intelligence.threat_intel import ThreatIntelligence
        from correlation.engine import CorrelationEngine
        from api.app import init_api, set_correlation_engine, app

        alert_store  = AlertStore()
        flow_store   = FlowStore()
        scorer       = ThreatScorer()
        response_eng = ResponseEngine(enabled=False)
        ti           = ThreatIntelligence()
        correlator   = CorrelationEngine()

        init_api(alert_store, flow_store, scorer, response_eng, ti)
        set_correlation_engine(correlator)

        import uvicorn
        print(f"📡 API docs: http://localhost:{config.API_PORT}/docs")
        uvicorn.run(app, host=config.API_HOST, port=config.API_PORT)
        return

    # ── Full engine ────────────────────────────────────────────────────
    from engine import AegisNDR

    print("=" * 60)
    print("      AegisNDR v1.0 - Starting Desktop App...")
    print("=" * 60)

    ndr = AegisNDR(
        interface=args.interface,
        mock_mode=args.mock or not args.interface,
        api_enabled=not args.no_api,
    )

    # ── Force train ────────────────────────────────────────────────────
    if args.train:
        print("Training ML model...")
        ndr.ml_engine.force_train()
        print("Done.")
        return

    ndr.start()

    # ── Attack simulation ──────────────────────────────────────────────
    if args.simulate:
        import time
        from simulation.attacker import AttackSimulator
        print("\nStarting attack simulation in 3 seconds...")
        time.sleep(3)
        sim = AttackSimulator(ndr.packet_queue)
        sim.start()
        sim.run_all(delay_between=8.0)
        print("⚔️  Attack simulation running in background\n")

    # ── Block until stopped ────────────────────────────────────────────
    try:
        import time
        while ndr._running:
            time.sleep(1)
    except KeyboardInterrupt:
        ndr.stop()


if __name__ == "__main__":
    main()
