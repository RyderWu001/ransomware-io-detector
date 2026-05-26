"""
端到端整合入口：啟動監控 → 特徵工程 → 威脅分析 → 自動阻斷
"""

import os
import time
import argparse
import logging
from collections import defaultdict

from detector.monitor import FileSystemMonitor
from detector.entropy import EntropyAnalyzer, FeatureVector
from detector.analyzer import ThreatAnalyzer
from detector.blocker import respond_to_threat

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)


def run_detector(watch_dir: str, poll_interval: float, use_llm: bool, forensic_mode: bool):
    monitor = FileSystemMonitor(watch_dir)
    entropy_analyzer = EntropyAnalyzer(window_seconds=5.0)
    threat_analyzer = ThreatAnalyzer(use_llm=use_llm)

    # pid -> list of FeatureVector（供 LLM 彙整行為歷史）
    pid_histories: dict[int, list[FeatureVector]] = defaultdict(list)
    blocked_pids: set[int] = set()

    monitor.start()
    logger.info(f"偵測系統啟動 | 監控目錄: {watch_dir} | LLM: {use_llm}")

    try:
        while True:
            time.sleep(poll_interval)
            events = monitor.drain_events()
            if not events:
                continue

            feature_vectors = entropy_analyzer.process_batch(events)
            for fv in feature_vectors:
                pid = fv.pid or 0
                pid_histories[pid].append(fv)

                alert = threat_analyzer.analyze(fv, pid_histories[pid])
                if alert is None:
                    continue

                logger.warning("=" * 60)
                logger.warning(f"[THREAT DETECTED] {alert.feature_summary}")
                logger.warning(f"觸發原因: {alert.trigger_reason}")

                if alert.llm_report:
                    logger.warning(f"\n--- Claude 威脅報告 ---\n{alert.llm_report}\n")

                if pid not in blocked_pids and pid != 0:
                    result = respond_to_threat(pid, forensic_mode=forensic_mode)
                    blocked_pids.add(pid)
                    logger.warning(
                        f"[ACTION] {result['action'].upper()} PID={pid} | "
                        f"成功: {result['success']}"
                    )

    except KeyboardInterrupt:
        monitor.stop()
        logger.info("偵測系統已停止。")
        alerts = threat_analyzer.get_alerts()
        logger.info(f"本次共偵測到 {len(alerts)} 個威脅告警。")


def main():
    parser = argparse.ArgumentParser(description="Ransomware I/O Detector")
    parser.add_argument("--dir", default="~/honeypot_dir", help="監控目錄")
    parser.add_argument("--interval", type=float, default=2.0, help="輪詢間隔（秒）")
    parser.add_argument("--no-llm", action="store_true", help="停用 LLM 分析")
    parser.add_argument("--kill", action="store_true", help="改用 SIGKILL 而非 cgroup freeze")
    args = parser.parse_args()

    run_detector(
        watch_dir=args.dir,
        poll_interval=args.interval,
        use_llm=not args.no_llm,
        forensic_mode=not args.kill,
    )


if __name__ == "__main__":
    main()
