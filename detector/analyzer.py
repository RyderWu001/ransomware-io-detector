"""
Phase 3: Time Series Analysis & LLM Intent Parsing
第一層：閾值規則 + Isolation Forest 異常偵測
第二層：Claude API 產出威脅鑑識報告
"""

import os
import time
import numpy as np
import anthropic
from dataclasses import dataclass
from collections import defaultdict
from sklearn.ensemble import IsolationForest

from detector.entropy import FeatureVector


# --- 第一層閾值（可調整）---
ALERT_IO_FREQ = 50        # 5 秒內超過 50 次寫入
ALERT_ENTROPY  = 7.5      # 平均熵值超過 7.5
ALERT_DELTA    = 2.0      # 單次熵值跳升超過 2.0


@dataclass
class ThreatAlert:
    timestamp: float
    pid: int | None
    process_name: str | None
    trigger_reason: str
    feature_summary: str
    llm_report: str | None = None


class ThreatAnalyzer:
    def __init__(self, use_llm: bool = True, api_key: str | None = None):
        self.use_llm = use_llm
        self._client = anthropic.Anthropic(api_key=api_key or os.environ.get("ANTHROPIC_API_KEY"))
        # 每個 PID 的特徵歷史，供 Isolation Forest 訓練
        self._history: dict[int, list[list[float]]] = defaultdict(list)
        self._models: dict[int, IsolationForest] = {}
        self._alerts: list[ThreatAlert] = []

    # ------------------------------------------------------------------
    # 第一層：規則 + Isolation Forest
    # ------------------------------------------------------------------

    def _rule_check(self, fv: FeatureVector) -> str | None:
        """回傳觸發原因字串，未觸發則回傳 None。"""
        if fv.io_freq >= ALERT_IO_FREQ:
            return f"io_freq={fv.io_freq} >= {ALERT_IO_FREQ}"
        if fv.file_entropy >= ALERT_ENTROPY:
            return f"file_entropy={fv.file_entropy} >= {ALERT_ENTROPY}"
        if fv.entropy_delta >= ALERT_DELTA:
            return f"entropy_delta={fv.entropy_delta} >= {ALERT_DELTA}"
        return None

    def _iforest_check(self, pid: int, features: list[float]) -> bool:
        """
        用 Isolation Forest 判斷是否為異常點。
        至少累積 20 筆資料才開始訓練模型。
        """
        history = self._history[pid]
        history.append(features)
        if len(history) < 20:
            return False
        # 每 20 筆重新訓練一次
        if len(history) % 20 == 0:
            X = np.array(history)
            self._models[pid] = IsolationForest(contamination=0.05, random_state=42)
            self._models[pid].fit(X)
        model = self._models.get(pid)
        if model is None:
            return False
        pred = model.predict([features])
        return pred[0] == -1  # -1 表示異常

    # ------------------------------------------------------------------
    # 第二層：Claude API 鑑識報告
    # ------------------------------------------------------------------

    def _build_prompt(self, pid: int | None, pname: str | None,
                      history: list[FeatureVector]) -> str:
        lines = []
        for fv in history[-10:]:  # 最近 10 筆
            lines.append(
                f"  t={fv.timestamp:.2f}  io_freq={fv.io_freq}"
                f"  entropy={fv.file_entropy}  delta={fv.entropy_delta}"
                f"  file={fv.path}"
            )
        behavior = "\n".join(lines)
        return (
            f"你是一位資安鑑識分析師。以下是程序 PID={pid}（{pname or 'unknown'}）"
            f"最近的檔案 I/O 行為紀錄：\n\n{behavior}\n\n"
            "請根據以上行為，判斷是否符合勒索軟體的行為模式，"
            "並輸出一份簡短的威脅分析報告（繁體中文，不超過 200 字）。"
            "報告需包含：威脅等級（低/中/高/嚴重）、行為摘要、建議處置。"
        )

    def _call_llm(self, pid: int | None, pname: str | None,
                  history: list[FeatureVector]) -> str:
        prompt = self._build_prompt(pid, pname, history)
        response = self._client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=512,
            system="你是專業的端點資安分析師，擅長辨識勒索軟體與惡意行為模式。",
            messages=[{"role": "user", "content": prompt}],
        )
        return response.content[0].text

    # ------------------------------------------------------------------
    # 主要分析入口
    # ------------------------------------------------------------------

    def analyze(self, fv: FeatureVector,
                pid_history: list[FeatureVector]) -> ThreatAlert | None:
        pid = fv.pid or 0
        features = [fv.io_freq, fv.file_entropy, fv.entropy_delta]

        reason = self._rule_check(fv)
        is_anomaly = self._iforest_check(pid, features)

        if reason is None and not is_anomaly:
            return None

        trigger = reason or "IsolationForest anomaly"
        summary = (
            f"PID={fv.pid} ({fv.process_name or 'unknown'}) | "
            f"io_freq={fv.io_freq} | entropy={fv.file_entropy} | "
            f"delta={fv.entropy_delta}"
        )

        llm_report = None
        if self.use_llm:
            try:
                llm_report = self._call_llm(fv.pid, fv.process_name, pid_history)
            except Exception as e:
                llm_report = f"[LLM 呼叫失敗: {e}]"

        alert = ThreatAlert(
            timestamp=fv.timestamp,
            pid=fv.pid,
            process_name=fv.process_name,
            trigger_reason=trigger,
            feature_summary=summary,
            llm_report=llm_report,
        )
        self._alerts.append(alert)
        return alert

    def get_alerts(self) -> list[ThreatAlert]:
        return list(self._alerts)
