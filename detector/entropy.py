"""
Phase 2: Feature Engineering & Shannon Entropy
滑動視窗計算 I/O 頻率，並對每個被修改的檔案計算 Shannon Entropy。
產出時間序列特徵：[timestamp, pid, io_freq, file_entropy, entropy_delta]
"""

import math
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path

from detector.monitor import IOEvent


SAMPLE_BYTES = 4096  # 每次抽樣讀取的位元組數


@dataclass
class FeatureVector:
    timestamp: float
    pid: int | None
    process_name: str | None
    path: str
    io_freq: int          # 滑動視窗內該 PID 修改的檔案數
    file_entropy: float   # 當前檔案熵值 (0~8)
    entropy_delta: float  # 與上次該檔案熵值的差值


def shannon_entropy(data: bytes) -> float:
    """計算位元組序列的 Shannon Entropy，範圍 0（完全規律）到 8（完全隨機）。"""
    if not data:
        return 0.0
    freq = defaultdict(int)
    for byte in data:
        freq[byte] += 1
    total = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / total
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def sample_file_entropy(path: str) -> float | None:
    """讀取檔案前 SAMPLE_BYTES bytes 並計算熵值，檔案不存在或無法讀取則回傳 None。"""
    try:
        with open(path, "rb") as f:
            data = f.read(SAMPLE_BYTES)
        return shannon_entropy(data)
    except (OSError, PermissionError):
        return None


class EntropyAnalyzer:
    def __init__(self, window_seconds: float = 5.0):
        self.window_seconds = window_seconds
        # pid -> deque of (timestamp, path) 在視窗內的修改紀錄
        self._pid_window: dict[int, deque] = defaultdict(deque)
        # path -> last known entropy
        self._last_entropy: dict[str, float] = {}

    def _update_window(self, pid: int, timestamp: float, path: str):
        """將新事件加入視窗並移除過期的舊事件。"""
        dq = self._pid_window[pid]
        dq.append((timestamp, path))
        cutoff = timestamp - self.window_seconds
        while dq and dq[0][0] < cutoff:
            dq.popleft()

    def process(self, event: IOEvent) -> FeatureVector | None:
        """
        處理單一 IOEvent，回傳特徵向量；若無法取得熵值則回傳 None。
        只處理 created / modified 事件（這兩種才代表寫入行為）。
        """
        if event.event_type not in ("created", "modified"):
            return None

        entropy = sample_file_entropy(event.path)
        if entropy is None:
            return None

        pid = event.pid or 0
        self._update_window(pid, event.timestamp, event.path)
        io_freq = len(self._pid_window[pid])

        last = self._last_entropy.get(event.path, entropy)
        entropy_delta = round(entropy - last, 4)
        self._last_entropy[event.path] = entropy

        return FeatureVector(
            timestamp=event.timestamp,
            pid=event.pid,
            process_name=event.process_name,
            path=event.path,
            io_freq=io_freq,
            file_entropy=entropy,
            entropy_delta=entropy_delta,
        )

    def process_batch(self, events: list[IOEvent]) -> list[FeatureVector]:
        results = []
        for event in events:
            fv = self.process(event)
            if fv is not None:
                results.append(fv)
        return results


if __name__ == "__main__":
    # 快速測試：計算當前目錄下幾個檔案的熵值
    import sys
    targets = sys.argv[1:] or [__file__]
    for path in targets:
        e = sample_file_entropy(path)
        print(f"{Path(path).name}: entropy = {e}")
