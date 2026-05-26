"""
Phase 1: OS Monitoring Layer
使用 watchdog 監聽目錄的檔案 I/O 事件，記錄時間戳、PID、路徑。
"""

import os
import time
import psutil
import logging
from pathlib import Path
from dataclasses import dataclass, field
from collections import defaultdict
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)


@dataclass
class IOEvent:
    timestamp: float
    event_type: str   # created / modified / deleted / moved
    path: str
    pid: int | None
    process_name: str | None


def find_process_touching_file(filepath: str) -> tuple[int | None, str | None]:
    """掃描所有程序，找出正在開啟此檔案的 PID。"""
    try:
        for proc in psutil.process_iter(["pid", "name", "open_files"]):
            try:
                for f in proc.open_files():
                    if f.path == filepath:
                        return proc.pid, proc.name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception:
        pass
    return None, None


class RansomEventHandler(FileSystemEventHandler):
    def __init__(self, event_queue: list[IOEvent]):
        super().__init__()
        self.event_queue = event_queue

    def _record(self, event: FileSystemEvent, event_type: str):
        path = event.src_path
        pid, pname = find_process_touching_file(path)
        io_event = IOEvent(
            timestamp=time.time(),
            event_type=event_type,
            path=path,
            pid=pid,
            process_name=pname,
        )
        self.event_queue.append(io_event)
        logger.info(
            f"[{event_type.upper():8s}] {Path(path).name:<30s} "
            f"PID={pid or '?':>6}  proc={pname or 'unknown'}"
        )

    def on_created(self, event):
        if not event.is_directory:
            self._record(event, "created")

    def on_modified(self, event):
        if not event.is_directory:
            self._record(event, "modified")

    def on_deleted(self, event):
        if not event.is_directory:
            self._record(event, "deleted")

    def on_moved(self, event):
        if not event.is_directory:
            self._record(event, "moved")


class FileSystemMonitor:
    def __init__(self, watch_dir: str):
        self.watch_dir = str(Path(watch_dir).expanduser().resolve())
        self.event_queue: list[IOEvent] = []
        self._observer = Observer()
        self._handler = RansomEventHandler(self.event_queue)

    def start(self):
        Path(self.watch_dir).mkdir(parents=True, exist_ok=True)
        self._observer.schedule(self._handler, self.watch_dir, recursive=True)
        self._observer.start()
        logger.info(f"Monitoring started on: {self.watch_dir}")

    def stop(self):
        self._observer.stop()
        self._observer.join()
        logger.info("Monitoring stopped.")

    def drain_events(self) -> list[IOEvent]:
        """取出並清空佇列中的所有事件。"""
        events, self.event_queue[:] = self.event_queue[:], []
        return events


if __name__ == "__main__":
    monitor = FileSystemMonitor("~/honeypot_dir")
    monitor.start()
    try:
        while True:
            time.sleep(5)
            events = monitor.drain_events()
            if events:
                print(f"\n--- 過去 5 秒共 {len(events)} 個事件 ---")
                for e in events:
                    print(f"  {e.event_type:8s} | {Path(e.path).name} | PID {e.pid}")
    except KeyboardInterrupt:
        monitor.stop()
