"""
Phase 4: OS-Level Dynamic Blocking
偵測到威脅後，優先嘗試 cgroup v2 freeze（保留記憶體供鑑識），
若不可用則降回 SIGKILL 強制終止。
"""

import os
import signal
import logging
import subprocess
from pathlib import Path

import psutil

logger = logging.getLogger(__name__)

CGROUP_ROOT = Path("/sys/fs/cgroup")
FREEZE_GROUP = CGROUP_ROOT / "ransom_detector" / "frozen"


def _cgroup_available() -> bool:
    """確認系統支援 cgroup v2 且有寫入權限。"""
    return (CGROUP_ROOT / "cgroup.controllers").exists() and os.geteuid() == 0


def _ensure_freeze_group():
    """建立 cgroup freeze 群組（需 root）。"""
    FREEZE_GROUP.mkdir(parents=True, exist_ok=True)
    freeze_ctrl = FREEZE_GROUP / "cgroup.freeze"
    if not freeze_ctrl.exists():
        raise RuntimeError(f"cgroup freeze 不支援：{freeze_ctrl} 不存在")


def freeze_process(pid: int) -> bool:
    """
    將程序移入 cgroup freeze 群組，程序「急凍」但保留記憶體。
    成功回傳 True，失敗回傳 False。
    """
    if not _cgroup_available():
        logger.warning("cgroup v2 不可用（需 root），改用 SIGSTOP 暫停程序。")
        return _sigstop(pid)
    try:
        _ensure_freeze_group()
        (FREEZE_GROUP / "cgroup.procs").write_text(str(pid))
        (FREEZE_GROUP / "cgroup.freeze").write_text("1")
        logger.warning(f"[FREEZE] PID {pid} 已急凍於 cgroup: {FREEZE_GROUP}")
        return True
    except Exception as e:
        logger.error(f"cgroup freeze 失敗: {e}，改用 SIGSTOP。")
        return _sigstop(pid)


def kill_process(pid: int) -> bool:
    """
    向程序發送 SIGKILL，強制終止（不保留記憶體）。
    適用於確認惡意且不需鑑識的情況。
    """
    try:
        os.kill(pid, signal.SIGKILL)
        logger.warning(f"[KILL] PID {pid} 已強制終止 (SIGKILL)")
        return True
    except ProcessLookupError:
        logger.info(f"PID {pid} 已不存在。")
        return False
    except PermissionError:
        logger.error(f"無權限終止 PID {pid}。")
        return False


def _sigstop(pid: int) -> bool:
    """發送 SIGSTOP 暫停（不終止）程序。"""
    try:
        os.kill(pid, signal.SIGSTOP)
        logger.warning(f"[STOP] PID {pid} 已暫停 (SIGSTOP)")
        return True
    except (ProcessLookupError, PermissionError) as e:
        logger.error(f"SIGSTOP 失敗: {e}")
        return False


def unfreeze_process(pid: int):
    """解凍（供鑑識完成後恢復或進行後續處置）。"""
    if _cgroup_available() and FREEZE_GROUP.exists():
        try:
            (FREEZE_GROUP / "cgroup.freeze").write_text("0")
            logger.info(f"[UNFREEZE] PID {pid} 已解凍")
        except Exception as e:
            logger.error(f"解凍失敗: {e}")
    else:
        try:
            os.kill(pid, signal.SIGCONT)
            logger.info(f"[CONT] PID {pid} 已恢復 (SIGCONT)")
        except Exception as e:
            logger.error(f"SIGCONT 失敗: {e}")


def get_process_info(pid: int) -> dict:
    """取得程序的詳細資訊供鑑識報告。"""
    try:
        proc = psutil.Process(pid)
        return {
            "pid": pid,
            "name": proc.name(),
            "exe": proc.exe(),
            "cmdline": proc.cmdline(),
            "create_time": proc.create_time(),
            "status": proc.status(),
            "open_files": [f.path for f in proc.open_files()],
            "connections": len(proc.connections()),
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
        return {"pid": pid, "error": str(e)}


def respond_to_threat(pid: int, forensic_mode: bool = True) -> dict:
    """
    統一威脅回應入口。
    forensic_mode=True：急凍（保留記憶體，可後續鑑識）
    forensic_mode=False：直接 SIGKILL
    """
    info = get_process_info(pid)
    if forensic_mode:
        success = freeze_process(pid)
        action = "freeze"
    else:
        success = kill_process(pid)
        action = "kill"
    return {"action": action, "success": success, "process_info": info}
