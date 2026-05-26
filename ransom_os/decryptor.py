"""
Standalone Decryptor - 獨立解密工具
提供僅有 key 的情況下，對任意目錄執行批次解密。
"""

import sys
import logging
from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [Decryptor] %(message)s")


def decrypt_directory(target_dir: str, key: bytes) -> tuple[int, int]:
    """
    對目錄內所有 .ransomed 檔案解密。
    回傳 (成功數, 失敗數)
    """
    fernet = Fernet(key)
    target = Path(target_dir).expanduser().resolve()
    success, failed = 0, 0

    enc_files = list(target.rglob("*.ransomed"))
    if not enc_files:
        logger.info("找不到任何 .ransomed 檔案。")
        return 0, 0

    logger.info(f"找到 {len(enc_files)} 個加密檔案，開始解密...")

    for enc_path in enc_files:
        try:
            data = fernet.decrypt(enc_path.read_bytes())
            original_path = enc_path.parent / enc_path.stem  # 去掉 .ransomed
            original_path.write_bytes(data)
            enc_path.unlink()
            logger.info(f"[OK] {enc_path.name} → {original_path.name}")
            success += 1
        except InvalidToken:
            logger.error(f"[FAIL] {enc_path.name}: 金鑰錯誤，無法解密")
            failed += 1
        except Exception as e:
            logger.error(f"[FAIL] {enc_path.name}: {e}")
            failed += 1

    logger.info(f"解密完成：成功 {success} / 失敗 {failed}")
    return success, failed


def load_key_from_file(key_path: str) -> bytes:
    return Path(key_path).read_bytes()


def load_key_from_hex(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("用法: python -m ransom_os.decryptor <target_dir> <key_file_or_hex>")
        sys.exit(1)

    target = sys.argv[1]
    key_input = sys.argv[2]

    if Path(key_input).exists():
        key = load_key_from_file(key_input)
    else:
        try:
            key = load_key_from_hex(key_input)
        except ValueError:
            key = key_input.encode()

    decrypt_directory(target, key)
