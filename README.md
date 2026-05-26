# Ransomware File System I/O Time Series Detection System

針對勒索軟體與詐欺行為的檔案系統 I/O 時間序列探勘系統

## 專案架構

```
ransomware-io-detector/
├── detector/          # 偵測系統 (Phase 1-4)
│   ├── monitor.py     # OS 監控層 (inotify)
│   ├── entropy.py     # Shannon Entropy 計算
│   ├── analyzer.py    # Isolation Forest + LLM 分析
│   └── blocker.py     # cgroup 自動阻斷
├── ransom_os/         # RansomOS 模擬器 (教學展示)
│   ├── simulator.py   # 勒索軟體模擬邏輯
│   └── decryptor.py   # 解密還原
├── dashboard/         # Live Dashboard (React/HTML)
└── requirements.txt
```

## 四階段架構

| Phase | 功能 | 技術 |
|-------|------|------|
| 1 | OS 監控層 | inotify / eBPF |
| 2 | 特徵工程 | Shannon Entropy、滑動視窗 |
| 3 | AI 偵測 | Isolation Forest + Claude API |
| 4 | 動態阻斷 | cgroup v2 / SIGKILL |

## 技術 Stack

- **Python**: 監控、加解密邏輯 (`cryptography`, `psutil`, `watchdog`)
- **Linux**: inotify / eBPF / cgroup v2
- **Claude API**: 即時威脅分析報告
- **React/HTML**: Live Dashboard

## 核心概念

> 「我們不在乎你用什麼惡意程式碼，我們只看你的底層行為。」

勒索軟體無論怎麼變形，最終都必須「讀取檔案 → 加密 → 寫入檔案」。
系統透過監控這個行為模式（高 I/O 頻率 + 高資訊熵）來偵測並阻斷攻擊。
