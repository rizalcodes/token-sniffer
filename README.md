# 🔍 Token Sniffer Bot

> Detect honeypots, rug pulls & scam tokens on Ethereum — powered by GoPlus Security API + Etherscan V2 + Web3.py

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python)
![Web3](https://img.shields.io/badge/Web3.py-6.x-orange?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)

---

## 📌 Overview

**Token Sniffer Bot** is a standalone Python tool that analyzes ERC-20 token contracts for safety risks before you ape in. It combines multiple data sources to generate a **safety score (0–100)** and sends results directly to your Telegram.

Built as part of the [Web3 Python Toolkit](https://github.com/rizalcodes/web3-python-toolkit) project.

---

## ✨ Features

| Feature | Description |
|---|---|
| 🍯 Honeypot Detection | Checks if token cannot be sold |
| 💸 Tax Analysis | Buy/sell tax percentage check |
| 👤 Ownership Risk | Owner & creator holding percentage |
| 🔒 LP Lock Check | Liquidity pool lock verification |
| 📋 Contract Verification | Source code verified on Etherscan |
| ⭐ Safety Score | 0–100 score with SAFE / RISKY / DANGER label |
| 🤖 Telegram Bot | `/sniff` and `/quick` commands |

---

## 🛠️ Tech Stack

- **Python 3.10+**
- **Web3.py** — Ethereum node interaction
- **GoPlus Security API** — Token security data (free tier: 10k req/day)
- **Etherscan API V2** — Contract verification & token info
- **Infura** — Ethereum RPC provider
- **python-telegram-bot / requests** — Telegram integration

---

## ⚡ Quick Start

### 1. Clone the repo
```bash
git clone https://github.com/rizalcodes/token-sniffer
cd token-sniffer
```

### 2. Install dependencies
```bash
pip install web3 requests
```

### 3. Configure API keys

Open `token_sniffer.py` and set your keys:
```python
ETHERSCAN_API_KEY = "your_etherscan_key"
INFURA_URL        = "https://mainnet.infura.io/v3/your_infura_key"
TELEGRAM_TOKEN    = "your_telegram_bot_token"
TELEGRAM_CHAT_ID  = "your_chat_id"
```

### 4. Run

**As Telegram Bot:**
```bash
python token_sniffer.py
```

**As CLI tool:**
```bash
python token_sniffer.py check 0xA0b86991c6218b36c1d19d4a2e9Eb0cE3606eB48
```

---

## 🤖 Bot Commands

| Command | Description |
|---|---|
| `/sniff <address>` | Full token safety analysis (~15s) |
| `/quick <address>` | Quick honeypot check (~5s) |
| `/watch <address>` | Add token to watchlist |
| `/watchlist` | View monitored tokens |
| `/unwatch <address>` | Remove from watchlist |

---

## 📊 Safety Score System

| Score | Label | Meaning |
|---|---|---|
| 80 – 100 | ✅ SAFE | Low risk, looks legitimate |
| 50 – 79 | ⚠️ RISKY | Proceed with caution |
| 0 – 49 | 🚨 DANGER | High risk, likely scam |

**Score deductions:**
- Honeypot detected → **-50**
- High sell tax (>10%) → **-20**
- Hidden owner → **-25**
- Self-destruct function → **-30**
- Liquidity not locked → **-15**
- Contract unverified → **-10**
- High buy tax (>10%) → **-15**

---

## 📸 Example Output
