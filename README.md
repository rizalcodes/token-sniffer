# 🔍 Token Sniffer Bot

> Detect honeypots, rug pulls & scam tokens on Ethereum — powered by GoPlus Security API + Etherscan V2 + Web3.py with Telegram alerts. 

![Python](https://img.shields.io/badge/Python-3.12+-blue?style=flat-square&logo=python)
![GoPlus](https://img.shields.io/badge/GoPlus-Security_API-red?style=flat-square)
![Telegram](https://img.shields.io/badge/Telegram-Bot-26A5E4?style=flat-square&logo=telegram)
![Ethereum](https://img.shields.io/badge/Ethereum-Mainnet-627EEA?style=flat-square&logo=ethereum)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

---

## 🔍 What is Token Sniffing?

Token sniffing is the process of analyzing an ERC-20 smart contract for malicious patterns before buying — helping traders avoid losing funds to honeypots, rug pulls, and scam tokens.

This bot analyzes tokens using:
- 🛡️ **GoPlus Security API** — industry standard token security database
- 📋 **Etherscan V2** — contract verification & on-chain data
- ⛓️ **Web3.py** — direct Ethereum node interaction via Infura

---

## ✨ Features

- 🍯 **Honeypot Detection** — check if token can actually be sold
- 💸 **Tax Analysis** — buy/sell tax percentage check
- 👤 **Ownership Risk** — owner & creator holding percentage
- 🔒 **LP Lock Check** — liquidity pool lock verification
- 📋 **Contract Verification** — source code verified on Etherscan
- ⭐ **Safety Score** — 0–100 score with SAFE / RISKY / DANGER label
- 🤖 **Telegram Bot** — `/sniff` and `/quick` commands
- 👀 **Watchlist** — monitor multiple tokens at once

---

## 🚀 Quick Start

### 1. Install dependencies

```bash
pip install web3 requests
```

### 2. Set API keys

Open `token_sniffer.py` and configure:

```python
ETHERSCAN_API_KEY = "your_etherscan_key"
INFURA_URL        = "https://mainnet.infura.io/v3/your_infura_key"
TELEGRAM_TOKEN    = "your_telegram_bot_token"
TELEGRAM_CHAT_ID  = "your_chat_id"
```

### 3. Run as Telegram Bot

```bash
python token_sniffer.py
```

### 4. Quick CLI check (one-time)

```bash
python token_sniffer.py check 0xA0b86991c6218b36c1d19d4a2e9Eb0cE3606eB48
```

---

## 🤖 Telegram Commands

| Command | Description |
|---------|-------------|
| `/sniff <address>` | Full token safety analysis (~15s) |
| `/quick <address>` | Quick honeypot check (~5s) |
| `/watch <address>` | Add token to watchlist |
| `/watchlist` | View monitored tokens |
| `/unwatch <address>` | Remove from watchlist |

---

## 📊 Sample Output

```
🟢 TOKEN SAFETY REPORT
━━━━━━━━━━━━━━━━━━━━━━
🏷️ USD Coin ($USDC)
📍 0xA0b86991...606eB48
⭐ Safety Score: 95/100 — SAFE ✅

📊 Key Metrics:
- Honeypot    : NO ✅
- Buy Tax     : 0.0%
- Sell Tax    : 0.0%
- Owner Hold  : 0.0%
- Holders     : 2,100,000+
- LP Locked   : YES ✅
- Verified    : YES ✅
```

---

## ⭐ Safety Score System

| Score | Label | Meaning |
|-------|-------|---------|
| 80 – 100 | ✅ SAFE | Low risk, looks legitimate |
| 50 – 79 | ⚠️ RISKY | Proceed with caution |
| 0 – 49 | 🚨 DANGER | High risk, likely scam |

**Score deductions:**

| Issue | Deduction |
|-------|-----------|
| Honeypot detected | -50 |
| Hidden owner | -25 |
| Self-destruct function | -30 |
| High sell tax (>10%) | -20 |
| Liquidity not locked | -15 |
| High buy tax (>10%) | -15 |
| Contract unverified | -10 |
| Owner can take back ownership | -10 |
| High owner/creator holding | -10 |
| External call risk | -5 |

---

## 🏗️ Architecture

```
token_sniffer.py
├── GoPlusClient        → GoPlus Security API integration
│   ├── check_token()        → full token security data
│   └── check_honeypot()     → honeypot detection only
├── EtherscanClient     → Etherscan V2 API integration
│   ├── get_token_info()     → token name, symbol, supply
│   ├── get_contract_info()  → source code verification
│   ├── get_token_holders()  → holder count
│   └── get_token_transfers() → recent transfer activity
├── TokenAnalyzer       → Core safety engine
│   ├── analyze()            → full safety analysis + scoring
│   └── quick_check()        → fast honeypot check only
└── TokenSnifferBot     → Telegram bot with 5 commands
```

---

## 📡 Data Sources

| Source | Usage |
|--------|-------|
| [GoPlus Security API](https://gopluslabs.io) | Primary — honeypot, tax, ownership, LP data |
| [Etherscan V2](https://etherscan.io) | Contract verification, token info |
| [Infura](https://infura.io) | Ethereum RPC node |

GoPlus free tier supports up to **10,000 requests/day**.

---

## ⚠️ Risk Disclaimer

| Risk Level | Description |
|------------|-------------|
| 🟢 SAFE | Score 80–100, passed all major checks |
| 🟡 RISKY | Score 50–79, has warnings — trade carefully |
| 🔴 DANGER | Score 0–49, critical issues detected — avoid |

> **This tool is for informational purposes only. Always do your own research before buying any token.**

---

## 🔧 Requirements

```
web3>=6.0.0
requests>=2.28.0
```

---

## 👤 Author

**Rizal** — [@rizalcodes](https://github.com/rizalcodes)

> Building Web3 tools with Python 🐍⛓️

---

## 📄 License

MIT License — free to use, modify, and distribute.
