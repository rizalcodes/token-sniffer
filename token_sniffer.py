"""
token_sniffer.py - Token Safety Analyzer & Sniffer
By Rizal | github.com/rizalcodes
Detect honeypots, rug pulls, and scam tokens on Ethereum
Multi-source: Etherscan V2 + GoPlus Security API + Web3.py
Output: Safety score + Telegram alerts
"""

import os
import time
import logging
import requests
from web3 import Web3
from datetime import datetime

# ─────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
log = logging.getLogger(__name__)


# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────
ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY", "Your_Etherscan_Api_Here")
INFURA_URL        = os.getenv("INFURA_URL",        "https://mainnet.infura.io/v3/Your_Infure_Key_Here")
TELEGRAM_TOKEN    = os.getenv("TELEGRAM_TOKEN",    "Your_Bot_Token_Here")
TELEGRAM_CHAT_ID  = os.getenv("TELEGRAM_CHAT_ID",  "Your_Chat_ID_Here")

# Safety thresholds
MIN_LIQUIDITY_USD    = 10000   # minimum liquidity untuk dianggap legitimate ($10k)
MAX_TAX_PERCENT      = 10      # maximum acceptable tax (10%)
MIN_HOLDERS          = 50      # minimum holders
MAX_OWNER_PERCENT    = 20      # maximum owner holding (20%)


# ─────────────────────────────────────────────
# 1. GOPLUS SECURITY CLIENT
# ─────────────────────────────────────────────
class GoPlusClient:
    """
    GoPlus Security API — industri standard untuk token security check.
    Free tier: 10,000 req/day
    """
    BASE = "https://api.gopluslabs.io/api/v1"

    def __init__(self):
        self.session = requests.Session()

    def check_token(self, token_address: str, chain_id: int = 1) -> dict:
        """Full security check untuk satu token."""
        try:
            r = self.session.get(
                f"{self.BASE}/token_security/{chain_id}",
                params={"contract_addresses": token_address.lower()},
                timeout=15
            )
            data   = r.json()
            result = data.get("result", {})
            return result.get(token_address.lower(), {})
        except Exception as e:
            log.error(f"GoPlus error: {e}")
            return {}

    def check_honeypot(self, token_address: str) -> dict:
        """Check apakah token adalah honeypot."""
        try:
            r = self.session.get(
                f"{self.BASE}/honeypot_detection/1",
                params={"contract_addresses": token_address.lower()},
                timeout=15
            )
            data   = r.json()
            result = data.get("result", {})
            return result.get(token_address.lower(), {})
        except Exception as e:
            log.error(f"Honeypot check error: {e}")
            return {}


# ─────────────────────────────────────────────
# 2. ETHERSCAN CLIENT
# ─────────────────────────────────────────────
class EtherscanClient:
    BASE = "https://api.etherscan.io/v2/api"

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.session = requests.Session()

    def _get(self, params: dict) -> dict:
        params["apikey"]  = self.api_key
        params["chainid"] = 1
        try:
            r = self.session.get(self.BASE, params=params, timeout=15)
            return r.json()
        except Exception as e:
            log.error(f"Etherscan error: {e}")
            return {}

    def get_token_info(self, address: str) -> dict:
        """Ambil info dasar token."""
        data = self._get({
            "module" : "token",
            "action" : "tokeninfo",
            "contractaddress": address,
        })
        result = data.get("result", [])
        return result[0] if isinstance(result, list) and result else {}

    def get_contract_info(self, address: str) -> dict:
        """Cek apakah contract verified dan ambil source code info."""
        data = self._get({
            "module" : "contract",
            "action" : "getsourcecode",
            "address": address,
        })
        result = data.get("result", [])
        if isinstance(result, list) and result and isinstance(result[0], dict):
            return result[0]
        return {}

    def get_token_holders(self, address: str) -> int:
        """Ambil jumlah holder token."""
        data = self._get({
            "module" : "token",
            "action" : "tokenholdercount",
            "contractaddress": address,
        })
        try:
            return int(data.get("result", 0))
        except Exception:
            return 0

    def get_token_transfers(self, address: str, limit: int = 100) -> list:
        """Ambil recent token transfers."""
        data = self._get({
            "module"  : "account",
            "action"  : "tokentx",
            "contractaddress": address,
            "sort"    : "desc",
            "offset"  : limit,
            "page"    : 1,
        })
        result = data.get("result", [])
        return result if isinstance(result, list) else []

    def get_new_tokens(self, limit: int = 20) -> list:
        """Ambil token contracts yang baru di-deploy."""
        # Get recent contract creations
        data = self._get({
            "module" : "account",
            "action" : "txlist",
            "address": "0x0000000000000000000000000000000000000000",
            "sort"   : "desc",
            "offset" : limit,
            "page"   : 1,
        })
        result = data.get("result", [])
        # Filter contract creations
        contracts = [
            tx for tx in (result if isinstance(result, list) else [])
            if tx.get("contractAddress")
        ]
        return contracts[:limit]


# ─────────────────────────────────────────────
# 3. TOKEN ANALYZER
# ─────────────────────────────────────────────
class TokenAnalyzer:
    """Core engine untuk analyze token safety."""

    def __init__(self):
        self.goplus    = GoPlusClient()
        self.etherscan = EtherscanClient(ETHERSCAN_API_KEY)
        self.w3        = Web3(Web3.HTTPProvider(INFURA_URL))

    def analyze(self, token_address: str) -> dict:
        """Full token safety analysis."""
        log.info(f"🔍 Analyzing token: {token_address[:10]}...")

        address = token_address.lower()
        result  = {
            "address"   : token_address,
            "timestamp" : datetime.now().isoformat(),
            "checks"    : {},
            "score"     : 100,  # start dengan 100, kurangi per issue
            "issues"    : [],
            "warnings"  : [],
            "safe"      : True,
        }

        # ── 1. GoPlus Security Check ──────────
        log.info("🛡️ Running GoPlus security check...")
        gp = self.goplus.check_token(token_address)
        time.sleep(0.5)

        if gp:
            # Honeypot check
            is_honeypot = gp.get("is_honeypot", "0")
            if is_honeypot == "1":
                result["issues"].append("🚨 HONEYPOT DETECTED — cannot sell token!")
                result["score"] -= 50
                result["safe"]   = False

            # Buy tax
            buy_tax = float(gp.get("buy_tax", 0) or 0) * 100
            if buy_tax > MAX_TAX_PERCENT:
                result["issues"].append(f"⚠️ High buy tax: {buy_tax:.1f}%")
                result["score"] -= 15

            # Sell tax
            sell_tax = float(gp.get("sell_tax", 0) or 0) * 100
            if sell_tax > MAX_TAX_PERCENT:
                result["issues"].append(f"🚨 High sell tax: {sell_tax:.1f}%")
                result["score"] -= 20
                if sell_tax > 50:
                    result["safe"] = False

            # Owner can mint
            can_mint = gp.get("can_take_back_ownership", "0")
            if can_mint == "1":
                result["warnings"].append("⚠️ Owner can take back ownership")
                result["score"] -= 10

            # Hidden owner
            hidden_owner = gp.get("hidden_owner", "0")
            if hidden_owner == "1":
                result["issues"].append("🚨 Hidden owner detected!")
                result["score"] -= 25
                result["safe"] = False

            # Self-destruct
            selfdestruct = gp.get("selfdestruct", "0")
            if selfdestruct == "1":
                result["issues"].append("🚨 Contract can self-destruct!")
                result["score"] -= 30
                result["safe"] = False

            # External call
            ext_call = gp.get("external_call", "0")
            if ext_call == "1":
                result["warnings"].append("⚠️ Contract makes external calls")
                result["score"] -= 5

            # Owner percent
            owner_percent = float(gp.get("owner_percent", 0) or 0) * 100
            if owner_percent > MAX_OWNER_PERCENT:
                result["warnings"].append(f"⚠️ Owner holds {owner_percent:.1f}% of supply")
                result["score"] -= 10

            # Creator percent
            creator_percent = float(gp.get("creator_percent", 0) or 0) * 100
            if creator_percent > MAX_OWNER_PERCENT:
                result["warnings"].append(f"⚠️ Creator holds {creator_percent:.1f}% of supply")
                result["score"] -= 10

            # LP locked
            lp_holders = gp.get("lp_holders", [])
            lp_locked  = any(
                h.get("is_locked") == 1
                for h in (lp_holders if isinstance(lp_holders, list) else [])
            )
            if not lp_locked and lp_holders:
                result["warnings"].append("⚠️ Liquidity not locked")
                result["score"] -= 15

            # Holder count
            holder_count = int(gp.get("holder_count", 0) or 0)
            if holder_count < MIN_HOLDERS and holder_count > 0:
                result["warnings"].append(f"⚠️ Low holder count: {holder_count}")
                result["score"] -= 5

            result["checks"]["goplus"] = {
                "is_honeypot"    : is_honeypot == "1",
                "buy_tax"        : buy_tax,
                "sell_tax"       : sell_tax,
                "owner_percent"  : owner_percent,
                "creator_percent": creator_percent,
                "holder_count"   : holder_count,
                "lp_locked"      : lp_locked,
                "can_mint"       : can_mint == "1",
                "hidden_owner"   : hidden_owner == "1",
                "self_destruct"  : selfdestruct == "1",
            }

            # Token basic info from GoPlus
            result["name"]   = gp.get("token_name", "Unknown")
            result["symbol"] = gp.get("token_symbol", "???")

        # ── 2. Contract Verification ──────────
        log.info("📋 Checking contract verification...")
        contract_info = self.etherscan.get_contract_info(token_address)
        is_verified   = bool(contract_info.get("SourceCode", ""))

        result["checks"]["verified"] = is_verified
        if not is_verified:
            result["warnings"].append("⚠️ Contract source code not verified")
            result["score"] -= 10

        result["checks"]["contract_name"] = contract_info.get("ContractName", "Unknown")

        # ── 3. Final Score ────────────────────
        result["score"] = max(0, result["score"])  # min 0

        # Safety label
        if result["score"] >= 80:
            result["safety_label"] = "SAFE ✅"
            result["safety_color"] = "🟢"
        elif result["score"] >= 50:
            result["safety_label"] = "RISKY ⚠️"
            result["safety_color"] = "🟡"
            result["safe"] = False
        else:
            result["safety_label"] = "DANGER 🚨"
            result["safety_color"] = "🔴"
            result["safe"] = False

        log.info(f"✅ Analysis complete — Score: {result['score']}/100 — {result['safety_label']}")
        return result

    def quick_check(self, token_address: str) -> dict:
        """Quick honeypot check saja (lebih cepat)."""
        log.info(f"⚡ Quick check: {token_address[:10]}...")
        gp = self.goplus.check_token(token_address)
        if not gp:
            return {"error": "Could not fetch data"}

        is_honeypot = gp.get("is_honeypot", "0") == "1"
        buy_tax     = float(gp.get("buy_tax", 0) or 0) * 100
        sell_tax    = float(gp.get("sell_tax", 0) or 0) * 100

        return {
            "address"    : token_address,
            "name"       : gp.get("token_name", "Unknown"),
            "symbol"     : gp.get("token_symbol", "???"),
            "is_honeypot": is_honeypot,
            "buy_tax"    : buy_tax,
            "sell_tax"   : sell_tax,
            "holders"    : int(gp.get("holder_count", 0) or 0),
            "safe"       : not is_honeypot and sell_tax <= MAX_TAX_PERCENT,
        }


# ─────────────────────────────────────────────
# 4. TELEGRAM BOT
# ─────────────────────────────────────────────
class TokenSnifferBot:
    def __init__(self):
        self.token    = TELEGRAM_TOKEN
        self.chat_id  = TELEGRAM_CHAT_ID
        self.base     = f"https://api.telegram.org/bot{self.token}"
        self.analyzer = TokenAnalyzer()
        self.offset   = 0
        self.running  = True
        self.watchlist = []  # tokens to monitor
        log.info("🤖 TokenSnifferBot initialized")

    def send(self, chat_id: str, text: str):
        try:
            requests.post(
                f"{self.base}/sendMessage",
                json={"chat_id": chat_id, "text": text, "parse_mode": "Markdown"},
                timeout=10
            )
        except Exception as e:
            log.error(f"Send error: {e}")

    def get_updates(self) -> list:
        try:
            r = requests.get(
                f"{self.base}/getUpdates",
                params={"offset": self.offset, "timeout": 10},
                timeout=15
            )
            return r.json().get("result", [])
        except Exception:
            return []

    def _format_result(self, result: dict) -> str:
        """Format analysis result untuk Telegram."""
        color  = result.get("safety_color", "⚪")
        label  = result.get("safety_label", "UNKNOWN")
        score  = result.get("score", 0)
        name   = result.get("name", "Unknown")
        symbol = result.get("symbol", "???")
        addr   = result.get("address", "")
        checks = result.get("checks", {}).get("goplus", {})

        msg = f"""
{color} *TOKEN SAFETY REPORT*
━━━━━━━━━━━━━━━━━━━━━━
🏷️ *{name}* (${symbol})
📍 `{addr[:10]}...{addr[-6:]}`
⭐ Safety Score: *{score}/100* — {label}

📊 *Key Metrics:*
• Honeypot    : `{'YES 🚨' if checks.get('is_honeypot') else 'NO ✅'}`
• Buy Tax     : `{checks.get('buy_tax', 0):.1f}%`
• Sell Tax    : `{checks.get('sell_tax', 0):.1f}%`
• Owner Hold  : `{checks.get('owner_percent', 0):.1f}%`
• Holders     : `{checks.get('holder_count', 0):,}`
• LP Locked   : `{'YES ✅' if checks.get('lp_locked') else 'NO ⚠️'}`
• Verified    : `{'YES ✅' if result.get('checks', {}).get('verified') else 'NO ⚠️'}`
        """.strip()

        issues   = result.get("issues", [])
        warnings = result.get("warnings", [])

        if issues:
            msg += "\n\n🚨 *Issues:*\n" + "\n".join(issues)

        if warnings:
            msg += "\n\n⚠️ *Warnings:*\n" + "\n".join(warnings)

        msg += f"\n\n⏰ {result.get('timestamp', '')[:19]}"
        return msg

    # ── Commands ──────────────────────────────
    def cmd_start(self, chat_id: str):
        self.send(chat_id, """
🔍 *Token Sniffer Bot*
━━━━━━━━━━━━━━━━━━━━━━

Detect honeypots, rug pulls & scam tokens!

📋 *Commands:*
/sniff `<address>` — Full token safety analysis
/quick `<address>` — Quick honeypot check
/watch `<address>` — Monitor token for changes
/watchlist — View monitored tokens
/unwatch `<address>` — Remove from watchlist
/help — Show commands

*Example:*
`/sniff 0xA0b86991c6218b36c1d19d4a2e9Eb0cE3606eB48`
`/quick 0xA0b86991c6218b36c1d19d4a2e9Eb0cE3606eB48`
        """.strip())

    def cmd_sniff(self, chat_id: str, args: list):
        if not args:
            self.send(chat_id, "⚠️ Usage: `/sniff 0x...`")
            return
        address = args[0].strip()
        if not address.startswith("0x") or len(address) != 42:
            self.send(chat_id, "❌ Invalid address format.")
            return

        self.send(chat_id, f"🔍 Analyzing token...\n`{address}`\n⏳ Mohon tunggu ~15 detik...")
        try:
            result = self.analyzer.analyze(address)
            self.send(chat_id, self._format_result(result))
        except Exception as e:
            self.send(chat_id, f"❌ Error: `{str(e)[:200]}`")

    def cmd_quick(self, chat_id: str, args: list):
        if not args:
            self.send(chat_id, "⚠️ Usage: `/quick 0x...`")
            return
        address = args[0].strip()
        self.send(chat_id, f"⚡ Quick checking `{address[:10]}...`")
        try:
            result = self.analyzer.quick_check(address)
            if result.get("error"):
                self.send(chat_id, f"❌ Error: `{result['error']}`")
                return

            safe_emoji = "✅" if result["safe"] else "🚨"
            hp_text    = "YES 🚨" if result["is_honeypot"] else "NO ✅"

            self.send(chat_id, f"""
⚡ *QUICK CHECK*
━━━━━━━━━━━━━━━━━━━━━━
🏷️ *{result['name']}* (${result['symbol']})
{safe_emoji} Status: `{'SAFE' if result['safe'] else 'RISKY/DANGEROUS'}`

• Honeypot : `{hp_text}`
• Buy Tax  : `{result['buy_tax']:.1f}%`
• Sell Tax : `{result['sell_tax']:.1f}%`
• Holders  : `{result['holders']:,}`

Use /sniff for full analysis!
            """.strip())
        except Exception as e:
            self.send(chat_id, f"❌ Error: `{str(e)[:200]}`")

    def cmd_watch(self, chat_id: str, args: list):
        if not args:
            self.send(chat_id, "⚠️ Usage: `/watch 0x...`")
            return
        address = args[0].strip()
        if address not in self.watchlist:
            self.watchlist.append(address)
            self.send(chat_id, f"✅ `{address[:10]}...` added to watchlist!")
        else:
            self.send(chat_id, "⚠️ Already in watchlist.")

    def cmd_watchlist(self, chat_id: str):
        if not self.watchlist:
            self.send(chat_id, "📭 Watchlist empty.\nUse `/watch 0x...` to add tokens.")
            return
        lines = ["👀 *Token Watchlist*\n━━━━━━━━━━━━━━━━━━━━━━"]
        for i, addr in enumerate(self.watchlist, 1):
            lines.append(f"{i}. `{addr[:10]}...{addr[-4:]}`")
        self.send(chat_id, "\n".join(lines))

    def cmd_unwatch(self, chat_id: str, args: list):
        if not args:
            self.send(chat_id, "⚠️ Usage: `/unwatch 0x...`")
            return
        address = args[0].strip()
        if address in self.watchlist:
            self.watchlist.remove(address)
            self.send(chat_id, f"✅ `{address[:10]}...` removed from watchlist.")
        else:
            self.send(chat_id, "❌ Address not found in watchlist.")

    # ── Message Router ────────────────────────
    def handle(self, message: dict):
        text    = message.get("text", "").strip()
        chat_id = str(message.get("chat", {}).get("id", ""))
        if not text or not chat_id:
            return

        parts   = text.split()
        command = parts[0].lower()
        args    = parts[1:]
        log.info(f"📨 {command} from {chat_id}")

        if command in ("/start", "/help"): self.cmd_start(chat_id)
        elif command == "/sniff":          self.cmd_sniff(chat_id, args)
        elif command == "/quick":          self.cmd_quick(chat_id, args)
        elif command == "/watch":          self.cmd_watch(chat_id, args)
        elif command == "/watchlist":      self.cmd_watchlist(chat_id)
        elif command == "/unwatch":        self.cmd_unwatch(chat_id, args)
        else:
            self.send(chat_id, "❓ Unknown command. Type /help for commands.")

    # ── Main Loop ─────────────────────────────
    def run(self):
        log.info("🚀 TokenSnifferBot started!")
        while self.running:
            try:
                updates = self.get_updates()
                for update in updates:
                    self.offset = update["update_id"] + 1
                    msg = update.get("message", {})
                    if msg:
                        self.handle(msg)
            except KeyboardInterrupt:
                self.running = False
            except Exception as e:
                log.error(f"Polling error: {e}")
                time.sleep(5)


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────
if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "check":
        if len(sys.argv) < 3:
            print("Usage: python token_sniffer.py check <token_address>")
            sys.exit(1)

        address  = sys.argv[2]
        analyzer = TokenAnalyzer()

        print(f"\n🔍 Analyzing: {address}")
        result = analyzer.analyze(address)

        print(f"\n{result.get('safety_color','')} Safety Score: {result['score']}/100 — {result['safety_label']}")
        print(f"Name   : {result.get('name', 'Unknown')} (${result.get('symbol', '???')})")

        checks = result.get("checks", {}).get("goplus", {})
        print(f"Honeypot  : {'YES' if checks.get('is_honeypot') else 'NO'}")
        print(f"Buy Tax   : {checks.get('buy_tax', 0):.1f}%")
        print(f"Sell Tax  : {checks.get('sell_tax', 0):.1f}%")
        print(f"Holders   : {checks.get('holder_count', 0):,}")
        print(f"LP Locked : {'YES' if checks.get('lp_locked') else 'NO'}")
        print(f"Verified  : {'YES' if result.get('checks',{}).get('verified') else 'NO'}")

        if result.get("issues"):
            print("\n🚨 Issues:")
            for issue in result["issues"]:
                print(f"  {issue}")

        if result.get("warnings"):
            print("\n⚠️ Warnings:")
            for warning in result["warnings"]:
                print(f"  {warning}")

    else:
        bot = TokenSnifferBot()
        bot.run()
