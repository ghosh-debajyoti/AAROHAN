from typing import Any


class ForensicEngineService:
    def __init__(self, headers: dict[str, Any]):
        self.headers = headers

    def evaluate_alignment(self) -> dict[str, Any]:
        results = {
            "dmarc_pass": False,
            "spf_pass": False,
            "dkim_pass": False,
            "reply_to_mismatch": False,
            "technical_flag_score": 0.0,
        }

        auth_results = self.headers.get("Authentication-Results")
        if auth_results:
            auth_str = str(auth_results).lower()
            if "dmarc=pass" in auth_str:
                results["dmarc_pass"] = True
            if "spf=pass" in auth_str:
                results["spf_pass"] = True
            if "dkim=pass" in auth_str:
                results["dkim_pass"] = True

        # Calculate technical flag score based on failures
        if not results["dmarc_pass"]:
            results["technical_flag_score"] += 15
        if not results["spf_pass"]:
            results["technical_flag_score"] += 10
        if not results["dkim_pass"]:
            results["technical_flag_score"] += 10

        # Check Reply-To mismatch
        sender = self.headers.get("From")
        reply_to = self.headers.get("Reply-To")
        if sender and reply_to and str(sender).strip() != str(reply_to).strip():
            results["reply_to_mismatch"] = True
            results["technical_flag_score"] += 20

        return results
