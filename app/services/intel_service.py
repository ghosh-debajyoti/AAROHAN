from typing import Any

import Levenshtein
import requests


class IntelService:
    @staticmethod
    def query_ip(ip: str) -> dict[str, Any]:
        if not ip:
            return {}
        try:
            resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    return {
                        "ip": ip,
                        "asn": data.get("as"),
                        "isp": data.get("isp"),
                        "country": data.get("country"),
                        "region": data.get("regionName"),
                    }
        except requests.RequestException:
            pass
        return {}

    @staticmethod
    def check_lookalike_domain(
        from_domain: str, reply_to_domain: str
    ) -> dict[str, Any]:
        if not from_domain or not reply_to_domain:
            return {"is_lookalike": False, "distance": 0}

        from_domain = from_domain.lower().strip()
        reply_to_domain = reply_to_domain.lower().strip()

        if from_domain == reply_to_domain:
            return {"is_lookalike": False, "distance": 0}

        distance = Levenshtein.distance(from_domain, reply_to_domain)
        is_lookalike = distance <= 2

        return {
            "is_lookalike": is_lookalike,
            "distance": distance,
            "from_domain": from_domain,
            "reply_to_domain": reply_to_domain,
        }
