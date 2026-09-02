import re
from typing import Any


class RouteService:
    def __init__(self, received_headers: list[str]):
        # Received headers usually come from top to bottom (most recent to oldest)
        # We want to reverse them to order them chronologically (oldest to most recent)
        self.received_headers = received_headers or []

    def parse_routes(self) -> list[dict[str, Any]]:
        routes = []
        # Received: from HELO (IP) by SERVER with PROTOCOL id ID; TIMESTAMP
        # Regex to capture HELO/EHLO, IP and Timestamp
        from_re = re.compile(r"from\s+([^\s]+)")
        ip_re = re.compile(r"\[([0-9a-fA-F\.\:]+)\]")

        # We process in reverse to get chronological order (oldest first, which is the originating IP)
        for i, header in enumerate(reversed(self.received_headers)):
            header = str(header).replace("\n", " ").replace("\r", "")

            hop_data = {
                "hop_number": i + 1,
                "raw": header,
                "helo_domain": None,
                "ip": None,
                "timestamp": None,
            }

            from_match = from_re.search(header)
            if from_match:
                hop_data["helo_domain"] = from_match.group(1)

            ip_match = ip_re.search(header)
            if ip_match:
                hop_data["ip"] = ip_match.group(1)

            # split by ; to get timestamp at the end
            parts = header.rsplit(";", 1)
            if len(parts) > 1:
                hop_data["timestamp"] = parts[-1].strip()

            routes.append(hop_data)

        return routes

    def get_earliest_infrastructure(self) -> dict[str, Any]:
        routes = self.parse_routes()
        if not routes:
            return {}
        # The first hop in the chronological list is usually the sender's mail server or client
        return routes[0]
