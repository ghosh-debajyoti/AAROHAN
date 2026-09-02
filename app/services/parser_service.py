import email
import hashlib
import re
from dataclasses import dataclass
from email import policy
from typing import Any


@dataclass
class AttachmentMeta:
    filename: str
    mime_type: str
    sha256: str
    size: int

@dataclass
class ParsedEmail:
    headers: dict[str, Any]
    body: str
    indicators: list[dict[str, str]]
    attachments: list[AttachmentMeta]
    mime_boundaries: list[str]
    relay_route: list[dict[str, Any]]

class EmailParserService:
    def __init__(self, raw_eml_bytes: bytes):
        self.raw_bytes = raw_eml_bytes
        self.msg = email.message_from_bytes(raw_eml_bytes, policy=policy.default)
    
    def parse_all(self) -> ParsedEmail:
        headers = self._extract_headers()
        body, boundaries = self._extract_body_and_boundaries()
        attachments = self._extract_attachments()
        indicators = self._extract_indicators(body)
        relay_route = self._extract_relay_route(headers.get("Received", []))
        
        return ParsedEmail(
            headers=headers,
            body=body,
            indicators=indicators,
            attachments=attachments,
            mime_boundaries=boundaries,
            relay_route=relay_route
        )
    
    def _extract_headers(self) -> dict[str, Any]:
        try:
            return {
                "From": self.msg.get("From"),
                "Reply-To": self.msg.get("Reply-To"),
                "Received": self.msg.get_all("Received") or [],
                "Message-ID": self.msg.get("Message-ID"),
                "Authentication-Results": self.msg.get("Authentication-Results"),
                "Subject": self.msg.get("Subject"),
                "Date": self.msg.get("Date")
            }
        except Exception as e:
            print(f"Header extraction failed: {e}")
            return {}
            
    def _extract_body_and_boundaries(self) -> tuple[str, list[str]]:
        body = ""
        boundaries = []
        try:
            if self.msg.is_multipart():
                bound = self.msg.get_boundary()
                if bound: boundaries.append(bound)
                for part in self.msg.walk():
                    content_type = part.get_content_type()
                    cdisp = str(part.get("Content-Disposition"))
                    pb = part.get_boundary()
                    if pb and pb not in boundaries:
                        boundaries.append(pb)
                    
                    if content_type == "text/plain" and "attachment" not in cdisp:
                        content = part.get_content()
                        if content:
                            body += content
            else:
                content = self.msg.get_content()
                if content:
                    body = content
        except Exception as e:
            print(f"Body extraction failed: {e}")
        return body, [b for b in boundaries if b]

    def _extract_attachments(self) -> list[AttachmentMeta]:
        attachments = []
        try:
            if self.msg.is_multipart():
                for part in self.msg.walk():
                    cdisp = str(part.get("Content-Disposition"))
                    if "attachment" in cdisp:
                        payload = part.get_payload(decode=True) or b""
                        if payload:
                            attachments.append(AttachmentMeta(
                                filename=part.get_filename() or "unknown",
                                mime_type=part.get_content_type(),
                                sha256=hashlib.sha256(payload).hexdigest(),
                                size=len(payload)
                            ))
        except Exception as e:
            print(f"Attachment extraction failed: {e}")
        return attachments

    def _extract_indicators(self, body: str) -> list[dict[str, str]]:
        inds = []
        try:
            ips = set(re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', body))
            urls = set(re.findall(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', body))
            
            for ip in ips: inds.append({"type": "IP", "value": ip})
            for url in urls:
                inds.append({"type": "URL", "value": url})
                dm = re.search(r'https?://([^/:]+)', url)
                if dm: inds.append({"type": "DOMAIN", "value": dm.group(1)})
        except Exception as e:
            print(f"Indicator extraction failed: {e}")
        return inds

    def _extract_relay_route(self, received_headers: list[str]) -> list[dict[str, Any]]:
        routes = []
        try:
            if not isinstance(received_headers, list):
                received_headers = [received_headers] if received_headers else []
                
            from_re = re.compile(r'from\s+([^\s]+)')
            ip_re = re.compile(r'\[([0-9a-fA-F\.\:]+)\]')
            
            for i, header in enumerate(reversed(received_headers)):
                h = str(header).replace('\n', ' ').replace('\r', '')
                f_m = from_re.search(h)
                ip_m = ip_re.search(h)
                ts = h.rsplit(';', 1)[-1].strip() if ';' in h else None
                
                routes.append({
                    "hop_number": i + 1,
                    "raw": h,
                    "helo_domain": f_m.group(1) if f_m else None,
                    "ip": ip_m.group(1) if ip_m else None,
                    "timestamp": ts
                })
        except Exception as e:
            print(f"Relay extraction failed: {e}")
        return routes
