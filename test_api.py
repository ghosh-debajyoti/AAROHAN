import asyncio

import httpx


async def test_api():
    async with httpx.AsyncClient(base_url="http://127.0.0.1:8000") as client:
        # Create a dummy EML content
        eml_content = b"""From: attacker@malicious.com
To: victim@company.com
Reply-To: typosquat@mailicious.com
Subject: URGENT: Invoice Payment
Date: Wed, 02 Sep 2026 10:00:00 -0700
Message-ID: <12345@malicious.com>
Received: from mail.malicious.com (mail.malicious.com [8.8.8.8]) by mx.google.com with ESMTPS id xyz; Wed, 02 Sep 2026 10:00:00 -0700 (PDT)
Authentication-Results: mx.google.com; spf=fail (google.com: domain of attacker@malicious.com does not designate 8.8.8.8 as permitted sender) smtp.mailfrom=attacker@malicious.com; dkim=fail; dmarc=fail

Please pay the attached invoice immediately.
"""
        files = {'file': ('test.eml', eml_content, 'message/rfc822')}
        
        try:
            response = await client.post("/api/v1/analyze", files=files)
            print(f"Status Code: {response.status_code}")
            import json
            print(json.dumps(response.json(), indent=2))
        except Exception as e:
            print(f"Error during request: {e}")

if __name__ == "__main__":
    asyncio.run(test_api())
