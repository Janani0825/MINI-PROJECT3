"""Google Safe Browsing Lookup API integration.

The API key is read only from the server environment. If it is not configured,
or the service is temporarily unavailable, the normal PhishGuard scan continues.
"""
import os

import requests

API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
TIMEOUT = 5


def check_url(url):
    """Return a small, UI-safe status object for one URL."""
    api_key = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
    if not api_key:
        return {
            "status": "not_configured",
            "checked": False,
            "matches": [],
            "note": "Google Safe Browsing API key is not configured."
        }

    payload = {
        "client": {
            "clientId": "phishguard-college-project",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        response = requests.post(
            API_URL,
            params={"key": api_key},
            json=payload,
            timeout=TIMEOUT
        )
        response.raise_for_status()
        data = response.json()
        matches = data.get("matches", [])
        return {
            "status": "hit" if matches else "clear",
            "checked": True,
            "matches": [
                {
                    "threat_type": item.get("threatType", "UNKNOWN"),
                    "platform_type": item.get("platformType", "ANY_PLATFORM")
                }
                for item in matches
            ],
            "note": (
                "Google Safe Browsing lists this URL as unsafe."
                if matches else
                "No match was found in the Google Safe Browsing lists checked."
            )
        }
    except (requests.RequestException, ValueError):
        return {
            "status": "unavailable",
            "checked": False,
            "matches": [],
            "note": "Google Safe Browsing could not be reached. Other checks still ran."
        }
