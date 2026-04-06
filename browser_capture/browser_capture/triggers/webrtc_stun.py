"""
Load a minimal page that starts WebRTC ICE to STUN server (browser STUN Binding).
"""

from __future__ import annotations

from playwright.sync_api import Page


def run_webrtc_stun(
    page: Page,
    *,
    stun_url: str = "stun:stun.l.google.com:19302",
    timeout_ms: int = 45_000,
) -> None:
    """Load minimal HTML that creates RTCPeerConnection with given ICE server."""
    html = f"""<!DOCTYPE html><html><head><meta charset="utf-8"></head><body>
<script>
const cfg = {{ iceServers: [{{ urls: "{stun_url}" }}] }};
const pc = new RTCPeerConnection(cfg);
pc.createDataChannel("probe");
pc.createOffer().then(o => pc.setLocalDescription(o)).catch(() => {{}});
</script></body></html>"""
    page.set_content(html, wait_until="domcontentloaded", timeout=timeout_ms)
    page.wait_for_timeout(min(8000, timeout_ms))
