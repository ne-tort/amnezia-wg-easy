"""
Architect-style CPS chains for I2–I5 when capture does not fill slots.

Uses only tags supported by amneziawg-go: <b>, <t>, <r>, <rc>, <rd>.
Merged after real capture values in ``merge_collector_output``.
"""

from __future__ import annotations

from typing import Dict

# * Bump when editing ARCHITECT_DEFAULTS below (audit trail for "constants" vs live capture).
ARCHITECT_BUNDLE_VERSION = "3"
ARCHITECT_BUNDLE_DATE = "2026-04-03"

# * Shared STUN-shaped tails (openssl stun / webrtc / browser STUN share merge fallbacks).
_STUN_I2_I5: Dict[str, str] = {
    "i2": "<b 0x010100002112a44200000000000000000000000000000000><rc 8><t><r 32>",
    "i3": "<b 0x0101000c2112a442000000000000000000000000002000080001000000000000><rc 12><t><r 64>",
    "i4": "<b 0x010100142112a4420000000000000000000000000020000800010000000000000000000000000000><rc 16><t><r 80>",
    "i5": "<b 0x010100182112a4420000000000000000000000000020000800010000000000000000000000000000000000><rc 20><t><r 96>",
}

# * Per profile_id: keys i2–i5 (i1 always from collector ``hex``).
ARCHITECT_DEFAULTS: Dict[str, Dict[str, str]] = {
    # * run_all / collectors — full I2–I5; I1 only from live capture (``hex``).
    "dns": {
        "i2": "<b 0xe166010000010000000000000a323430433a3a3636363600001c0001><r 74><t>",
        "i3": "<b 0xcd6f0100000100000000000002373702393102363801380000010001><r 172><t>",
        "i4": "<b 0x8037010000010000000000000236340136023634013600001c0001><r 164><t>",
        "i5": "<b 0x1a41010000010000000000000331393403323432013201330000010001><r 200><t>",
    },
    "quic": {
        "i2": "<b 0xc0000000011449bd04acae2704b7e806d5735d6240e5c74c75e40821e2d1fdec75507c009fc4d662><rc 12><t><r 138>",
        "i3": "<b 0xc2000000010c835d74f46edb155431c1dbf70276240c3eee268dfd5a922fba275cee05e37bf0><rc 20><t><r 100>",
        "i4": "<b 0xc1000000010b3981e65aca96bcd076765e1461fc8f698ea0f4f3f66882ba4451324b51ec5e6700c6d1d174><rc 13><t><r 48>",
        "i5": "<b 0xc2000000011231a946ecdd257a354f4b2144efb7ec8befc30e6bb807e69ac89520101ca6e9328900189ffab4><rc 14><t><r 152>",
    },
    "stun": dict(_STUN_I2_I5),
    "sip": {
        "i2": "<b 0x5245474953544552207369703a7369702e706c69766f2e636f6d2002442f89><rc 53><t><r 20>",
        "i3": "<b 0x5245474953544552207369703a7369702e616e74697369702e636f6d20e8227e58><rc 41><t><r 36>",
        "i4": "<b 0x5245474953544552207369703a7369702e6265656c696e652e7275207052023f><rc 60><t><r 44>",
        "i5": "<b 0x5245474953544552207369703a7369702e736970756e692e636f6d207ed4aa38><rc 34><t><r 20>",
    },
    "webrtc": dict(_STUN_I2_I5),
    "dtls": {
        "i2": "<b 0x16fefd00efef9300e5dd20011001573f2027aa86fefd0000d8c661d398df7e879273ffa5d4e206e9abf74e6aa174d7d6fd421da6f57fcc194ddf3d44><rc 19><t><r 74>",
        "i3": "<b 0x16fefd0040c5d8dc42bee7006701c8f701c7becbfefd000016ceb757d67bfad05bec21acd32488cbc66fb5130856796f1c5619549684f34722f2bf6e><rc 33><t><r 98>",
        "i4": "<b 0x16fefd0047edb108e559bb0088014a9c18b608c7fefd00004e72dbdec95576b062ab205ef87d7698c2c2c176690ffa5ac0595ae983d3c82cde1b8822><rc 17><t><r 100>",
        "i5": "<b 0x16fefd007fec709fb465da00da01e2d3d9ae77d1fefd0000aa487c36b438be49518fcedc303a955d44d8ca1f69945119b5f331bb4ccea7d906f57872><rc 24><t><r 76>",
    },
    "quic_rfc": {
        "i2": "<b 0xc0000000011449bd04acae2704b7e806d5735d6240e5c74c75e40821e2d1fdec75507c009fc4d662><rc 12><t><r 138>",
        "i3": "<b 0xc2000000010c835d74f46edb155431c1dbf70276240c3eee268dfd5a922fba275cee05e37bf0><rc 20><t><r 100>",
        "i4": "<b 0xc1000000010b3981e65aca96bcd076765e1461fc8f698ea0f4f3f66882ba4451324b51ec5e6700c6d1d174><rc 13><t><r 48>",
        "i5": "<b 0xc2000000011231a946ecdd257a354f4b2144efb7ec8befc30e6bb807e69ac89520101ca6e9328900189ffab4><rc 14><t><r 152>",
    },
    "quic_rtt0": {
        "i2": "<b 0xd20000000110f617a8cff7b5a7c3bf92b4ac78a933fa0d7199417cc91bdbb8c0a53f89bc7f3f83f2><t><r 112><rc 18>",
        "i3": "<b 0xd300000001125d07a9edf0ccef067d7afe13d63ed4b058c013d9091fb0b60fe317c94fc6a75d63071387ce57a9eec366><t><r 48><rc 22>",
        "i4": "<b 0xd3000000011145c186870b5ff1ea0a9aac0d4d1d05c514039024a0be56386c><t><r 54><rc 21>",
        "i5": "<b 0xd3000000010b19544d2b46bff2be2d5b20098d2661c172641f7f90d083bc6b><t><r 70><rc 28>",
    },
    "http3": {
        "i2": "<b 0xe20000000113b5942cfbd4fe1abde2a5df261f10d7c82df4aa0d6d7bef5aa1ed2f3928e833273374aa679b><rc 36><r 132><t>",
        "i3": "<b 0xe1000000010f830384d3e1b176de40e97f5cb4b117140b5253c88c2a855de9d4a8d0bfb21275e2cf56142bd5ddb2><rc 25><r 122><t>",
        "i4": "<b 0xe2000000010f31702a1f745b59519e35a188a2d6f000d71addfa><rc 20><r 104><t>",
        "i5": "<b 0xc3000000011461da93a5f257b285d490139ffa047ba2fd5067570ec83730c104944e4fe4f8d088a34b87e3a758><rc 20><r 76><t>",
    },
    "quic_alt_svc": {
        "i2": "<b 0xc00000000114a0280f4f3b6bbbe155ca2a01dc2490951897994e099f84a8ef696de76c470bc13f59255ab6bdce316ec84b15fd8e><rc 17><t><r 90>",
        "i3": "<b 0x6784344d332f738e52f6cfcb15><r 500><t><rc 7><rd 6>",
        "i4": "<b 0x8ca1d68c74d4266306><t><rc 5><r 22><rd 5>",
        "i5": "<rd 8><b 0x9beafab6><rc 12><r 466><t>",
    },
    "quic_burst": {
        "i2": "<b 0xd100000001081dcd238f9e8761a6015f7cea33d7><t><r 76><rc 36>",
        "i3": "<b 0xc10000000112d2c9676a94b1bfdea5fa1e324f715c6657270208a3f954a80e><rc 28><r 82><t>",
        "i4": "<t><r 8><b 0xf4ce1823d4e6fa24188eb3ea87ff><rc 7><rd 8>",
        "i5": "<b 0x31ef9a8b0e9c93c874><t><rc 5><r 408><rd 8>",
    },
    "dns_doh": {
        "i2": "<b 0xe166010000010000000000000a323430433a3a3636363600001c0001><r 74><t>",
        "i3": "<b 0xcd6f0100000100000000000002373702393102363801380000010001><r 172><t>",
        "i4": "<b 0x8037010000010000000000000236340136023634013600001c0001><r 164><t>",
        "i5": "<b 0x1a41010000010000000000000331393403323432013201330000010001><r 200><t>",
    },
    "dtls_webrtc": {
        "i2": "<b 0x16fefd00efef9300e5dd20011001573f2027aa86fefd0000d8c661d398df7e879273ffa5d4e206e9abf74e6aa174d7d6fd421da6f57fcc194ddf3d44><rc 19><t><r 74>",
        "i3": "<b 0x16fefd0040c5d8dc42bee7006701c8f701c7becbfefd000016ceb757d67bfad05bec21acd32488cbc66fb5130856796f1c5619549684f34722f2bf6e><rc 33><t><r 98>",
        "i4": "<b 0x16fefd0047edb108e559bb0088014a9c18b608c7fefd00004e72dbdec95576b062ab205ef87d7698c2c2c176690ffa5ac0595ae983d3c82cde1b8822><rc 17><t><r 100>",
        "i5": "<b 0x16fefd007fec709fb465da00da01e2d3d9ae77d1fefd0000aa487c36b438be49518fcedc303a955d44d8ca1f69945119b5f331bb4ccea7d906f57872><rc 24><t><r 76>",
    },
    "sip_browser": {
        "i2": "<b 0x5245474953544552207369703a7369702e706c69766f2e636f6d2002442f89><rc 53><t><r 20>",
        "i3": "<b 0x5245474953544552207369703a7369702e616e74697369702e636f6d20e8227e58><rc 41><t><r 36>",
        "i4": "<b 0x5245474953544552207369703a7369702e6265656c696e652e7275207052023f><rc 60><t><r 44>",
        "i5": "<b 0x5245474953544552207369703a7369702e736970756e692e636f6d207ed4aa38><rc 34><t><r 20>",
    },
    # * Browser QUIC: I1 from capture only; I2–I5 here when chain shorter than 5 (merge_collector_output).
    "quic_browser": {
        "i2": "<b 0xc0000000011421fb303f533722bcba00d68aad60d8b10e451b3d04ed7d1ca0008832068f><rc 16><t><r 136>",
        "i3": "<b 0xc1000000010913060d199eea2632f30551754f67b113945c58b996268507f24577b192117a8f1fb5ad276c5c38><rc 24><t><r 80>",
        "i4": "<b 0xc20000000108a5effc604907c5f803ec563f0cc32b0d0417fe107c145254ce1c8f90e9><rc 17><t><r 154>",
        "i5": "<b 0xc300000001125a1c4d8a3b17165e82954739914a4d8971e5101896d624e91096bdfdddf999d415646a00df30a199><rc 7><t><r 118>",
    },
    "stun_browser": dict(_STUN_I2_I5),
}
