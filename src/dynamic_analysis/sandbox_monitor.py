"""
sandbox_monitor.py — Sandbox Davranış İzleme ve Anti-Evasion

Sandbox analiz sonuçlarını raporlar ve
Anti-VM/Anti-Sandbox rutinlerini tespit eder.
"""

import re
from dataclasses import dataclass, field


@dataclass
class SandboxResult:
    dns_queries: list[str] = field(default_factory=list)
    http_requests: list[dict] = field(default_factory=list)
    file_changes: list[dict] = field(default_factory=list)
    process_created: list[str] = field(default_factory=list)
    registry_changes: list[str] = field(default_factory=list)
    anti_vm_detected: list[str] = field(default_factory=list)
    anti_sandbox_detected: list[str] = field(default_factory=list)
    evasion_score: int = 0


# Anti-VM string göstergeleri
ANTI_VM_STRINGS = [
    "VMware", "VirtualBox", "VBOX", "QEMU", "Hyper-V", "Xen",
    "Virtual HD", "VMDK", "vmtoolsd", "vm3dservice",
    "vboxservice", "vboxtray", "vmwaretray", "vmwareuser",
    "VBoxMouse", "VBoxGuest", "VBoxSF", "VBoxVideo",
]

ANTI_SANDBOX_STRINGS = [
    "SbieDll", "sandboxie", "cuckoomon", "dbghelp",
    "wireshark", "fiddler", "procmon", "procexp",
    "ollydbg", "x64dbg", "ida", "ghidra",
    "GetCursorPos", "GetLastInputInfo", "GetTickCount",
    "NtQueryInformationProcess", "IsDebuggerPresent",
    "OutputDebugString", "CheckRemoteDebuggerPresent",
]

ANTI_VM_REGISTRY_KEYS = [
    r"HKLM\SOFTWARE\VMware",
    r"HKLM\SOFTWARE\Oracle\VirtualBox",
    r"HKLM\SYSTEM\CurrentControlSet\Services\VBoxGuest",
    r"HKLM\HARDWARE\Description\System\BIOS\SystemManufacturer",
]


class SandboxMonitor:
    """Sandbox davranış izleme ve Anti-Evasion motoru."""

    def analyze_code_for_evasion(self, code: str) -> SandboxResult:
        """Koddaki Anti-VM ve Anti-Sandbox rutinlerini tespit et."""
        result = SandboxResult()

        # Anti-VM string tespiti
        for indicator in ANTI_VM_STRINGS:
            if indicator.lower() in code.lower():
                result.anti_vm_detected.append(
                    f"Anti-VM göstergesi: '{indicator}' referansı bulundu"
                )

        # Anti-Sandbox string tespiti
        for indicator in ANTI_SANDBOX_STRINGS:
            if indicator.lower() in code.lower():
                result.anti_sandbox_detected.append(
                    f"Anti-Sandbox göstergesi: '{indicator}' referansı bulundu"
                )

        # Anti-VM registry kontrolü
        for key in ANTI_VM_REGISTRY_KEYS:
            if key.lower().replace("\\", "/") in code.lower().replace("\\", "/"):
                result.anti_vm_detected.append(f"VM registry sorgusu: {key}")

        # Zamanlama kontrolü (timing check)
        timing_patterns = [
            (r"(?i)GetTickCount\s*\(\s*\)", "GetTickCount zamanlama kontrolü"),
            (r"(?i)Date\.now\s*\(\s*\)", "Date.now zamanlama kontrolü"),
            (r"(?i)performance\.now", "performance.now zamanlama kontrolü"),
            (r"(?i)setTimeout\s*\(\s*.*\s*,\s*(\d{4,})", "Uzun setTimeout gecikmesi"),
        ]
        for pattern, desc in timing_patterns:
            if re.search(pattern, code):
                result.anti_sandbox_detected.append(f"Kaçınma tekniği: {desc}")

        # Fare hareketi kontrolü
        if re.search(r"(?i)GetCursorPos|MouseMove|onmousemove", code):
            result.anti_sandbox_detected.append(
                "Fare hareketi kontrolü — sandbox'ta fare hareket etmez"
            )

        # Evasion skoru
        result.evasion_score = (
            len(result.anti_vm_detected) * 15
            + len(result.anti_sandbox_detected) * 10
        )

        # URL/domain çıkarma
        result.dns_queries = list(set(
            re.findall(r"\b([\w-]+\.(?:com|net|org|ru|cn|tk|xyz))\b", code)
        ))
        result.http_requests = [
            {"url": url}
            for url in re.findall(r"https?://[^\s\"'<>]+", code)
        ]

        return result

    def generate_anti_evasion_profile(self) -> dict:
        """
        VM'i 'süslemek' için sahte ortam profili üret.
        Zararlı yazılımın Anti-VM rutinlerini savuşturmak için kullanılır.
        """
        return {
            "hardware": {
                "system_manufacturer": "Dell Inc.",
                "system_product": "OptiPlex 7090",
                "bios_vendor": "Dell Inc.",
                "processor": "Intel(R) Core(TM) i7-11700 @ 2.50GHz",
                "memory_gb": 16,
                "disk_model": "Samsung SSD 970 EVO Plus 1TB",
            },
            "software": {
                "os": "Windows 10 Pro 22H2",
                "browser": "Google Chrome 120.0.6099.130",
                "office": "Microsoft Office Professional Plus 2021",
                "recent_documents": [
                    "Q4_2024_Report.docx",
                    "Budget_Planning.xlsx",
                    "Team_Photo_2024.jpg",
                ],
            },
            "network": {
                "hostname": "DESKTOP-A7B3C9F",
                "domain": "contoso.local",
                "dns_servers": ["10.0.0.1", "8.8.8.8"],
            },
            "browser_history": [
                "https://www.google.com",
                "https://outlook.office.com",
                "https://www.linkedin.com",
                "https://www.amazon.com",
            ],
        }
