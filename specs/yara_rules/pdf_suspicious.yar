/*
  YARA Kuralları — Orta Güvenirlikli PDF Şüpheli Tespit
*/

rule PDF_Suspicious_JavaScript {
    meta:
        description = "PDF içinde JavaScript kodu (tek başına)"
        author = "SussyPDF"
        severity = "medium"
        score = 40
        mitre = "T1059.007"

    strings:
        $js1 = "/JS" nocase
        $js2 = "/JavaScript" nocase

    condition:
        uint32(0) == 0x46445025 and ($js1 or $js2)
}

rule PDF_Multiple_EOF {
    meta:
        description = "Birden fazla %%EOF — Artımlı güncelleme veya Shadow Attack"
        author = "SussyPDF"
        severity = "medium"
        score = 35
        mitre = "T1027"

    strings:
        $eof = "%%EOF"

    condition:
        uint32(0) == 0x46445025 and #eof > 1
}

rule PDF_EmbeddedFiles {
    meta:
        description = "PDF içinde gömülü dosyalar"
        author = "SussyPDF"
        severity = "medium"
        score = 30

    strings:
        $embed = "/EmbeddedFiles" nocase

    condition:
        uint32(0) == 0x46445025 and $embed
}

rule PDF_XFA_Form {
    meta:
        description = "XFA form — XML parsing zafiyeti riski"
        author = "SussyPDF"
        severity = "medium"
        score = 25

    strings:
        $xfa = "/XFA" nocase

    condition:
        uint32(0) == 0x46445025 and $xfa
}

rule PDF_Flash_Content {
    meta:
        description = "Flash (SWF) içeriği — EOL teknoloji"
        author = "SussyPDF"
        severity = "medium"
        score = 35

    strings:
        $rich = "/RichMedia" nocase
        $swf = { 46 57 53 }
        $cws = { 43 57 53 }

    condition:
        uint32(0) == 0x46445025 and ($rich or $swf or $cws)
}

rule PDF_Anti_Analysis {
    meta:
        description = "Anti-analiz teknikleri tespit edildi"
        author = "SussyPDF"
        severity = "medium"
        score = 30

    strings:
        $vm1 = "VMware" nocase
        $vm2 = "VirtualBox" nocase
        $sb1 = "SbieDll" nocase
        $dbg1 = "IsDebuggerPresent" nocase
        $dbg2 = "NtQueryInformationProcess" nocase

    condition:
        uint32(0) == 0x46445025 and any of them
}
