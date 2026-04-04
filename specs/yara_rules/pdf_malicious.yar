/*
  YARA Kuralları — Yüksek Güvenirlikli PDF Zararlı Tespit
  Kesin tehdit göstergelerini hedefler.
*/

rule PDF_Launch_PowerShell {
    meta:
        description = "PDF /Launch + PowerShell komutu — Kritik"
        author = "SussyPDF"
        severity = "critical"
        score = 100
        mitre = "T1059.001"

    strings:
        $launch = "/Launch" nocase
        $ps1 = "powershell" nocase
        $ps2 = "pwsh" nocase
        $cmd = "cmd.exe" nocase

    condition:
        uint32(0) == 0x46445025 and $launch and ($ps1 or $ps2 or $cmd)
}

rule PDF_OpenAction_JavaScript {
    meta:
        description = "PDF /OpenAction + /JavaScript — Otomatik JS tetikleme"
        author = "SussyPDF"
        severity = "critical"
        score = 90
        mitre = "T1059.007"

    strings:
        $open = "/OpenAction" nocase
        $js1 = "/JS" nocase
        $js2 = "/JavaScript" nocase

    condition:
        uint32(0) == 0x46445025 and $open and ($js1 or $js2)
}

rule PDF_Heap_Spray {
    meta:
        description = "PDF JavaScript Heap Spray kalıbı"
        author = "SussyPDF"
        severity = "critical"
        score = 95
        mitre = "T1203"

    strings:
        $nop = "%u9090%u9090"
        $spray1 = "spray" nocase
        $spray2 = "slideSize" nocase
        $spray3 = "heapSpray" nocase
        $js = "/JavaScript" nocase

    condition:
        uint32(0) == 0x46445025 and $js and ($nop or $spray1 or $spray2 or $spray3)
}

rule PDF_Embedded_Executable {
    meta:
        description = "PDF içinde gömülü PE/EXE dosyası"
        author = "SussyPDF"
        severity = "critical"
        score = 100
        mitre = "T1027.006"

    strings:
        $mz = { 4D 5A }
        $embed = "/EmbeddedFiles" nocase
        $pe = "This program cannot be run in DOS mode"

    condition:
        uint32(0) == 0x46445025 and $embed and ($mz or $pe)
}

rule PDF_ADODB_Download_Execute {
    meta:
        description = "ADODB.Stream ile dosya indirme ve çalıştırma"
        author = "SussyPDF"
        severity = "critical"
        score = 95
        mitre = "T1105"

    strings:
        $adodb = "ADODB.Stream" nocase
        $wscript = "WScript.Shell" nocase
        $xmlhttp = "XMLHTTP" nocase
        $save = "SaveToFile" nocase
        $run = ".Run" nocase

    condition:
        uint32(0) == 0x46445025 and $adodb and $save and ($wscript or $run or $xmlhttp)
}
