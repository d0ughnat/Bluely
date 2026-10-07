rule HighConfidence_EICAR_Test_File
{
    meta:
        description = "Standard EICAR antivirus test string; not real malware"
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        $eicar
}

rule Suspicious_Shell_Download_Execute
{
    meta:
        description = "Shell download-and-execute pattern; review context before acting"
    strings:
        $curl = /curl[ \t]+[^\n]{0,180}[|][ \t]*(sh|bash)/ nocase
        $wget = /wget[ \t]+[^\n]{0,180}[|][ \t]*(sh|bash)/ nocase
    condition:
        filesize < 1048576 and any of them
}
