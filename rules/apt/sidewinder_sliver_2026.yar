rule APT_SideWinder_Sliver_2026 {
    meta:
        description = "Detects SideWinder Sliver-based stager mimicking Pakistan Code domains"
        author = "Chamod Lakshitha"
        hash = "df3e59bc863c4fb92461daf5b2c3f3b28af9be4c220687c9c5df78c2598c1b30"
        date = "2026-04-08"

    strings:
        $c2_url = "https://cdn1.pakistancode.com:8443/favicon.ico" ascii wide
        $orig_name = "sliver.exe" ascii wide
        $guid = "b7a842cd-eeb2-4e88-a5c7-7b2b864e8ca9" ascii wide
        $f1 = "HexStringToBytes" ascii
        $f2 = "xord" ascii
        $f3 = "aesd" ascii
        $f4 = "GetShellCode" ascii
        $s1 = "TotalPhysicalMemory" ascii wide
        $s2 = "Win32_ComputerSystem" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        (
            $c2_url or 
            $guid or 
            $orig_name or 
            (3 of ($f*)) or
            (all of ($s*))
        )
}
