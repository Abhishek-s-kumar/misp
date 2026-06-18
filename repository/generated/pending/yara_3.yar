rule test_misp_connection {
    meta:
        description = "Test rule from MISP pipeline"
    strings:
        $a = "powershell.exe" nocase
    condition:
        $a
}