param([string]$Path = "C:\Users\<user>\.zcode\workspace\default\atrust-analysis\aTrustHelper.dll")

# Offline replication of atrust_debug_patch_v2 ScanForSites: verify the two
# byte signatures locate the patch sites uniquely.
$bytes = [System.IO.File]::ReadAllBytes($Path)
if (-not $bytes) { Write-Output 'READ FAILED'; exit 1 }
$eLfanew = [BitConverter]::ToInt32($bytes, 0x3C)
$numSections = [BitConverter]::ToUInt16($bytes, $eLfanew + 6)
$szOpt = [BitConverter]::ToUInt16($bytes, $eLfanew + 20)
$secTab = $eLfanew + 24 + $szOpt

$textOff = 0; $textRva = 0; $textSize = 0
for ($i = 0; $i -lt $numSections; $i++) {
    $name = [System.Text.Encoding]::ASCII.GetString($bytes, $secTab + $i * 40, 8).TrimEnd([char]0)
    if ($name -eq '.text') {
        $textSize = [BitConverter]::ToUInt32($bytes, $secTab + $i * 40 + 8)
        $textRva  = [BitConverter]::ToUInt32($bytes, $secTab + $i * 40 + 12)
        $textOff  = [BitConverter]::ToUInt32($bytes, $secTab + $i * 40 + 20)
        break
    }
}
Write-Output (".text RVA=0x{0:X} size=0x{1:X} fileoff=0x{2:X}" -f $textRva, $textSize, $textOff)

$patA = [byte[]](0xC7,0x45,0xF8,0x00,0x00,0x02,0x00,0x33,0xC0,0x89)
$patB = [byte[]](0x00,0x00,0x03,0x00,0x33,0xC0,0x89)
$aSites = @()
for ($i = 0; $i -le ($textSize - $patA.Length); $i++) {
    $m = $true
    for ($k = 0; $k -lt $patA.Length; $k++) { if ($bytes[$textOff + $i + $k] -ne $patA[$k]) { $m = $false; break } }
    if ($m) { $aSites += ($textRva + $i + 5) }
}
$bSites = @()
for ($i = 0; $i -le ($textSize - 13); $i++) {
    if ($bytes[$textOff + $i] -ne 0xC7 -or $bytes[$textOff + $i + 1] -ne 0x85) { continue }
    $m = $true
    for ($k = 0; $k -lt $patB.Length; $k++) { if ($bytes[$textOff + $i + 6 + $k] -ne $patB[$k]) { $m = $false; break } }
    if ($m) { $bSites += ($textRva + $i + 8) }
}
Write-Output ("Pattern A (02) sites : " + (($aSites | ForEach-Object { '0x{0:X}' -f $_ }) -join ', '))
Write-Output ("Pattern B (03) sites : " + (($bSites | ForEach-Object { '0x{0:X}' -f $_ }) -join ', '))
$ok = ($aSites.Count -eq 1 -and $bSites.Count -eq 1 -and $aSites[0] -eq 0x3EB87 -and $bSites[0] -eq 0x3EBFA)
if ($ok) { Write-Output 'VALIDATION OK: unique hits 0x3EB87 / 0x3EBFA' } else { Write-Output 'VALIDATION MISMATCH!' }
