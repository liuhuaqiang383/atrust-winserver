param([string]$Path)

$bytes = [System.IO.File]::ReadAllBytes($Path)
$eLfanew = [BitConverter]::ToInt32($bytes, 0x3C)
$peSig = [BitConverter]::ToInt32($bytes, $eLfanew)
if ($peSig -ne 0x00004550) { Write-Error "Not a PE file"; exit 1 }

$machine = [BitConverter]::ToUInt16($bytes, $eLfanew + 4)
$machineName = switch ($machine) { 0x14c {"x86"} 0x8664 {"x64"} 0xAA64 {"arm64"} default { "0x{0:X}" -f $machine } }
Write-Output ("Machine: " + $machineName)

$optHeaderOffset = $eLfanew + 24
$magic = [BitConverter]::ToUInt16($bytes, $optHeaderOffset)
$pe32plus = ($magic -eq 0x20b)
Write-Output ("OptionalHeaderMagic: 0x{0:X} ({1})" -f $magic, $(if ($pe32plus) {"PE32+"} else {"PE32"}))

# Data directory: PE32 at opt+96, PE32+ at opt+112. Export dir is index 0.
$ddOffset = $optHeaderOffset + $(if ($pe32plus) {112} else {96})
$exportRva = [BitConverter]::ToUInt32($bytes, $ddOffset)
$exportSize = [BitConverter]::ToUInt32($bytes, $ddOffset + 4)
Write-Output ("ExportDir RVA: 0x{0:X} size {1}" -f $exportRva, $exportSize)
if ($exportRva -eq 0) { Write-Output "No exports"; exit 0 }

# Sections start after optional header. NumberOfSections at eLfanew+6, SizeOfOptionalHeader at eLfanew+20.
$numSections = [BitConverter]::ToUInt16($bytes, $eLfanew + 6)
$sizeOfOptHeader = [BitConverter]::ToUInt16($bytes, $eLfanew + 20)
$sectionsOffset = $optHeaderOffset + $sizeOfOptHeader

function RvaToOffset([uint32]$rva) {
    for ($i = 0; $i -lt $numSections; $i++) {
        $sec = $sectionsOffset + $i * 40
        $virtualSize = [BitConverter]::ToUInt32($bytes, $sec + 8)
        $virtualAddress = [BitConverter]::ToUInt32($bytes, $sec + 12)
        $rawSize = [BitConverter]::ToUInt32($bytes, $sec + 16)
        $rawPointer = [BitConverter]::ToUInt32($bytes, $sec + 20)
        $span = [Math]::Max($virtualSize, $rawSize)
        if ($rva -ge $virtualAddress -and $rva -lt ($virtualAddress + $span)) {
            return [int]($rva - $virtualAddress + $rawPointer)
        }
    }
    return -1
}

$exportOffset = RvaToOffset $exportRva
if ($exportOffset -lt 0) { Write-Error "Export RVA not mappable"; exit 1 }

$numNames = [BitConverter]::ToUInt32($bytes, $exportOffset + 24)
$addrOfNamesRva = [BitConverter]::ToUInt32($bytes, $exportOffset + 32)
$namesOffset = RvaToOffset $addrOfNamesRva

Write-Output ("Exported names ({0}):" -f $numNames)
for ($i = 0; $i -lt $numNames; $i++) {
    $nameRva = [BitConverter]::ToUInt32($bytes, $namesOffset + $i * 4)
    $nameOff = RvaToOffset $nameRva
    $end = $nameOff
    while ($bytes[$end] -ne 0) { $end++ }
    $name = [System.Text.Encoding]::ASCII.GetString($bytes, $nameOff, $end - $nameOff)
    Write-Output ("  " + $name)
}
