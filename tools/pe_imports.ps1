param([string]$Path)

$bytes = [System.IO.File]::ReadAllBytes($Path)
$eLfanew = [BitConverter]::ToInt32($bytes, 0x3C)
$numSections = [BitConverter]::ToUInt16($bytes, $eLfanew + 6)
$sizeOfOptHeader = [BitConverter]::ToUInt16($bytes, $eLfanew + 20)
$optHeaderOffset = $eLfanew + 24
$magic = [BitConverter]::ToUInt16($bytes, $optHeaderOffset)
$pe32plus = ($magic -eq 0x20b)
$ddOffset = $optHeaderOffset + $(if ($pe32plus) {112} else {96})
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

$importRva = [BitConverter]::ToUInt32($bytes, $ddOffset + 8)  # directory index 1 = imports
$off = RvaToOffset $importRva
Write-Output "=== Import table ==="
while ($true) {
    $iltRva = [BitConverter]::ToUInt32($bytes, $off)       # OriginalFirstThunk
    $nameRva = [BitConverter]::ToUInt32($bytes, $off + 12)
    $iatRva = [BitConverter]::ToUInt32($bytes, $off + 16)
    if ($iltRva -eq 0 -and $nameRva -eq 0) { break }
    $nameOff = RvaToOffset $nameRva
    $end = $nameOff; while ($bytes[$end] -ne 0) { $end++ }
    $dllName = [System.Text.Encoding]::ASCII.GetString($bytes, $nameOff, $end - $nameOff)

    $thunkRva = $(if ($iltRva -ne 0) { $iltRva } else { $iatRva })
    $thunkOff = RvaToOffset $thunkRva
    $funcs = @()
    $idx = 0
    while ($true) {
        $entry = [BitConverter]::ToUInt32($bytes, $thunkOff + $idx * 4)
        if ($entry -eq 0) { break }
        if (($entry -band 0x80000000) -eq 0) {
            $hintOff = RvaToOffset $entry
            $e2 = $hintOff + 2; while ($bytes[$e2] -ne 0) { $e2++ }
            $funcs += [System.Text.Encoding]::ASCII.GetString($bytes, $hintOff + 2, $e2 - $hintOff - 2)
        } else {
            $funcs += ("#" + ($entry -band 0xFFFF))
        }
        $idx++
    }
    Write-Output ("{0}: {1}" -f $dllName, ($funcs -join ", "))
    $off += 20
}
