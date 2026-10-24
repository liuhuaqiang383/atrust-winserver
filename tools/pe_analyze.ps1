param(
    [string]$Path,
    [string[]]$Functions = @("isWinServer", "isSupportOS", "isWin10orGreater"),
    [int]$MaxBytes = 400
)

$bytes = [System.IO.File]::ReadAllBytes($Path)
$eLfanew = [BitConverter]::ToInt32($bytes, 0x3C)
$numSections = [BitConverter]::ToUInt16($bytes, $eLfanew + 6)
$sizeOfOptHeader = [BitConverter]::ToUInt16($bytes, $eLfanew + 20)
$optHeaderOffset = $eLfanew + 24
$magic = [BitConverter]::ToUInt16($bytes, $optHeaderOffset)
$pe32plus = ($magic -eq 0x20b)
$ddOffset = $optHeaderOffset + $(if ($pe32plus) {112} else {96})
$sectionsOffset = $optHeaderOffset + $sizeOfOptHeader
$imageBase = [BitConverter]::ToUInt32($bytes, $optHeaderOffset + 28)  # PE32 only

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

# --- Build IAT map: slot RVA -> "dll!func" ---
$importRva = [BitConverter]::ToUInt32($bytes, $ddOffset + 8)
$off = RvaToOffset $importRva
$iatMap = @{}
while ($true) {
    $iltRva = [BitConverter]::ToUInt32($bytes, $off)
    $nameRva = [BitConverter]::ToUInt32($bytes, $off + 12)
    $iatRva = [BitConverter]::ToUInt32($bytes, $off + 16)
    if ($iltRva -eq 0 -and $nameRva -eq 0) { break }
    $nameOff = RvaToOffset $nameRva
    $end = $nameOff; while ($bytes[$end] -ne 0) { $end++ }
    $dllName = [System.Text.Encoding]::ASCII.GetString($bytes, $nameOff, $end - $nameOff)
    $thunkRva = $(if ($iltRva -ne 0) { $iltRva } else { $iatRva })
    $thunkOff = RvaToOffset $thunkRva
    $iatOff = RvaToOffset $iatRva
    $idx = 0
    while ($true) {
        $entry = [BitConverter]::ToUInt32($bytes, $thunkOff + $idx * 4)
        if ($entry -eq 0) { break }
        $funcName = $null
        if (($entry -band 0x80000000) -eq 0) {
            $hintOff = RvaToOffset $entry
            $e2 = $hintOff + 2; while ($bytes[$e2] -ne 0) { $e2++ }
            $funcName = [System.Text.Encoding]::ASCII.GetString($bytes, $hintOff + 2, $e2 - $hintOff - 2)
        } else { $funcName = ("#" + ($entry -band 0xFFFF)) }
        $iatMap[[uint32]($iatRva + $idx * 4)] = "$dllName!$funcName"
        $idx++
    }
    $off += 20
}

# --- Exports: name -> RVA ---
$exportRva = [BitConverter]::ToUInt32($bytes, $ddOffset)
$exportOffset = RvaToOffset $exportRva
$numNames = [BitConverter]::ToUInt32($bytes, $exportOffset + 24)
$addrOfNamesRva = [BitConverter]::ToUInt32($bytes, $exportOffset + 32)
$addrOfFunctionsRva = [BitConverter]::ToUInt32($bytes, $exportOffset + 28)
$addrOfNameOrdsRva = [BitConverter]::ToUInt32($bytes, $exportOffset + 36)
$namesOffset = RvaToOffset $addrOfNamesRva
$funcsOffset = RvaToOffset $addrOfFunctionsRva
$ordsOffset = RvaToOffset $addrOfNameOrdsRva
$exportMap = @{}   # name -> RVA
$exportList = @()  # sorted by RVA: @{rva;name}
for ($i = 0; $i -lt $numNames; $i++) {
    $nameRva = [BitConverter]::ToUInt32($bytes, $namesOffset + $i * 4)
    $nameOff = RvaToOffset $nameRva
    $e3 = $nameOff; while ($bytes[$e3] -ne 0) { $e3++ }
    $name = [System.Text.Encoding]::ASCII.GetString($bytes, $nameOff, $e3 - $nameOff)
    $ord = [BitConverter]::ToUInt16($bytes, $ordsOffset + $i * 2)
    $frva = [BitConverter]::ToUInt32($bytes, $funcsOffset + $ord * 4)
    $exportMap[$name] = $frva
    $exportList += [pscustomobject]@{Rva = $frva; Name = $name}
}
$exportSorted = $exportList | Sort-Object Rva

Write-Output ("ImageBase: 0x{0:X}" -f $imageBase)

# --- For each requested function: dump bytes + annotate call [iat] patterns ---
foreach ($fname in $Functions) {
    if (-not $exportMap.Contains($fname)) { Write-Output "!! export $fname not found"; continue }
    $frva = $exportMap[$fname]
    # function end = next export RVA (rough bound)
    $nextRva = ($exportSorted | Where-Object { $_.Rva -gt $frva } | Select-Object -First 1).Rva
    if (-not $nextRva) { $nextRva = $frva + $MaxBytes }
    $span = [Math]::Min($nextRva - $frva, $MaxBytes)
    $start = RvaToOffset $frva
    Write-Output ""
    Write-Output ("==== {0}  RVA 0x{1:X}  VA 0x{2:X}  len~{3} ====" -f $fname, $frva, ($imageBase + $frva), $span)

    # scan for FF 15 disp32 (call [addr]) and FF 25 (jmp [addr]) patterns
    for ($i = 0; $i -lt ($span - 6); $i++) {
        if ($bytes[$start + $i] -eq 0xFF -and ($bytes[$start + $i + 1] -eq 0x15 -or $bytes[$start + $i + 1] -eq 0x25)) {
            $target = [BitConverter]::ToUInt32($bytes, $start + $i + 2)
            $kind = $(if ($bytes[$start + $i + 1] -eq 0x15) {"call"} else {"jmp "})
            $imp = $iatMap[[uint32]$target]
            if ($imp) {
                Write-Output ("  +0x{0:X3} (RVA 0x{1:X})  {2} [{3}] -> {4}" -f $i, ($frva + $i), $kind, ("0x{0:X}" -f $target), $imp)
            }
        }
    }

    # hexdump first 160 bytes
    $dumpLen = [Math]::Min($span, 160)
    for ($row = 0; $row -lt $dumpLen; $row += 16) {
        $hex = ""
        $ascii = ""
        for ($c = 0; ($c -lt 16) -and (($row + $c) -lt $dumpLen); $c++) {
            $b = $bytes[$start + $row + $c]
            $hex += ("{0:X2} " -f $b)
            if ($b -ge 32 -and $b -le 126) { $ascii += [char]$b } else { $ascii += "." }
        }
        Write-Output ("  {0:X8}  {1,-48} {2}" -f ($imageBase + $frva + $row), $hex, $ascii)
    }
}
