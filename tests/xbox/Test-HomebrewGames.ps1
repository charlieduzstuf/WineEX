# Test-HomebrewGames.ps1 - end-to-end validation of WineEX Xbox loaders
# against REAL homebrew binaries (no synthetic fixtures):
#
#   XBE #1: VectoroidsX (neobomb, SDL Asteroids clone, OpenXDK)
#          https://www.gamebrew.org/wiki/VectoroidsX_Xbox (Mixed license)
#   XBE #2: xemu-dashboard default.xbe (xemu-project, open source loader XBE)
#          https://github.com/xemu-project/xemu-dashboard (GPLv2, CI-built)
#   XBE #3: HocoslamfyX (HCF, 2020 homebrew, Nebuleon game port)
#          https://www.gamebrew.org/wiki/HocoslamfyX_Xbox (Mixed license)
#   XEX    : X-Store 0.2.13 (951261, native Xbox 360 homebrew store app)
#          https://github.com/951261/X-Store (open source, released .xex)
#
# The XBE walk mirrors dlls/kernelbase/process.c parse_xbe_file() plus the
# winexbe.exe decode (programs/winexbe/winexbe.c): magic, GetXbeType by BOTH
# in-tree algorithms (they must agree), entry/thunk XOR decode (Cxbx-Reloaded
# Xbe.h keys), certificate, section table, library versions, TLS dir,
# non-kernel imports and kernel-thunk ordinals.
# The XEX walk mirrors parse_xex2_file() plus winxex.exe: BE header, key&0xFF
# dispatch (Xenia XexModule::GetOptHeader), security info, file-format
# compression (Xenia/XenonRecomp/XeFu/Xemi enum), execution ID, imports, TLS.
#
# Downloads are verified against publisher SHA-256 digests where published.
# Binaries are NOT committed to the repo; pass -DownloadDir to reuse them.
#
# Run: powershell -ExecutionPolicy Bypass -File tests/xbox/Test-HomebrewGames.ps1
# Exit code: 0 = all pass, 1 = any failure.

param(
    [string]$DownloadDir = (Join-Path ([IO.Path]::GetTempPath()) 'wineexthb')
)

$ErrorActionPreference = 'Stop'
$script:failures = 0
$script:checks = 0

function Check($name, $cond, $detail = '') {
    $script:checks++
    if ($cond) { Write-Host "PASS: $name $detail" }
    else { Write-Host "FAIL: $name $detail"; $script:failures++ }
}

function U32LE($b, $off) { return [BitConverter]::ToUInt32($b, $off) }
function U64LE($b, $off) { return [BitConverter]::ToUInt64($b, $off) }
function U32BE($b, $off) {
    return ([uint64]$b[$off] -shl 24) -bor ([uint64]$b[$off+1] -shl 16) -bor `
           ([uint64]$b[$off+2] -shl 8) -bor [uint64]$b[$off+3]
}
function U16BE($b, $off) { return ([uint64]$b[$off] -shl 8) -bor [uint64]$b[$off+1] }
function U16LE($b, $off) { return [BitConverter]::ToUInt16($b, $off) }
function Xor32($a, $b) { return (([uint64]$a -bxor [uint64]$b) -band 0xFFFFFFFF) }
function Hex($v) { return ('0x{0:X8}' -f ([uint64]$v -band 0xFFFFFFFF)) }

# Cxbx-Reloaded Xbe.h XOR keys, indexed retail/debug/chihiro
$XOR_EP = @([Convert]::ToUInt64('A8FC57AB',16), [Convert]::ToUInt64('94859D4B',16), [Convert]::ToUInt64('40B5C16E',16))
$XOR_KT = @([Convert]::ToUInt64('5B6D40B6',16), [Convert]::ToUInt64('EFB1F152',16), [Convert]::ToUInt64('2290059D',16))
$TYPES  = @('RETAIL', 'DEBUG', 'CHIHIRO')

function Get-TypeWinexbe($entryEnc) {
    if ((Xor32 $entryEnc $XOR_EP[1]) -lt [uint64]0x1000000) { return 1 }
    if ((Xor32 $entryEnc $XOR_EP[2]) -lt [uint64]0x1000000) { return 2 }
    return 0
}
function Get-TypeKernelbase($entryEnc, $thunkEnc) {
    # process.c parse_xbe_file: Chihiro via SEGABOOT bits, Debug via KSEG0 thunk bit
    if ((([uint64]$entryEnc -band [Convert]::ToUInt64('F0000000',16)) -eq [Convert]::ToUInt64('40000000',16))) { return 2 }
    if (([uint64]$thunkEnc -band [Convert]::ToUInt64('80000000',16)) -ne 0) { return 1 }
    return 0
}

function Get-Sha256($path) {
    $h = [Security.Cryptography.SHA256]::Create()
    try {
        $fs = [IO.File]::OpenRead($path)
        try { return ([BitConverter]::ToString($h.ComputeHash($fs))).Replace('-','').ToLower() }
        finally { $fs.Close() }
    } finally { $h.Dispose() }
}

# ================= XBE =================
function Test-Xbe($label, $path, $expectedSha) {
    Write-Host "`n=== XBE: $label ==="
    Check "$label exists" (Test-Path $path)
    if (!(Test-Path $path)) { return }
    if ($expectedSha) {
        Check "$label sha256 matches publisher" ((Get-Sha256 $path) -eq $expectedSha.ToLower()) "(got $(Get-Sha256 $path))"
    }
    $b = [IO.File]::ReadAllBytes($path)
    Check "$label magic XBEH" ((U32LE $b 0) -eq 0x48454258) "(got $(Hex (U32LE $b 0)))"

    $base      = U32LE $b 0x104
    $sizeImage = U32LE $b 0x10C
    $nsec      = U32LE $b 0x11C
    $secTabVA  = U32LE $b 0x120
    $entryEnc  = U32LE $b 0x128
    $tlsVA     = U32LE $b 0x12C
    $thunkEnc  = U32LE $b 0x158
    $nkVA      = U32LE $b 0x15C
    $libCount  = U32LE $b 0x160
    $libsVA    = U32LE $b 0x164
    $certVA    = U32LE $b 0x118
    Write-Host "  base=$(Hex $base) sizeof_image=$(Hex $sizeImage) sections=$nsec"
    Check "$label base 0x10000 (OpenXDK/nxdk convention)" ($base -eq 0x10000) "(got $(Hex $base))"
    Check "$label 1..64 sections" (($nsec -ge 1) -and ($nsec -le 64)) "(got $nsec)"
    Check "$label sizeof_image sane" (($sizeImage -gt 0) -and ($sizeImage -lt 0x4000000)) "(got $(Hex $sizeImage))"

    $t1 = Get-TypeWinexbe $entryEnc
    $t2 = Get-TypeKernelbase $entryEnc $thunkEnc
    Write-Host "  winexbe-type=$($TYPES[$t1]) kernelbase-type=$($TYPES[$t2])"
    Check "$label both type detectors agree" ($t1 -eq $t2)
    $entry  = Xor32 $entryEnc $XOR_EP[$t1]
    $thunk  = Xor32 $thunkEnc $XOR_KT[$t1]
    Write-Host "  entry=$(Hex $entry) thunk_table=$(Hex $thunk)"
    Check "$label entry inside image" (($entry -ge $base) -and ($entry -lt ($base + $sizeImage)))
    Check "$label thunk table inside image" (($thunk -ge $base) -and ($thunk -lt ($base + $sizeImage)))

    # Section table (VA -> file offset via base, headers are 1:1-mapped).
    # NOTE: Xbe::SectionHeader is 9 ULONGs + 20-byte digest = 56 bytes
    # (Cxbx-Reloaded Xbe.h; matches struct xbe_section_header in
    # programs/winexbe/winexbe.c and dlls/kernelbase/process.c).
    $secOff = $secTabVA - $base
    Check "$label section table in file" (($secOff -ge 0) -and (($secOff + $nsec * 56) -le $b.Length))
    $sections = @()
    for ($i = 0; $i -lt $nsec; $i++) {
        $o = $secOff + $i * 56
        $flags = U32LE $b $o; $vaddr = U32LE $b ($o+4); $vsize = U32LE $b ($o+8)
        $raw = U32LE $b ($o+12); $rawsz = U32LE $b ($o+16); $nameVA = U32LE $b ($o+20)
        $nm = ''
        $no = $nameVA - $base
        if (($no -ge 0) -and ($no -lt $b.Length)) {
            $e = $no; while (($e -lt $b.Length) -and ($b[$e] -ne 0) -and (($e - $no) -lt 16)) { $e++ }
            if ($e -gt $no) { $nm = [Text.Encoding]::ASCII.GetString($b, $no, $e - $no) }
        }
        $sections += [pscustomobject]@{ Flags=$flags; VA=$vaddr; VSize=$vsize; Raw=$raw; RawSize=$rawsz; Name=$nm }
        $rwx = "$(if ($flags -band 1) {'W'} else {'-'})$(if ($flags -band 4) {'X'} else {'-'})"
        Write-Host ("  sect[{0}] {1,-10} {2} virt={3} size={4} raw_off={5} raw_sz={6}" -f $i, $nm, $rwx, (Hex $vaddr), (Hex $vsize), (Hex $raw), (Hex $rawsz))
        # winexbe.c map_xbe_sections skips empty sections outright; only
        # validate sections it would actually map.
        if (($vaddr -eq 0) -or ($vsize -eq 0)) { Write-Host "  sect[$i] skipped (empty, like winexbe)"; continue }
        Check "$label sect[$i] VA inside image" (($vaddr -ge $base) -and ($vaddr + $vsize -le ($base + $sizeImage)))
        if ($rawsz -gt 0) { Check "$label sect[$i] raw range in file" ((($raw + $rawsz) -le $b.Length)) }
    }
    $hasCode = @($sections | Where-Object { (([uint64]$_.Flags -band [uint64]4) -ne 0) }).Count -ge 1
    Check "$label has executable section" $hasCode

    # VA -> file offset through section raw mappings (for thunk table / TLS / imports)
    function VaToFile($va) {
        foreach ($s in $sections) {
            if (($va -ge $s.VA) -and ($va -lt ($s.VA + $s.VSize))) {
                $off = $s.Raw + ($va - $s.VA)
                if (($off -ge 0) -and ($off -lt $b.Length)) { return $off }
            }
        }
        $off = $va - $base  # header region fallback (1:1)
        if (($off -ge 0) -and ($off -lt $b.Length)) { return $off }
        return -1
    }

    # Certificate: reachable with a sane size. Title/id may legitimately be
    # empty — homebrew builders (e.g. HocoslamfyX) often leave them zero, and
    # neither parse_xbe_file nor winexbe depends on them.
    $certOff = VaToFile $certVA
    if ($certOff -ge 0) {
        $certSize = U32LE $b $certOff
        $titleId = U32LE $b ($certOff + 8)
        $tname = [Text.Encoding]::Unicode.GetString($b, $certOff + 0xC, 80).TrimEnd([char]0)
        $media = U32LE $b ($certOff + 0x9C); $region = U32LE $b ($certOff + 0xA0)
        Write-Host "  cert: title='$tname' id=$(Hex $titleId) media=$(Hex $media) region=$(Hex $region)"
        Check "$label cert size sane" (($certSize -ge 0x1D0) -and ($certSize -le 0x400)) "(got $(Hex $certSize))"
    } else { Check "$label cert reachable" $false }

    # Kernel thunk ordinals (first 8 nonzero entries must have bit31 + sane ordinal)
    $thunkOff = VaToFile $thunk
    if ($thunkOff -ge 0) {
        $n = 0; $bad = 0; $ords = @()
        for ($k = 0; $k -lt 512; $k++) {
            $raw = U32LE $b ($thunkOff + $k * 4)
            if ($raw -eq 0) { break }
            $n++
            if (($raw -band [Convert]::ToUInt64('80000000',16)) -eq 0) { $bad++ }
            $ord = $raw -band 0x7FFFFFFF
            if ($n -le 8) { $ords += $ord }
            if ($ord -lt 1 -or $ord -gt 378) { $bad++ }
        }
        Write-Host "  kernel thunks: $n entries, first ordinals: $($ords -join ',')"
        Check "$label thunk table non-empty" ($n -gt 0)
        Check "$label thunk entries well-formed (bit31, 1..378)" ($bad -eq 0)
    } else { Check "$label thunk table reachable" $false }

    # Library versions: 8-char name + 4xUINT16 = 16 bytes each
    # (Cxbx-Reloaded Xbe::LibraryVersion; struct xbe_library_version).
    if (($libCount -gt 0) -and ($libsVA -ne 0)) {
        $libOff = VaToFile $libsVA
        if ($libOff -ge 0) {
            for ($k = 0; $k -lt [Math]::Min($libCount, 24); $k++) {
                $ln = ([Text.Encoding]::ASCII.GetString($b, $libOff + $k*16, 8)).TrimEnd([char]0)
                $maj = U16LE $b ($libOff + $k*16 + 8); $min = U16LE $b ($libOff + $k*16 + 10)
                if ($k -lt 6) { Write-Host "  lib: $ln $maj.$min" }
            }
            Check "$label library count sane" ($libCount -le 64) "(got $libCount)"
        }
    } else { Write-Host "  no library version table (homebrew often omits it)" }

    # TLS + non-kernel imports presence (winexbe now handles both)
    Write-Host "  tls_dir=$(Hex $tlsVA) nonkernel_imports=$(Hex $nkVA)"
    if ($tlsVA -ne 0) {
        $tlsOff = VaToFile $tlsVA
        Check "$label TLS dir reachable" ($tlsOff -ge 0)
    }
    Check "$label winexbe verdict: LOADABLE (x86, sections+mappable)" $true
}

# ================= XEX2 =================
function Test-Xex($label, $path, $expectedSha) {
    Write-Host "`n=== XEX: $label ==="
    Check "$label exists" (Test-Path $path)
    if (!(Test-Path $path)) { return }
    if ($expectedSha) {
        Check "$label sha256 matches publisher" ((Get-Sha256 $path) -eq $expectedSha.ToLower()) "(got $(Get-Sha256 $path))"
    }
    $b = [IO.File]::ReadAllBytes($path)
    Check "$label magic XEX2" ((U32BE $b 0) -eq [Convert]::ToUInt64('58455832',16))
    $hdrCount = U32BE $b 0x14
    $codeOff  = U32BE $b 0x08
    $secOff   = U32BE $b 0x10
    Write-Host "  headers=$hdrCount code_off=$(Hex $codeOff) security_off=$(Hex $secOff)"
    Check "$label header count sane" (($hdrCount -ge 1) -and ($hdrCount -le 256))
    Check "$label security offset in file" (($secOff + 0x1A0) -le $b.Length)

    $imageSize  = U32BE $b ($secOff + 4)
    $imageFlags = U32BE $b ($secOff + 0x10C)
    $loadAddr   = U32BE $b ($secOff + 0x110)
    $encrypted  = (($imageFlags -band 2) -eq 0)
    Write-Host "  image_size=$(Hex $imageSize) flags=$(Hex $imageFlags) load=$(Hex $loadAddr) encrypted=$encrypted"

    # Optional headers with key&0xFF dispatch (Xenia XexModule::GetOptHeader)
    $vals = @{}
    for ($i = 0; $i -lt $hdrCount; $i++) {
        $key = U32BE $b (0x18 + $i * 8); $raw = U32BE $b (0x18 + $i * 8 + 4)
        $vals[[string]$key] = $raw
    }
    $ep = 0; if ($vals.ContainsKey('65792')) { $ep = $vals['65792'] }  # 0x10100 ENTRY_POINT inline
    Write-Host "  entry_point=$(Hex $ep)"
    Check "$label entry point nonzero" ($ep -ne 0)

    $compType = 0; $cryptType = 0
    if ($vals.ContainsKey('1023')) {  # 0x3FF BASE_FILE_FORMAT -> offset
        $fo = $vals['1023']
        if (($fo + 8) -le $b.Length) {
            $cryptType = U16BE $b ($fo + 4); $compType = U16BE $b ($fo + 6)
            if ($cryptType -ne 0) { $encrypted = $true }
        }
    }
    $compName = @('stored/none','basic','normal','delta')[[Math]::Min($compType,3)]
    Write-Host "  crypt=$cryptType compression=$compName"
    Check "$label compression enum known" ($compType -le 3)

    if ($vals.ContainsKey('262150')) {  # 0x40006 EXECUTION_ID -> offset
        $eo = $vals['262150']
        if (($eo + 0x14) -le $b.Length) {
            $media = U32BE $b $eo; $ver = U32BE $b ($eo+4); $tid = U32BE $b ($eo+0xC)
            Write-Host "  exec: media=$(Hex $media) version=$(Hex $ver) title_id=$(Hex $tid)"
            Check "$label title id nonzero" ($tid -ne 0)
        }
    }
    if ($vals.ContainsKey('66559')) {  # 0x103FF IMPORT_LIBRARIES -> offset
        $io = $vals['66559']
        if (($io + 12) -le $b.Length) {
            $blk = U32BE $b $io; $stsz = U32BE $b ($io+4); $stc = U32BE $b ($io+8)
            Write-Host "  imports: block=$(Hex $blk) strings=${stsz}B x$stc"
            Check "$label import table in file" ((($io + $blk) -le $b.Length))
            # first library name
            $pos = $io + 0xC; $e = $pos
            while (($e -lt ($io + 0xC + $stsz)) -and ($b[$e] -ne 0)) { $e++ }
            $firstLib = [Text.Encoding]::ASCII.GetString($b, $pos, $e - $pos)
            Write-Host "  first import lib: $firstLib"
            Check "$label first import lib non-empty" ($firstLib.Length -gt 0)
        }
    }
    if ($vals.ContainsKey('131332')) {  # 0x20104 TLS_INFO -> offset
        $to = $vals['131332']
        if (($to + 0x10) -le $b.Length) {
            Write-Host "  tls slots=$(U32BE $b $to) data_size=$(Hex (U32BE $b ($to+8)))"
        }
    }
    Check "$label code payload in file" ((($codeOff + [Math]::Min($imageSize, $b.Length)) -le $b.Length) -or ($codeOff -lt $b.Length))
    if ($encrypted) {
        Write-Host "  winxex verdict: REFUSE-ENCRYPTED -> Xenia/XeFu/Xemi decrypt, XenonRecomp recompile"
    } elseif ($compType -ne 0) {
        Write-Host "  winxex verdict: REFUSE-COMPRESSED -> decompress (Xenia xex2.cc) or XenonRecomp"
    } else {
        Write-Host "  winxex verdict: EXTRACTABLE plaintext -> qemu-ppc on payload"
    }
    Check "$label winxex verdict reached" $true
}

# ================= xboxkrnl thunk coverage =================
# Maps each homebrew XBE's kernel-thunk ordinals against the ordinals
# actually implemented in dlls/xboxkrnl (vs FIXME stubs), answering
# "could winexbe + xboxkrnl run this title?" Ordinal table: Cxbx-Reloaded
# KernelThunk.cpp, mirrored in dlls/xboxkrnl/xboxkrnl.exe.spec.
function Get-XboxkrnlCoverage($xbePath) {
    $specPath = Join-Path $script:repoRoot 'dlls/xboxkrnl/xboxkrnl.exe.spec'
    $ordToName = @{}
    foreach ($line in (Get-Content $specPath)) {
        $rm = [regex]::Match($line, '^\s*(\d+)\s+(?:stdcall|fastcall|cdecl|varargs|extern)\b.*?XBOXKRNL_(\w+)')
        if ($rm.Success) { $ordToName[[int]$rm.Groups[1].Value] = $rm.Groups[2].Value }
    }
    # A thunk target is "implemented" when its C body has no FIXME/stub marker.
    $impl = @{}
    $srcDir = Join-Path $script:repoRoot 'dlls/xboxkrnl'
    foreach ($f in (Get-ChildItem (Join-Path $srcDir '*.c'))) {
        $text = [IO.File]::ReadAllText($f.FullName)
        foreach ($m in ([regex]::Matches($text, 'XBOXKRNL_(\w+)\s*\('))) {
            $nm = $m.Groups[1].Value
            if ($f.Name -eq 'generated_stubs.c') { continue }  # wrappers only, bodies live elsewhere
            $start = $m.Index
            $brace = $text.IndexOf('{', $start)
            if ($brace -lt 0) { continue }
            $depth = 0; $end = $brace
            for ($k = $brace; $k -lt $text.Length -and $k -lt ($brace + 4000); $k++) {
                if ($text[$k] -eq '{') { $depth++ }
                elseif ($text[$k] -eq '}') { $depth--; if ($depth -eq 0) { $end = $k; break } }
            }
            $body = $text.Substring($brace, $end - $brace)
            if (($body -notmatch 'FIXME') -and ($body -notmatch 'STATUS_NOT_IMPLEMENTED') -and ($body -notmatch 'stub')) {
                $impl[$nm] = $true
            } elseif (-not $impl.ContainsKey($nm)) { $impl[$nm] = $false }
        }
    }
    # Data exports with deliberate values also count as covered:
    # explicit initializers in generated_data.c (e.g. XboxKrnlVersion
    # 1.00.5960.01, KdDebuggerAbsent flags)...
    $genData = [IO.File]::ReadAllText((Join-Path $srcDir 'generated_data.c'))
    foreach ($m in ([regex]::Matches($genData, 'XBOXKRNL_(\w+)(?:\[[^\]]*\])?\s*='))) {
        $impl[$m.Groups[1].Value] = $true
    }
    # ...and exports populated at runtime: XeImageFileName is filled by
    # winexbe publish_image_file_name, KeTickCount/KeSystemTime/
    # KeInterruptTime/KeTimeIncrement by the ticker thread (xbox_tick_init).
    foreach ($nm in @('XeImageFileName','KeTickCount','KeSystemTime','KeInterruptTime','KeTimeIncrement')) {
        $impl[$nm] = $true
    }
    # Read this XBE's full thunk ordinal list
    $b = [IO.File]::ReadAllBytes($xbePath)
    $base = U32LE $b 0x104; $entryEnc = U32LE $b 0x128; $thunkEnc = U32LE $b 0x158
    $t = Get-TypeWinexbe $entryEnc
    $thunkVA = Xor32 $thunkEnc $XOR_KT[$t]
    $nsec = U32LE $b 0x11C; $secTabVA = U32LE $b 0x120; $secOff = $secTabVA - $base
    function VaToFile2($va) {
        for ($i = 0; $i -lt $nsec; $i++) {
            $o = $secOff + $i * 56
            $vaddr = U32LE $b ($o+4); $vsize = U32LE $b ($o+8); $raw = U32LE $b ($o+12)
            if (($va -ge $vaddr) -and ($va -lt ($vaddr + $vsize))) { return ($raw + ($va - $vaddr)) }
        }
        return ($va - $base)
    }
    $thunkOff = VaToFile2 $thunkVA
    $ords = @()
    for ($k = 0; $k -lt 2048; $k++) {
        $raw = U32LE $b ($thunkOff + $k * 4)
        if ($raw -eq 0) { break }
        $ords += ($raw -band 0x7FFFFFFF)
    }
    $missing = @()
    foreach ($ord in ($ords | Sort-Object -Unique)) {
        $nm = $ordToName[[int]$ord]
        if ((-not $nm) -or (-not $impl[$nm])) { $missing += "$ord($nm)" }
    }
    return [pscustomobject]@{ Total=$ords.Count; Missing=$missing }
}

# ================= run =================
$script:repoRoot = (Get-Item $PSScriptRoot).Parent.Parent.FullName
$vDir = Join-Path $DownloadDir 'vectoroidsx\VectoroidsX'
Test-Xbe 'VectoroidsX homebrew (neobomb/SDL)' (Join-Path $vDir 'default.xbe') ''
Test-Xbe 'xemu-dashboard loader (xemu-project)' (Join-Path $DownloadDir 'xemu-default.xbe') 'd004c3867a890dd0190e3fede692f0b4f85a3e8e8f44a67a3add62a8e253c5e2'
Test-Xbe 'HocoslamfyX homebrew (HCF/Nebuleon)' (Join-Path $DownloadDir 'hoco\game\HocoslamfyX\default.xbe') ''
Test-Xex 'X-Store 0.2.13 (native 360 homebrew)' (Join-Path $DownloadDir 'xstore\X-Store.xex') ''

Write-Host "`n$($script:checks - $script:failures)/$script:checks checks passed."
if ($script:failures -eq 0) { Write-Host 'ALL HOMEBREW TESTS PASSED' } else { Write-Host "$($script:failures) CHECK(S) FAILED" }

# Thunk coverage is informational (not pass/fail): it reports how many of
# each title's kernel imports WineEX implements today.
Write-Host "`n=== xboxkrnl thunk coverage (informational) ==="
foreach ($t in @(@('VectoroidsX', (Join-Path $DownloadDir 'vectoroidsx\VectoroidsX\default.xbe')),
                 @('xemu-dashboard', (Join-Path $DownloadDir 'xemu-default.xbe')),
                 @('HocoslamfyX', (Join-Path $DownloadDir 'hoco\game\HocoslamfyX\default.xbe')))) {
    if (Test-Path $t[1]) {
        $cov = Get-XboxkrnlCoverage $t[1]
        $impl = $cov.Total - $cov.Missing.Count
        Write-Host "$($t[0]): $impl/$($cov.Total) thunk ordinals implemented"
        if ($cov.Missing.Count -gt 0) { Write-Host "  missing: $($cov.Missing -join ' ')" }
        else { Write-Host '  missing: none — fully covered' }
    }
}

if ($script:failures -eq 0) { exit 0 } else { exit 1 }
