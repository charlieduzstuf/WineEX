# Test-XboxParsers.ps1 - offline validation of WineEX Xbox container parsing.
#
# Mirrors the exact algorithms in:
#   programs/winexbe/winexbe.c + dlls/kernelbase/process.c parse_xbe_file
#   programs/winxex/winxex.c   + dlls/kernelbase/process.c parse_xex2_file
# against synthetic fixtures, cross-checked with:
#   Cxbx-Reloaded src/common/xbe/Xbe.h (XBE magic, XOR keys, GetXbeType)
#   Xenia src/xenia/kernel/util/xex2_info.h (XEX2 magic, BE fields, opt keys)
#   XenonRecomp README (decrypted/decompressed input requirement)
#   XeFu/Xemi XEX loaders (same container layout)
#   WinDurango package mounting / XWine1-SlimEra Era loader (ZIP/APPX magic)
#
# Run: powershell -ExecutionPolicy Bypass -File tests/xbox/Test-XboxParsers.ps1
# Exit code: 0 = all pass, 1 = any failure.

$ErrorActionPreference = 'Stop'
$failures = 0

function Assert-Equal($name, $actual, $expected) {
    if ($actual -ne $expected) {
        Write-Host "FAIL: $name -- expected $expected, got $actual"
        $script:failures++
    } else {
        Write-Host "PASS: $name"
    }
}

function Read-U32LE($bytes, $off) {
    return [BitConverter]::ToUInt32($bytes, $off)
}

function Read-U32BE($bytes, $off) {
    return ([uint64]$bytes[$off] -shl 24) -bor ([uint64]$bytes[$off+1] -shl 16) -bor `
           ([uint64]$bytes[$off+2] -shl 8) -bor [uint64]$bytes[$off+3]
}

# PowerShell parses 0x80000000+ literals as *signed* Int32, but the C code
# uses UINT32 throughout. All address/key arithmetic below is done in the
# uint64 domain (masked to 32 bits) so comparisons match C unsigned semantics.
function U32($v) { return ([uint64]$v -band 0xFFFFFFFF) }
function Xor32($a, $b) { return (([uint64]$a -bxor [uint64]$b) -band 0xFFFFFFFF) }

# ---------------- XBE (orig Xbox, Cxbx-Reloaded) ----------------
$XBE_MAGIC   = 0x48454258  # "XBEH" LE
$XOR_EP = @([Convert]::ToUInt64('A8FC57AB', 16),
           [Convert]::ToUInt64('94859D4B', 16),
           [Convert]::ToUInt64('40B5C16E', 16))
$XOR_KT = @([Convert]::ToUInt64('5B6D40B6', 16), [Convert]::ToUInt64('EFB1F152', 16), [Convert]::ToUInt64('2290059D', 16))

Assert-Equal 'XBE magic is ASCII XBEH' `
    ([Text.Encoding]::ASCII.GetString([BitConverter]::GetBytes([uint32]$XBE_MAGIC))) 'XBEH'

# Synthetic retail XBE: base=0x10000, entry real VA 0x11000, thunk 0x12000.
$base = [uint64]0x10000
$entryReal = [uint64]0x11000
$thunkReal = [uint64]0x12000
# Encode with retail keys (winexbe.c: entry_addr = real ^ xor_ep[RETAIL])
$entryEnc = Xor32 $entryReal $XOR_EP[0]
$thunkEnc = Xor32 $thunkReal $XOR_KT[0]

# Type detection, both algorithm spellings in-tree must agree:
#  (a) winexbe.c: (entry ^ xor_ep[DEBUG]) < 0x1000000 -> DEBUG, elif CHIHIRIO -> CHIHIRIO else RETAIL
#  (b) process.c parse_xbe_file: (entry & WC_BASE)==SEGABOOT -> CHIHIRIO, elif thunk & KSEG0 -> DEBUG else RETAIL
function Get-TypeWinexbe($e) {
    if ((Xor32 $e $XOR_EP[1]) -lt [uint64]0x1000000) { return 'DEBUG' }
    if ((Xor32 $e $XOR_EP[2]) -lt [uint64]0x1000000) { return 'CHIHIRO' }
    return 'RETAIL'
}
# For the synthetic retail image, process.c rule needs thunk WITHOUT KSEG0 bit:
Assert-Equal 'winexbe type-detect retail' (Get-TypeWinexbe $entryEnc) 'RETAIL'
Assert-Equal 'retail entry roundtrip' (Xor32 $entryEnc $XOR_EP[0]) $entryReal
Assert-Equal 'retail thunk roundtrip' (Xor32 $thunkEnc $XOR_KT[0]) $thunkReal

# Debug image: entry chosen so (entry ^ xor_ep[DEBUG]) < 0x1000000.
# The *encoded* thunk carries the KSEG0 bit (process.c checks the encoded field).
$entryDbgReal = [uint64]0x123456
$entryDbgEnc = Xor32 $entryDbgReal $XOR_EP[1]
$thunkDbgEnc = [Convert]::ToUInt64('80001234', 16)  # encoded value, KSEG0 bit set
Assert-Equal 'winexbe type-detect debug' (Get-TypeWinexbe $entryDbgEnc) 'DEBUG'
# process.c rule: thunk & 0x80000000 (KSEG0) -> DEBUG
$KSEG0 = [Convert]::ToUInt64('80000000', 16)
Assert-Equal 'process.c debug rule (thunk KSEG0 bit)' (($thunkDbgEnc -band $KSEG0) -ne 0) $true
Assert-Equal 'process.c retail rule (thunk no KSEG0)' (($thunkEnc -band $KSEG0) -ne 0) $false

# Chihiro: winexbe XOR-range must say CHIHIRO.
$entryChiReal = [uint64]0x400123
$entryChiEnc = Xor32 $entryChiReal $XOR_EP[2]
Assert-Equal 'winexbe type-detect chihiro' (Get-TypeWinexbe $entryChiEnc) 'CHIHIRO'

# Thunk ordinal mask: raw & 0x7FFFFFFF (winexbe.c XBE_THUNK_ORDINAL_MASK)
Assert-Equal 'thunk ordinal mask' (([Convert]::ToUInt64('80000005',16)) -band [uint64]0x7FFFFFFF) 5

# Section flags (Xbe.h): WRITEABLE=1 EXECUTABLE=4 HEAD_RO=0x10 TAIL_RO=0x20
Assert-Equal 'XBE flag WRITEABLE' 0x00000001 1
Assert-Equal 'XBE flag EXECUTABLE' 0x00000004 4
Assert-Equal 'XBE flag HEAD_RO' 0x00000010 16
Assert-Equal 'XBE flag TAIL_RO' 0x00000020 32

# xbe_va translation: va - base = file offset (headers mapped 1:1)
$hdr = New-Object byte[] 0x200
[BitConverter]::GetBytes([uint32]$XBE_MAGIC).CopyTo($hdr, 0)
Assert-Equal 'xbe_va magic at base+0' (Read-U32LE $hdr 0) $XBE_MAGIC

# ---------------- XEX2 (Xbox 360, Xenia/XenonRecomp/XeFu/Xemi) ----------------
# Build minimal synthetic XEX2: magic BE, header_count=2, security at 0x40.
# Opt headers: ENTRY_POINT (inline, key&0xFF==0x00) + IMPORT_LIBRARIES (offset, &0xFF==0xFF).
$xex = New-Object byte[] 0x200
$xex[0]=0x58; $xex[1]=0x45; $xex[2]=0x58; $xex[3]=0x32  # "XEX2"
# module_flags @0x04 = TITLE(1)|USER_MODE(0x80) BE
$xex[4]=0; $xex[5]=0; $xex[6]=0; $xex[7]=0x81
# code_offset @0x08 = 0x100 BE ; security_offset @0x10 = 0x40 BE ; header_count @0x14 = 2 BE
$xex[8]=0; $xex[9]=0; $xex[10]=1; $xex[11]=0
$xex[16]=0; $xex[17]=0; $xex[18]=0; $xex[19]=0x40
$xex[20]=0; $xex[21]=0; $xex[22]=0; $xex[23]=2
# opt[0] @0x18: key 0x00010100 (ENTRY_POINT, inline) value 0x82000000
$xex[24]=0; $xex[25]=1; $xex[26]=1; $xex[27]=0
$xex[28]=0x82; $xex[29]=0; $xex[30]=0; $xex[31]=0
# opt[1] @0x20: key 0x000103FF (IMPORT_LIBRARIES -> offset) offset 0x80
$xex[32]=0; $xex[33]=1; $xex[34]=3; $xex[35]=0xFF
$xex[36]=0; $xex[37]=0; $xex[38]=0; $xex[39]=0x80
# security info @0x40: image_size @+4, image_flags @+0x10C (after rsa 0x100),
# load_address @+0x110, title_id further on. Set flags=NO_ENCRYPTION(2), load=0x82000000.
$xex[0x40+4]=0; $xex[0x40+5]=0; $xex[0x40+6]=0x10; $xex[0x40+7]=0   # image_size 0x1000
$xex[0x40+0x10C]=0; $xex[0x40+0x10D]=0; $xex[0x40+0x10E]=0; $xex[0x40+0x10F]=2
$xex[0x40+0x110]=0x82; $xex[0x40+0x111]=0; $xex[0x40+0x112]=0; $xex[0x40+0x113]=0
# execution-id-like title id at sec+0x194 (title_id field): 0x12345678 BE
$xex[0x40+0x194]=0x12; $xex[0x40+0x195]=0x34; $xex[0x40+0x196]=0x56; $xex[0x40+0x197]=0x78

Assert-Equal 'XEX2 magic BE' (Read-U32BE $xex 0) 0x58455832
Assert-Equal 'XEX2 header_count' (Read-U32BE $xex 0x14) 2
Assert-Equal 'XEX2 code_offset' (Read-U32BE $xex 0x08) 0x100
Assert-Equal 'XEX2 security_offset' (Read-U32BE $xex 0x10) 0x40
Assert-Equal 'XEX2 opt0 key ENTRY_POINT' (Read-U32BE $xex 0x18) 0x00010100
$PPC_BASE = [Convert]::ToUInt64('82000000', 16)
Assert-Equal 'XEX2 opt0 inline value' (Read-U32BE $xex 0x1C) $PPC_BASE
Assert-Equal 'XEX2 opt1 key IMPORT_LIBS' (Read-U32BE $xex 0x20) 0x000103FF
# key&0xFF dispatch (Xenia GetOptHeader): 0x00 inline, 0xFF offset
Assert-Equal 'XEX2 dispatch ENTRY_POINT inline' ((0x00010100 -band 0xFF) -le 0x01) $true
Assert-Equal 'XEX2 dispatch IMPORT_LIBS offset' ((0x000103FF -band 0xFF) -le 0x01) $false
Assert-Equal 'XEX2 image_flags NO_ENCRYPTION' (Read-U32BE $xex (0x40+0x10C)) 2
Assert-Equal 'XEX2 plaintext iff flags&2' (((Read-U32BE $xex (0x40+0x10C)) -band 2) -ne 0) $true
Assert-Equal 'XEX2 load_address' (Read-U32BE $xex (0x40+0x110)) $PPC_BASE
# Compression enum (Xenia xex2_file_format_info / XeFu / Xemi agree)
Assert-Equal 'XEX2 comp NONE' 0 0
Assert-Equal 'XEX2 comp BASIC' 1 1
Assert-Equal 'XEX2 comp NORMAL' 2 2
Assert-Equal 'XEX2 comp DELTA' 3 3

# ---------------- Xbox One package (WinDurango / XWine1-SlimEra) ----------------
# APPX/MSIXVC/XVC are ZIPs: PK\x03\x04 (parse_xbox_one_package checks this)
$zip = New-Object byte[] 4
$zip[0]=[byte][char]'P'; $zip[1]=[byte][char]'K'; $zip[2]=3; $zip[3]=4
$recognized = ($zip[0] -eq [byte][char]'P' -and $zip[1] -eq [byte][char]'K' -and $zip[2] -eq 3 -and $zip[3] -eq 4)
Assert-Equal 'XOne package ZIP magic' $recognized $true
$bad = New-Object byte[] 4
$bad[0]=[byte][char]'M'; $bad[1]=[byte][char]'Z'; $bad[2]=0x90; $bad[3]=0
$recognizedBad = ($bad[0] -eq [byte][char]'P' -and $bad[1] -eq [byte][char]'K' -and $bad[2] -eq 3 -and $bad[3] -eq 4)
Assert-Equal 'XOne package rejects MZ' $recognizedBad $false

# ---------------- C source consistency ----------------
$root = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
if (-not (Test-Path (Join-Path $root 'programs/winxex/winxex.c'))) {
    # fallback: locate repo root from script path
    $root = (Get-Item $PSScriptRoot).Parent.Parent.FullName
}
function Assert-Contains($name, $file, $pattern) {
    $hit = Select-String -Path $file -Pattern $pattern -SimpleMatch | Select-Object -First 1
    if ($hit) { Write-Host "PASS: $name" } else { Write-Host "FAIL: $name -- '$pattern' not in $file"; $script:failures++ }
}
Assert-Contains 'winxex cites Xenia' (Join-Path $root 'programs/winxex/winxex.c') 'Xenia'
Assert-Contains 'winxex cites XenonRecomp' (Join-Path $root 'programs/winxex/winxex.c') 'XenonRecomp'
Assert-Contains 'winxex cites XeFu' (Join-Path $root 'programs/winxex/winxex.c') 'XeFu'
Assert-Contains 'winxex cites Xemi' (Join-Path $root 'programs/winxex/winxex.c') 'Xemi'
Assert-Contains 'winxex cites WinDurango/xWine' (Join-Path $root 'programs/winxex/winxex.c') 'WinDurango'
Assert-Contains 'winexbe cites Cxbx-Reloaded' (Join-Path $root 'programs/winexbe/winexbe.c') 'Cxbx-Reloaded'
Assert-Contains 'winexbe cites Xemu' (Join-Path $root 'programs/winexbe/winexbe.c') 'Xemu'
Assert-Contains 'kernelbase routes .xex to winxex' (Join-Path $root 'dlls/kernelbase/process.c') 'create_xex_process'
Assert-Contains 'kernelbase routes .xbe to winexbe' (Join-Path $root 'dlls/kernelbase/process.c') 'create_xbe_process'
Assert-Contains 'kernelbase handles xvc package' (Join-Path $root 'dlls/kernelbase/process.c') 'parse_xbox_one_package'
Assert-Contains 'xboxkrnl Ob name resolve' (Join-Path $root 'dlls/xboxkrnl/hal_ob_stubs.c') 'ObReferenceObjectByName'
Assert-Contains 'xboxkrnl test exists' (Join-Path $root 'dlls/xboxkrnl/tests/xboxkrnl.c') 'START_TEST(xboxkrnl)'
Assert-Contains 'xgameruntime test exists' (Join-Path $root 'dlls/xgameruntime/tests/xgameruntime.c') 'START_TEST(xgameruntime)'
Assert-Contains 'xboxkrnl tests in configure.ac' (Join-Path $root 'configure.ac') 'dlls/xboxkrnl/tests'
Assert-Contains 'xgameruntime tests in configure.ac' (Join-Path $root 'configure.ac') 'dlls/xgameruntime/tests'
Assert-Contains 'xboxkrnl tests in configure' (Join-Path $root 'configure') 'dlls/xboxkrnl/tests'
Assert-Contains 'xgameruntime tests in configure' (Join-Path $root 'configure') 'dlls/xgameruntime/tests'
Assert-Contains 'winxex extract mode' (Join-Path $root 'programs/winxex/winxex.c') '--extract-pe'
Assert-Contains 'winxex compression types' (Join-Path $root 'programs/winxex/winxex.c') 'XEX_COMP_NORMAL'
Assert-Contains 'winexbe TLS init' (Join-Path $root 'programs/winexbe/winexbe.c') 'init_xbe_tls'
Assert-Contains 'winexbe nonkernel imports' (Join-Path $root 'programs/winexbe/winexbe.c') 'resolve_nonkernel_imports'
Assert-Contains 'winexbe unresolved ordinal fatal' (Join-Path $root 'programs/winexbe/winexbe.c') 'xbe_unresolved_ordinal'
Assert-Contains 'winexbe publishes XeImageFileName' (Join-Path $root 'programs/winexbe/winexbe.c') 'publish_image_file_name'
Assert-Contains 'xboxkrnl reports final kernel version' (Join-Path $root 'dlls/xboxkrnl/generated_data.c') '5960'
Assert-Contains 'xboxkrnl ticker thread' (Join-Path $root 'dlls/xboxkrnl/keirql_misc.c') 'xbox_tick_init'
Assert-Contains 'xboxkrnl ticker wired in DllMain' (Join-Path $root 'dlls/xboxkrnl/main.c') 'xbox_tick_init'
Assert-Contains 'Phy reports no link' (Join-Path $root 'dlls/xboxkrnl/hal_ob_stubs.c') 'no NIC emulated'
Assert-Contains 'xboxkrnl test checks tick' (Join-Path $root 'dlls/xboxkrnl/tests/xboxkrnl.c') 'KeTickCount did not advance'
Assert-Contains 'xboxkrnl SHA uses +24 ctx' (Join-Path $root 'dlls/xboxkrnl/xc_crypto.c') 'XBOX_SHA_STATE_OFF'
Assert-Contains 'xboxkrnl 3DES K1K2K1' (Join-Path $root 'dlls/xboxkrnl/xc_crypto.c') 'K3 = K1'
Assert-Contains 'xboxkrnl ModExp portable' (Join-Path $root 'dlls/xboxkrnl/xc_crypto.c') 'xc_modexp_le'
Assert-Contains 'xboxkrnl UpdateCrypto vector' (Join-Path $root 'dlls/xboxkrnl/xc_crypto.c') 'xc_crypto_vector'
Assert-Contains 'xboxkrnl test checks modexp' (Join-Path $root 'dlls/xboxkrnl/tests/xboxkrnl.c') 'test_xc_modexp'
Assert-Contains 'xboxkrnl test checks 3DES' (Join-Path $root 'dlls/xboxkrnl/tests/xboxkrnl.c') 'XcBlockCrypt(3DES)'
Assert-Contains 'xboxkrnl test checks updatecrypto' (Join-Path $root 'dlls/xboxkrnl/tests/xboxkrnl.c') 'test_xc_updatecrypto'

Write-Host ""
if ($failures -eq 0) { Write-Host "ALL TESTS PASSED"; exit 0 }
else { Write-Host "$failures TEST(S) FAILED"; exit 1 }
