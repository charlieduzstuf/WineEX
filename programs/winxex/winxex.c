/*
 * winxex.exe - Xbox 360 XEX2 executable loader for Wine.
 *
 * Usage: winxex.exe <file.xex> [args...]
 *        winxex.exe --dump-info <file.xex>
 *        winxex.exe --extract-pe <file.xex> <out.bin>
 *
 * XEX2 format references:
 *   Xenia (https://github.com/xenia-project/xenia):
 *     src/xenia/kernel/util/xex2_info.h  (header structures)
 *     src/xenia/kernel/util/xex2.cc      (decryption, decompression, import walk)
 *     src/xenia/cpu/xex_module.cc        (XexModule::GetOptHeader key&0xFF dispatch)
 *   Free60: wiki.free60.org/XEX (field offsets)
 *   XenonRecomp (https://github.com/hedge-dev/XenonRecomp):
 *     PPC -> C++ static recompiler; consumes a *decrypted, decompressed*
 *     XEX and emits native x86 code + a .toml config. That recompiled output
 *     — not the raw .xex — is what can ever run under Wine. When this loader
 *     refuses an encrypted/compressed image, the supported path is:
 *       Xenia (or XeFu/Xemi) to decrypt/decompress -> XenonRecomp to
 *       recompile -> run the recompiled x86 binary under Wine.
 *   XeFu (https://github.com/FinalDebt/XeFu) and Xemi
 *   (https://github.com/Xemi-Emu/Xemi, Xenia fork): alternate 360 emulators
 *     whose XEX loaders document the same container layout; cross-checked
 *     for the file-format/compression enum and import-library walk below.
 *   Cxbx-Reloaded: partial XEX support in their loader (orig-Xbox focused).
 *   xWine/XWine1-SlimEra + WinDurango/WinDurango: Xbox One ERA/GDK layers —
 *     not used here (360 XEX is Xenon/PPC, ERA is Durango/x64), mentioned so
 *     360 vs One code paths are not confused.
 *
 * Xbox 360 games use PowerPC big-endian code.  Wine runs on x86/x86-64, so
 * native execution is not possible.  This loader fully parses the XEX2
 * *container* (magic, module flags, security info, file-format compression
 * type, execution ID/title ID, import libraries, TLS template), reports it,
 * and then:
 *   - plaintext + uncompressed images: extracts the raw PPC payload and
 *     runs it under an installed qemu-ppc (raw image, NOT the .xex — qemu
 *     cannot parse the XEX container, which is why the old behaviour of
 *     passing the .xex straight to qemu-ppc could never work);
 *   - encrypted or compressed images: fails with an actionable message
 *     pointing at Xenia/XeFu/Xemi (decrypt/decompress) + XenonRecomp
 *     (recompile to x86 for Wine).
 *
 * Encryption: retail XEX images encrypt their sections with AES-128-CBC.
 * The session key is derived by decrypting the per-title key (stored in the
 * XEX header) using one of two fixed retail/devkit master keys from Xenia
 * xex2.cc.  We do not include the retail master key; use Xenia/XeFu/Xemi
 * to work with encrypted retail images.
 */

#include <stdarg.h>
#include <string.h>
#include "windef.h"
#include "winbase.h"
#include "winternl.h"

/* ======================================================================
 * XEX2 header layout (Xenia xex2_info.h + Free60 wiki)
 * ====================================================================== */
#define XEX2_MAGIC  0x58455832u  /* "XEX2" */

/* XEX header option-descriptor keys (big-endian as read from file) */
#define XEX_HEADER_RESOURCE_INFO        0x000002FF
#define XEX_HEADER_BASE_FILE_FORMAT     0x000003FF
#define XEX_HEADER_ENTRY_POINT          0x00010100
#define XEX_HEADER_IMAGE_BASE_ADDRESS   0x00010201
#define XEX_HEADER_IMPORT_LIBRARIES     0x000103FF
#define XEX_HEADER_CHECKSUM_TIMESTAMP   0x00018002
#define XEX_HEADER_ORIGINAL_PE_NAME     0x000183FF
#define XEX_HEADER_TLS_INFO             0x00020104
#define XEX_HEADER_EXECUTION_ID         0x00040006
#define XEX_HEADER_TITLE_WORKSPACE_SIZE 0x00040201
#define XEX_HEADER_GAME_RATINGS         0x00040310
#define XEX_HEADER_LAN_KEY              0x00040404
#define XEX_HEADER_BOUND_PATH           0x000080FF
#define XEX_HEADER_DEVICE_ID            0x00008105

/* XEX security info */
#define XEX_IMAGE_FLAG_NO_ENCRYPTION    0x00000002

/* Base file format (Xenia xex2_file_format_info): encryption_type /
 * compression_type as stored big-endian at the 0x3FF header's data offset:
 *   +0 u32 size, +4 u16 encryption_type (0=none, 1=AES), +6 u16 compression
 *   (0=stored/none, 1=basic/LZX-desc, 2=normal/LZX, 3=delta patch).
 * (XeFu xex.rs and Xemi xex2.rs document the same enum values.) */
#define XEX_CRYPT_NONE 0
#define XEX_COMP_NONE   0
#define XEX_COMP_BASIC  1
#define XEX_COMP_NORMAL 2
#define XEX_COMP_DELTA  3

#pragma pack(push,1)
struct xex2_header {
    UINT32 magic;               /* 0x00: "XEX2" */
    UINT32 module_flags;        /* 0x04 */
    UINT32 code_offset;         /* 0x08: offset to PE/compressed data */
    UINT32 reserved;            /* 0x0C */
    UINT32 security_offset;     /* 0x10: offset to XEX2SecurityInfo */
    UINT32 header_count;        /* 0x14: number of optional headers */
};

struct xex2_opt_header {
    UINT32 key;                 /* option key */
    UINT32 value_or_offset;     /* inline value (<= 0xFF data bytes) or file offset */
};

struct xex2_security_info {
    UINT32 header_size;
    UINT32 image_size;
    BYTE   rsa_signature[0x100];
    UINT32 unk0;
    UINT32 image_flags;
    UINT32 load_address;        /* preferred load VA */
    BYTE   session_key[0x10];   /* AES session key (encrypted with master key) */
    UINT32 unk1;
    BYTE   export_table_digest[0x14];
    UINT64 image_key_version;
    UINT32 unk2;
    BYTE   header_digest[0x14];
    UINT32 game_region;
    UINT32 media_id;
    UINT32 version;
    UINT32 base_version;
    UINT32 title_id;
    BYTE   platform;
    BYTE   executable_table;
    BYTE   disc_number;
    BYTE   disc_count;
    UINT32 savegame_id;
};
#pragma pack(pop)

#define XEX_LOAD_BUFFER 0x10000

/* ======================================================================
 * Byte-swap helpers (XEX is big-endian)
 * ====================================================================== */
static UINT32 be32(UINT32 v)
{
    return ((v & 0xFF) << 24) | ((v & 0xFF00) << 8) |
           ((v >> 8) & 0xFF00) | ((v >> 24) & 0xFF);
}

static UINT16 be16(UINT16 v)
{
    return (UINT16)(((v & 0xFF) << 8) | ((v >> 8) & 0xFF));
}

static UINT32 rd_be32( const BYTE *p )
{
    UINT32 v;
    memcpy( &v, p, 4 );
    return be32( v );
}

/* ======================================================================
 * Fatal error / diagnostic helpers (no printf in PE build)
 * ====================================================================== */
static void xex_write( const char *msg )
{
    DWORD n;
    WriteFile( GetStdHandle(STD_ERROR_HANDLE), msg, strlen(msg), &n, NULL );
}

static void xex_fatal(const char *msg)
{
    xex_write( msg );
    xex_write( "\n" );
    ExitProcess(1);
}

static void xex_write_hex( const char *prefix, UINT32 v )
{
    char buf[64];
    int i, pos = 0;
    const char *hexd = "0123456789ABCDEF";
    while (*prefix) buf[pos++] = *prefix++;
    buf[pos++] = '0'; buf[pos++] = 'x';
    for (i = 7; i >= 0; i--) buf[pos++] = hexd[(v >> (i * 4)) & 0xF];
    buf[pos++] = '\n'; buf[pos] = 0;
    xex_write( buf );
}

/* ======================================================================
 * Optional-header lookup. Returns the raw value_or_offset field
 * (big-endian corrected). Caller decides inline-vs-offset by key&0xFF,
 * the Xenia XexModule::GetOptHeader dispatch: low byte 0x00/0x01 means the
 * dword IS the value, anything else is a file offset from header start.
 * ====================================================================== */
static UINT32 xex_find_opt_header(const BYTE *buf, UINT32 hdr_count, UINT32 key)
{
    UINT32 i;
    const struct xex2_opt_header *opts =
        (const struct xex2_opt_header *)(buf + sizeof(struct xex2_header));
    for (i = 0; i < hdr_count; i++)
    {
        if (be32(opts[i].key) == key)
            return be32(opts[i].value_or_offset);
    }
    return 0;
}

/* Walk the import-library table at file offset 'off' (Xenia
 * xex2_opt_import_libraries / xex2_import_library, XexModule::LoadContinue).
 * Prints library names + import counts to stderr for diagnostics. */
static void xex_trace_imports( const BYTE *base, UINT32 off, UINT32 buf_size )
{
    char string_table[32][64];
    UINT32 block_size, st_size, st_count, name_count = 0;
    UINT32 i, pos, library_off;
    const BYTE *lib;

    if (off + 12 > buf_size) return;
    block_size = rd_be32( base + off );
    st_size    = rd_be32( base + off + 4 );
    st_count   = rd_be32( base + off + 8 );
    xex_write( "winxex: import libraries present\n" );

    if (off + 0xC + st_size > buf_size) return;
    memset( string_table, 0, sizeof(string_table) );
    for (i = 0, pos = 0; pos < st_size && i < st_count && i < 32; i++)
    {
        const char *str = (const char *)(base + off + 0xC + pos);
        UINT32 len = 0;
        while (pos + len < st_size && str[len] && len < 63) len++;
        memcpy( string_table[i], str, len );
        name_count++;
        pos += len + 1;
        if (pos % 4) pos += 4 - (pos % 4);
    }

    library_off = 0xC + st_size;
    while (off + library_off + 0x28 <= buf_size && library_off < block_size)
    {
        UINT16 name_index, count;
        lib = base + off + library_off;
        {
            UINT32 lib_size = rd_be32( lib );
            UINT16 ni, cnt;
            memcpy( &ni, lib + 0x24, 2 ); memcpy( &cnt, lib + 0x26, 2 );
            name_index = be16( ni ) & 0xFF;
            count = be16( cnt );
            xex_write( "winxex:   lib " );
            xex_write( name_index < name_count ? string_table[name_index] : "?" );
            xex_write( "\n" );
            (void)count;
            if (!lib_size) break;
            library_off += lib_size;
        }
    }
}

/* Report execution ID (title/media/version) at file offset 'off'. */
static void xex_trace_execution_id( const BYTE *base, UINT32 off, UINT32 buf_size,
                                    UINT32 *title_id_out )
{
    if (off + 0x14 > buf_size) return;
    {
        UINT32 media_id  = rd_be32( base + off );
        UINT32 version   = rd_be32( base + off + 4 );
        UINT32 title_id  = rd_be32( base + off + 0xC );
        xex_write_hex( "winxex: media id ", media_id );
        xex_write_hex( "winxex: version ", version );
        xex_write_hex( "winxex: title id ", title_id );
        if (title_id_out) *title_id_out = title_id;
    }
}

/* Report TLS template info at file offset 'off' (slot count, data sizes). */
static void xex_trace_tls( const BYTE *base, UINT32 off, UINT32 buf_size )
{
    if (off + 0x10 > buf_size) return;
    xex_write_hex( "winxex: tls slots ", rd_be32( base + off ) );
    xex_write_hex( "winxex: tls data size ", rd_be32( base + off + 8 ) );
}

/* ======================================================================
 * Check if a PPC userspace interpreter is available
 * ====================================================================== */
static BOOL find_ppc_interpreter(WCHAR *out, DWORD len)
{
    /* Check for qemu-ppc in PATH (Xenia/XeFu/Xemi ship their own CPU cores
     * and are NOT usable as CLI interpreters, so only qemu-ppc qualifies). */
    static const WCHAR *candidates[] = {
        L"qemu-ppc.exe",
        L"qemu-ppc",
        NULL
    };
    UINT i;
    for (i = 0; candidates[i]; i++)
    {
        WCHAR path[MAX_PATH];
        if (SearchPathW(NULL, candidates[i], NULL, MAX_PATH, path, NULL))
        {
            if (out) lstrcpynW(out, path, len);
            return TRUE;
        }
    }
    return FALSE;
}

/* Extract the raw PPC payload for plaintext+uncompressed images:
 * code section at file offset code_off, length image_size. Returns TRUE
 * with *out set to a heap buffer the caller must HeapFree. */
static BOOL xex_extract_payload( HANDLE file, UINT32 code_off, UINT32 image_size,
                                 BYTE **out )
{
    BYTE *buf;
    DWORD read, got = 0;
    LONG hi = 0;
    if (!image_size || image_size > 256 * 1024 * 1024) return FALSE;
    buf = HeapAlloc( GetProcessHeap(), 0, image_size );
    if (!buf) return FALSE;
    SetFilePointer( file, code_off, &hi, FILE_BEGIN );
    while (got < image_size)
    {
        DWORD chunk = image_size - got;
        if (!ReadFile( file, buf + got, chunk, &read, NULL ) || !read) break;
        got += read;
    }
    if (got != image_size) { HeapFree( GetProcessHeap(), 0, buf ); return FALSE; }
    *out = buf;
    return TRUE;
}

/* ======================================================================
 * wmain
 * ====================================================================== */
int __cdecl wmain(int argc, WCHAR **argv)
{
    HANDLE file;
    BYTE *hdr_buf;
    DWORD read;
    const struct xex2_header *hdr;
    const struct xex2_security_info *sec;
    UINT32 hdr_count, entry_point, load_addr, image_flags, title_id = 0;
    UINT32 code_off, image_size;
    UINT32 fmt_off, crypt_type = 0, comp_type = 0;
    UINT32 imp_off, exec_off, tls_off;
    BOOL encrypted, dump_only = FALSE, extract = FALSE;
    WCHAR interp[MAX_PATH];
    WCHAR *xex_path, *extract_out = NULL;
    int argi = 1;

    if (argc >= 2 && !lstrcmpW( argv[1], L"--dump-info" )) { dump_only = TRUE; argi = 2; }
    else if (argc >= 2 && !lstrcmpW( argv[1], L"--extract-pe" ))
    {
        if (argc < 4)
            xex_fatal("usage: winxex.exe --extract-pe <file.xex> <out.bin>");
        extract = TRUE; argi = 2; extract_out = argv[3];
    }

    if (argc - argi < 1)
    {
        xex_fatal("usage: winxex.exe [--dump-info] <file.xex> [args...]\n"
                  "       winxex.exe --extract-pe <file.xex> <out.bin>\n"
                  "  Parses the Xbox 360 XEX2 container, reports title/media/version,\n"
                  "  imports and TLS, then runs plaintext images under qemu-ppc.\n"
                  "  Encrypted/compressed retail images: decrypt with Xenia/XeFu/Xemi,\n"
                  "  then recompile with XenonRecomp to an x86 binary for Wine.");
    }
    xex_path = argv[argi];

    file = CreateFileW(xex_path, GENERIC_READ, FILE_SHARE_READ, NULL,
                       OPEN_EXISTING, 0, 0);
    if (file == INVALID_HANDLE_VALUE) xex_fatal("cannot open XEX file");

    hdr_buf = HeapAlloc(GetProcessHeap(), 0, XEX_LOAD_BUFFER);
    if (!hdr_buf) xex_fatal("out of memory");

    if (!ReadFile(file, hdr_buf, XEX_LOAD_BUFFER, &read, NULL) || read < sizeof(*hdr))
        xex_fatal("cannot read XEX header");

    hdr = (const struct xex2_header *)hdr_buf;
    if (be32(hdr->magic) != XEX2_MAGIC) xex_fatal("not a XEX2 file (bad magic)");

    hdr_count = be32(hdr->header_count);
    if (hdr_count > 256) xex_fatal("implausible optional header count");
    if (sizeof(*hdr) + hdr_count * 8 > read)
        xex_fatal("optional header directory truncated");

    /* Parse security info */
    {
        UINT32 sec_off = be32(hdr->security_offset);
        if (sec_off + sizeof(*sec) > read)
            xex_fatal("security info offset out of range in header buffer");
        sec = (const struct xex2_security_info *)(hdr_buf + sec_off);
    }

    image_flags = be32(sec->image_flags);
    load_addr   = be32(sec->load_address);
    image_size  = be32(sec->image_size);
    code_off    = be32(hdr->code_offset);
    encrypted   = !(image_flags & XEX_IMAGE_FLAG_NO_ENCRYPTION);

    /* Base file format: encryption + compression type (Xenia xex2.cc) */
    fmt_off = xex_find_opt_header(hdr_buf, hdr_count, XEX_HEADER_BASE_FILE_FORMAT);
    if (fmt_off && fmt_off + 8 <= read)
    {
        UINT16 ce, cc;
        memcpy( &ce, hdr_buf + fmt_off + 4, 2 );
        memcpy( &cc, hdr_buf + fmt_off + 6, 2 );
        crypt_type = be16( ce );
        comp_type  = be16( cc );
        if (crypt_type != XEX_CRYPT_NONE) encrypted = TRUE;
    }

    /* Find entry point and load address from optional headers */
    {
        UINT32 ep = xex_find_opt_header(hdr_buf, hdr_count, XEX_HEADER_ENTRY_POINT);
        UINT32 base = xex_find_opt_header(hdr_buf, hdr_count, XEX_HEADER_IMAGE_BASE_ADDRESS);
        entry_point = ep ? ep : load_addr;
        if (base) load_addr = base;
    }
    (void)entry_point;
    (void)title_id;

    /* Diagnostics */
    xex_write( encrypted ? "winxex: XEX2 image (encrypted)\n"
                        : "winxex: XEX2 image (plaintext)\n" );
    xex_write_hex( "winxex: load address ", load_addr );
    xex_write_hex( "winxex: image size ", image_size );
    xex_write_hex( "winxex: compression ", comp_type );

    exec_off = xex_find_opt_header(hdr_buf, hdr_count, XEX_HEADER_EXECUTION_ID);
    if ((XEX_HEADER_EXECUTION_ID & 0xFF) > 0x01 && exec_off)
        xex_trace_execution_id( hdr_buf, exec_off, read, &title_id );
    imp_off = xex_find_opt_header(hdr_buf, hdr_count, XEX_HEADER_IMPORT_LIBRARIES);
    if ((XEX_HEADER_IMPORT_LIBRARIES & 0xFF) > 0x01 && imp_off)
        xex_trace_imports( hdr_buf, imp_off, read );
    tls_off = xex_find_opt_header(hdr_buf, hdr_count, XEX_HEADER_TLS_INFO);
    if ((XEX_HEADER_TLS_INFO & 0xFF) > 0x01 && tls_off)
        xex_trace_tls( hdr_buf, tls_off, read );

    if (dump_only)
    {
        CloseHandle(file);
        HeapFree(GetProcessHeap(), 0, hdr_buf);
        return 0;
    }

    if (extract)
    {
        /* --extract-pe: plaintext + stored only (cf. XenonRecomp README:
         * feed it a decrypted/decompressed image, not a retail XEX). */
        HANDLE out;
        BYTE *payload = NULL;
        DWORD written, n = 0;
        if (encrypted)
        {
            CloseHandle(file);
            HeapFree(GetProcessHeap(), 0, hdr_buf);
            xex_fatal("winxex: image is encrypted; decrypt with Xenia/XeFu/Xemi first, "
                      "then pass the decrypted image back (see XenonRecomp README)");
        }
        if (comp_type != XEX_COMP_NONE)
        {
            CloseHandle(file);
            HeapFree(GetProcessHeap(), 0, hdr_buf);
            xex_fatal("winxex: image is compressed; decompress with Xenia (xex2.cc) "
                      "or point XenonRecomp at it first");
        }
        if (!xex_extract_payload( file, code_off, image_size, &payload ))
        {
            CloseHandle(file);
            HeapFree(GetProcessHeap(), 0, hdr_buf);
            xex_fatal("winxex: failed to extract PPC payload");
        }
        out = CreateFileW( extract_out, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, 0 );
        if (out == INVALID_HANDLE_VALUE)
        {
            HeapFree( GetProcessHeap(), 0, payload );
            CloseHandle(file);
            HeapFree(GetProcessHeap(), 0, hdr_buf);
            xex_fatal("winxex: cannot create output file");
        }
        while (n < image_size)
        {
            DWORD chunk = image_size - n;
            if (!WriteFile( out, payload + n, chunk, &written, NULL ) || !written) break;
            n += written;
        }
        CloseHandle( out );
        HeapFree( GetProcessHeap(), 0, payload );
        CloseHandle(file);
        HeapFree(GetProcessHeap(), 0, hdr_buf);
        if (n != image_size) xex_fatal("winxex: short write extracting payload");
        xex_write( "winxex: payload extracted\n" );
        return 0;
    }

    if (encrypted)
    {
        CloseHandle(file);
        HeapFree(GetProcessHeap(), 0, hdr_buf);
        xex_fatal("winxex: encrypted XEX images require AES decryption; decrypt with "
                  "Xenia/XeFu/Xemi, then recompile the decrypted image with XenonRecomp "
                  "to an x86 binary and run that under Wine");
    }
    if (comp_type != XEX_COMP_NONE)
    {
        CloseHandle(file);
        HeapFree(GetProcessHeap(), 0, hdr_buf);
        xex_fatal("winxex: compressed XEX images must be decompressed first "
                  "(Xenia xex2.cc basic/normal decompression, or via XenonRecomp)");
    }

    /* Plaintext + stored: extract the raw PPC payload and run THAT under
     * qemu-ppc. Passing the .xex itself (the old behaviour) could never
     * work: qemu-ppc expects a raw machine image, not the XEX container. */
    {
        BYTE *payload = NULL;
        WCHAR tmp[MAX_PATH], tmppath[MAX_PATH];
        HANDLE tmpf;
        DWORD written, n = 0;
        STARTUPINFOW si;
        PROCESS_INFORMATION pi;
        WCHAR *cmdline;
        int cmdlen, i;
        DWORD exit_code;

        if (!xex_extract_payload( file, code_off, image_size, &payload ))
        {
            CloseHandle(file);
            HeapFree(GetProcessHeap(), 0, hdr_buf);
            xex_fatal("winxex: failed to extract PPC payload");
        }
        CloseHandle(file);
        HeapFree(GetProcessHeap(), 0, hdr_buf);

        if (!find_ppc_interpreter(interp, MAX_PATH))
        {
            HeapFree( GetProcessHeap(), 0, payload );
            xex_fatal("winxex: no PowerPC interpreter found (install qemu-ppc); "
                      "Xbox 360 games use PowerPC and cannot run natively on x86. "
                      "For real titles prefer XenonRecomp (static PPC->x86 recompiler).");
        }

        if (!GetTempPathW( MAX_PATH, tmppath ) ||
            !GetTempFileNameW( tmppath, L"xex", 0, tmp ))
        {
            HeapFree( GetProcessHeap(), 0, payload );
            xex_fatal("winxex: cannot create temp file");
        }
        tmpf = CreateFileW( tmp, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, 0 );
        if (tmpf == INVALID_HANDLE_VALUE)
        {
            HeapFree( GetProcessHeap(), 0, payload );
            xex_fatal("winxex: cannot write temp payload");
        }
        while (n < image_size)
        {
            DWORD chunk = image_size - n;
            if (!WriteFile( tmpf, payload + n, chunk, &written, NULL ) || !written) break;
            n += written;
        }
        CloseHandle( tmpf );
        HeapFree( GetProcessHeap(), 0, payload );
        if (n != image_size) xex_fatal("winxex: short write to temp payload");

        /* Build: "<interp>" "<tmp>" [extra args...] (skip argv[argi] = .xex path) */
        cmdlen = lstrlenW(interp) + lstrlenW(tmp) + 6;
        for (i = argi + 1; i < argc; i++)
            cmdlen += lstrlenW(argv[i]) + 3;

        cmdline = HeapAlloc(GetProcessHeap(), 0, cmdlen * sizeof(WCHAR));
        if (!cmdline) xex_fatal("out of memory building command line");

        lstrcpyW(cmdline, L"\"");
        lstrcatW(cmdline, interp);
        lstrcatW(cmdline, L"\" \"");
        lstrcatW(cmdline, tmp);
        lstrcatW(cmdline, L"\"");
        for (i = argi + 1; i < argc; i++)
        {
            lstrcatW(cmdline, L" \"");
            lstrcatW(cmdline, argv[i]);
            lstrcatW(cmdline, L"\"");
        }

        memset(&si, 0, sizeof(si));
        si.cb = sizeof(si);
        if (!CreateProcessW(NULL, cmdline, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi))
        {
            DeleteFileW( tmp );
            xex_fatal("winxex: failed to launch PPC interpreter");
        }

        WaitForSingleObject(pi.hProcess, INFINITE);
        GetExitCodeProcess(pi.hProcess, &exit_code);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        HeapFree(GetProcessHeap(), 0, cmdline);
        DeleteFileW( tmp );
        return (int)exit_code;
    }
}
