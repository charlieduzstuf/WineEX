/*
 * xboxkrnl.exe - Xc* crypto: SHA-1 (inline FIPS 180-1), RC4 (inline),
 * HMAC-SHA1, DES/2-key-3DES via BCrypt, portable big-number modular
 * exponentiation, and the XcUpdateCrypto dispatch vector.
 *
 * Reference: Cxbx-Reloaded src/core/kernel/exports/EmuKrnlXc.cpp +
 * src/common/crypto/{EmuSha,LibRc4,EmuDes,EmuRsa}.* (behavioural ground
 * truth; Xbox calls into these through the same CRYPTO_VECTOR dispatch
 * implemented below for XcUpdateCrypto).
 *
 * Layout notes (all from Cxbx, verified against real homebrew):
 * - Xbox SHA_CTX carries a 24-byte header ahead of the SHA1_CTX, so every
 *   XcSHA* op runs at (BYTE*)ctx + 24 (Cxbx JumpedSHAInit/Update/Final).
 * - Xbox 3DES is 2-key EDE with a 16-byte key (K1,K2); BCrypt wants 24,
 *   so XcKeyTable expands to K1|K2|K1 locally (Cxbx JumpedKeyTable).
 * - XcModExp buffers are little-endian DWORD arrays of dwN DWORDs each:
 *   result = base^exp mod modulus (Cxbx xbox_exp_mod via libtomcrypt
 *   mp_import order -1). Implemented here with portable square-and-
 *   multiply (ULONG limbs, ULONGLONG accumulators — no __int128, so this
 *   builds under both GCC/Clang and MSVC).
 * - XcPKEncPublic/XcPKDecPrivate/XcPKGetKeyLen are unimplemented stubs in
 *   Cxbx too (LOG_UNIMPLEMENTED, return 0); XcVerifyPKCS1Signature likewise
 *   returns TRUE there. We match that behaviour exactly.
 * - XcCryptService is a dummy returning 0 in Cxbx as well ("just returns
 *   zero regardless of the input arguments").
 *
 * Xbox DES key table: we store a BCRYPT_KEY_HANDLE in the first 4 bytes of
 * the caller-provided buffer (opaque to titles, never inspected by them).
 */

#include <stdarg.h>
#include <string.h>
#include "windef.h"
#include "winbase.h"
#include "winternl.h"
#include "ntstatus.h"
#include "bcrypt.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(xboxkrnl);

/* Xbox SHA context has a 24-byte header ahead of the digest state. */
#define XBOX_SHA_STATE_OFF 24

/* ======================================================================
 * Inline SHA-1 (FIPS 180-1, portable C)
 * ====================================================================== */
typedef struct {
    ULONG state[5];
    ULONG count[2];
    BYTE  buf[64];
} SHA1_CTX_INLINE;

#define ROL32(v,n) (((v)<<(n))|((v)>>(32-(n))))

static void sha1_transform(ULONG state[5], const BYTE *block)
{
    ULONG a, b, c, d, e, tmp, W[80];
    int i;
    for (i = 0; i < 16; i++)
        W[i] = ((ULONG)block[i*4]<<24)|((ULONG)block[i*4+1]<<16)|
               ((ULONG)block[i*4+2]<<8)|(ULONG)block[i*4+3];
    for (i = 16; i < 80; i++)
        W[i] = ROL32(W[i-3]^W[i-8]^W[i-14]^W[i-16],1);
    a=state[0]; b=state[1]; c=state[2]; d=state[3]; e=state[4];
#define SHA1_ROUND(f,k) tmp=ROL32(a,5)+(f)+e+(k)+W[i]; e=d; d=c; c=ROL32(b,30); b=a; a=tmp
    for (i=0;i<20;i++) SHA1_ROUND((b&c)|(~b&d), 0x5A827999u);
    for (i=20;i<40;i++) SHA1_ROUND(b^c^d, 0x6ED9EBA1u);
    for (i=40;i<60;i++) SHA1_ROUND((b&c)|(b&d)|(c&d), 0x8F1BBCDCu);
    for (i=60;i<80;i++) SHA1_ROUND(b^c^d, 0xCA62C1D6u);
#undef SHA1_ROUND
    state[0]+=a; state[1]+=b; state[2]+=c; state[3]+=d; state[4]+=e;
}

static void sha1_init(SHA1_CTX_INLINE *ctx)
{
    ctx->state[0]=0x67452301u; ctx->state[1]=0xEFCDAB89u;
    ctx->state[2]=0x98BADCFEu; ctx->state[3]=0x10325476u;
    ctx->state[4]=0xC3D2E1F0u;
    ctx->count[0]=ctx->count[1]=0;
}

static void sha1_update(SHA1_CTX_INLINE *ctx, const BYTE *data, ULONG len)
{
    ULONG j = (ctx->count[0]>>3) & 63;
    if ((ctx->count[0] += len<<3) < (len<<3)) ctx->count[1]++;
    ctx->count[1] += len>>29;
    if (j + len < 64) { memcpy(&ctx->buf[j], data, len); return; }
    memcpy(&ctx->buf[j], data, 64-j);
    sha1_transform(ctx->state, ctx->buf);
    data += 64-j; len -= 64-j;
    while (len >= 64) { sha1_transform(ctx->state, data); data+=64; len-=64; }
    memcpy(ctx->buf, data, len);
}

static void sha1_final(SHA1_CTX_INLINE *ctx, BYTE digest[20])
{
    BYTE pad[64] = {0}; ULONG i, n;
    pad[0]=0x80;
    n = ((ctx->count[0]>>3) & 63);
    if (n < 56) { sha1_update(ctx, pad, 56-n); }
    else { sha1_update(ctx, pad, 120-n); }
    pad[0]=(BYTE)(ctx->count[1]>>24); pad[1]=(BYTE)(ctx->count[1]>>16);
    pad[2]=(BYTE)(ctx->count[1]>>8);  pad[3]=(BYTE)(ctx->count[1]);
    pad[4]=(BYTE)(ctx->count[0]>>24); pad[5]=(BYTE)(ctx->count[0]>>16);
    pad[6]=(BYTE)(ctx->count[0]>>8);  pad[7]=(BYTE)(ctx->count[0]);
    sha1_update(ctx, pad, 8);
    for (i=0;i<5;i++) {
        digest[i*4]=(BYTE)(ctx->state[i]>>24); digest[i*4+1]=(BYTE)(ctx->state[i]>>16);
        digest[i*4+2]=(BYTE)(ctx->state[i]>>8); digest[i*4+3]=(BYTE)(ctx->state[i]);
    }
    SecureZeroMemory(ctx, sizeof(*ctx));
}

/* ======================================================================
 * Inline RC4 (standard, no drop — Cxbx Rc4Initialise(..., DropN=0))
 * ====================================================================== */
typedef struct { BYTE S[256]; BYTE i, j; } RC4_CTX;

static void rc4_key(RC4_CTX *ctx, ULONG len, const BYTE *key)
{
    ULONG i, j=0;
    for (i=0;i<256;i++) ctx->S[i]=(BYTE)i;
    for (i=0;i<256;i++) {
        j=(j+ctx->S[i]+key[i%len])&255;
        { BYTE t=ctx->S[i]; ctx->S[i]=ctx->S[j]; ctx->S[j]=t; }
    }
    ctx->i=ctx->j=0;
}

static void rc4_crypt(RC4_CTX *ctx, ULONG len, BYTE *data)
{
    BYTE i=ctx->i, j=ctx->j, t;
    while (len--) {
        i=(i+1)&255; j=(j+ctx->S[i])&255;
        t=ctx->S[i]; ctx->S[i]=ctx->S[j]; ctx->S[j]=t;
        *data++ ^= ctx->S[(ctx->S[i]+ctx->S[j])&255];
    }
    ctx->i=i; ctx->j=j;
}

/* ======================================================================
 * Portable big-number modular exponentiation (little-endian limbs).
 *
 * Matches Cxbx xbox_exp_mod (libtomcrypt mp_import order -1 = LE):
 *   result[0..n) = base[0..n) ^ exp[0..n) mod mod[0..n), n = Len/4 limbs.
 * Returns 1 on success, 0 on bad input (Cxbx returns 1/0 the same way).
 * O(n^2) per bit; RSA-2048 (n=64) runs in milliseconds.
 * ====================================================================== */
#define MODEXP_MAX_LIMBS 64  /* 2048-bit RSA, the largest Xbox use */

static int bn_is_zero( const ULONG *a, ULONG n )
{
    ULONG i;
    for (i = 0; i < n; i++) if (a[i]) return 0;
    return 1;
}

/* -1/0/+1 */
static int bn_cmp( const ULONG *a, const ULONG *b, ULONG n )
{
    LONG i;
    for (i = (LONG)n - 1; i >= 0; i--)
        if (a[i] != b[i]) return a[i] > b[i] ? 1 : -1;
    return 0;
}

/* a -= b (n limbs); caller guarantees a >= b. Returns the final borrow
 * (always 0 when the precondition holds). */
static ULONG bn_sub( ULONG *a, const ULONG *b, ULONG n )
{
    ULONG i;
    ULONGLONG borrow = 0;
    for (i = 0; i < n; i++)
    {
        ULONGLONG t = (ULONGLONG)a[i] - b[i] - borrow;
        a[i] = (ULONG)t;
        borrow = (t >> 63) & 1; /* 1 iff the subtraction underflowed */
    }
    return (ULONG)borrow;
}

/* c = a * b (n limbs each -> 2n+1 limbs, zeroed by caller). */
static void bn_mul( ULONG *c, const ULONG *a, const ULONG *b, ULONG n )
{
    ULONG i, j, k;
    ULONGLONG t, carry;
    for (i = 0; i < n; i++)
    {
        carry = 0;
        for (j = 0; j < n; j++)
        {
            t = (ULONGLONG)c[i+j] + (ULONGLONG)a[i] * b[j] + carry;
            c[i+j] = (ULONG)t;
            carry = t >> 32;
        }
        k = i + n;
        while (carry)
        {
            t = (ULONGLONG)c[k] + carry;
            c[k] = (ULONG)t;
            carry = t >> 32;
            k++;
        }
    }
}

/* bit length of a (up to 32*n); 0 for zero. */
static ULONG bn_bitlen( const ULONG *a, ULONG n )
{
    LONG i = (LONG)n - 1;
    ULONG v, bits = 0;
    while (i >= 0 && !a[i]) i--;
    if (i < 0) return 0;
    v = a[i];
    while (v) { bits++; v >>= 1; }
    return (ULONG)i * 32 + bits;
}

/* r = num mod m; num has up to num_limbs limbs, m has n limbs (nonzero).
 * rem_ws is n+1 limbs of caller-provided scratch (kept off static storage
 * so concurrent title threads can't race). */
static void bn_mod( ULONG *r, const ULONG *num, ULONG num_limbs,
                    const ULONG *m, ULONG n, ULONG *rem_ws )
{
    ULONG *rem = rem_ws;
    LONG i;
    ULONG k;
    ULONGLONG t;
    ULONG carry;
    for (k = 0; k <= n; k++) rem[k] = 0;
    for (i = (LONG)bn_bitlen( num, num_limbs ) - 1; i >= 0; i--)
    {
        /* rem = (rem << 1) | bit_i(num); rem < 2m beforehand, so the
         * result stays below 2^32(n+1) and the subtract below brings it
         * back under m (which fits n limbs). */
        carry = (num[i / 32] >> (i % 32)) & 1;
        for (k = 0; k <= n; k++)
        {
            t = ((ULONGLONG)rem[k] << 1) | carry;
            rem[k] = (ULONG)t;
            carry = (ULONG)(t >> 32);
        }
        if (rem[n] || bn_cmp( rem, m, n ) >= 0)
            rem[n] -= bn_sub( rem, m, n );
    }
    memcpy( r, rem, n * sizeof(ULONG) );
}

/* r = a * b mod m (all n limbs); prod is 2n+1 limbs and rem n+1 limbs
 * of scratch. Separate buffers are required: bn_mod zeroes its workspace
 * before reading the input. */
static void bn_mul_mod( ULONG *r, const ULONG *a, const ULONG *b,
                        const ULONG *m, ULONG n, ULONG *prod, ULONG *rem )
{
    ULONG k;
    for (k = 0; k < 2 * n + 1; k++) prod[k] = 0;
    bn_mul( prod, a, b, n );
    bn_mod( r, prod, 2 * n + 1, m, n, rem );
}

static LONG xc_modexp_le( void *Result, const void *Base, const void *Exp,
                          const void *Modulus, ULONG n )
{
    /* All state on the stack: titles may call XcModExp concurrently. */
    ULONG r[MODEXP_MAX_LIMBS], b[MODEXP_MAX_LIMBS];
    ULONG e[MODEXP_MAX_LIMBS], m[MODEXP_MAX_LIMBS];
    ULONG prod[2 * MODEXP_MAX_LIMBS + 1], rem[MODEXP_MAX_LIMBS + 1];
    LONG i;
    if (!Result || !Base || !Exp || !Modulus || !n || n > MODEXP_MAX_LIMBS)
        return 0;
    memcpy( b, Base, n * sizeof(ULONG) );
    memcpy( e, Exp, n * sizeof(ULONG) );
    memcpy( m, Modulus, n * sizeof(ULONG) );
    if (bn_is_zero( m, n )) return 0;
    memset( r, 0, n * sizeof(ULONG) );
    r[0] = 1;
    bn_mod( b, b, n, m, n, rem ); /* reduce base first */
    for (i = (LONG)bn_bitlen( e, n ) - 1; i >= 0; i--)
    {
        bn_mul_mod( r, r, r, m, n, prod, rem ); /* r = r^2 */
        if ((e[i / 32] >> (i % 32)) & 1)
            bn_mul_mod( r, r, b, m, n, prod, rem ); /* r = r*b */
    }
    memcpy( Result, r, n * sizeof(ULONG) );
    memset( r, 0, sizeof(r) );
    memset( b, 0, sizeof(b) );
    memset( e, 0, sizeof(e) );
    memset( m, 0, sizeof(m) );
    memset( prod, 0, sizeof(prod) );
    memset( rem, 0, sizeof(rem) );
    return 1;
}

/* ======================================================================
 * DES/3DES via BCrypt.
 *
 * Xbox XcKeyTable stores the key schedule in a caller-provided buffer;
 * we store a BCRYPT_KEY_HANDLE in the first 4 bytes of that buffer.
 * Type 0 = DES (8-byte key); otherwise 2-key 3DES with a 16-byte key
 * (K1,K2), expanded to K1|K2|K1 for BCrypt (Cxbx JumpedKeyTable).
 * ====================================================================== */
static BCRYPT_ALG_HANDLE bh_des   = NULL;
static BCRYPT_ALG_HANDLE bh_3des  = NULL;
static LONG bh_once = 0;

static void bcrypt_init(void)
{
    if (InterlockedCompareExchange(&bh_once, 1, 0)) return;
    BCryptOpenAlgorithmProvider(&bh_des,  BCRYPT_DES_ALGORITHM,  NULL, 0);
    BCryptOpenAlgorithmProvider(&bh_3des, BCRYPT_3DES_ALGORITHM, NULL, 0);
}

static inline BCRYPT_ALG_HANDLE alg_for_type(ULONG type)
{
    return (type == 0) ? bh_des : bh_3des;
}

/* ======================================================================
 * CRYPTO_VECTOR dispatch (XcUpdateCrypto).
 *
 * Order matches Cxbx DefaultCryptoStruct: SHAInit, SHAUpdate, SHAFinal,
 * RC4Key, RC4Crypt, HMAC, PKEncPublic, PKDecPrivate, PKGetKeyLen,
 * VerifyPKCS1Signature, ModExp, DESKeyParity, KeyTable, BlockCrypt,
 * BlockCryptCBC, CryptService (16 entries). Tests rely on ModExp being
 * entry index 10.
 * ====================================================================== */
typedef void   (WINAPI *PC_XC_SHAINIT)( void * );
typedef void   (WINAPI *PC_XC_SHAUPDATE)( void *, void *, ULONG );
typedef void   (WINAPI *PC_XC_SHAFINAL)( void *, BYTE * );
typedef void   (WINAPI *PC_XC_RC4KEY)( void *, ULONG, const BYTE * );
typedef void   (WINAPI *PC_XC_RC4CRYPT)( void *, ULONG, BYTE * );
typedef void   (WINAPI *PC_XC_HMAC)( const BYTE *, ULONG, const BYTE *, ULONG,
                                     const BYTE *, ULONG, BYTE * );
typedef LONG   (WINAPI *PC_XC_PK)( void *, void *, void * );
typedef LONG   (WINAPI *PC_XC_PKKEYLEN)( void * );
typedef LONG   (WINAPI *PC_XC_MODEXP)( void *, void *, void *, void *, ULONG );
typedef void   (WINAPI *PC_XC_DESPARITY)( BYTE *, ULONG );
typedef void   (WINAPI *PC_XC_KEYTABLE)( ULONG, void *, void * );
typedef void   (WINAPI *PC_XC_BLOCK)( ULONG, void *, void *, void *, ULONG );
typedef void   (WINAPI *PC_XC_CBC)( ULONG, ULONG, void *, void *, void *, ULONG, void * );
typedef LONG   (WINAPI *PC_XC_CRYPTSERVICE)( ULONG, void * );

struct xc_crypto_vector
{
    PC_XC_SHAINIT   pXcSHAInit;
    PC_XC_SHAUPDATE pXcSHAUpdate;
    PC_XC_SHAFINAL  pXcSHAFinal;
    PC_XC_RC4KEY     pXcRC4Key;
    PC_XC_RC4CRYPT   pXcRC4Crypt;
    PC_XC_HMAC       pXcHMAC;
    PC_XC_PK         pXcPKEncPublic;
    PC_XC_PK         pXcPKDecPrivate;
    PC_XC_PKKEYLEN   pXcPKGetKeyLen;
    PC_XC_PK         pXcVerifyPKCS1Signature;
    PC_XC_MODEXP     pXcModExp;
    PC_XC_DESPARITY  pXcDESKeyParity;
    PC_XC_KEYTABLE   pXcKeyTable;
    PC_XC_BLOCK      pXcBlockCrypt;
    PC_XC_CBC        pXcBlockCryptCBC;
    PC_XC_CRYPTSERVICE pXcCryptService;
};

/* Forward declarations of the default implementations. */
static void default_sha_init( void *ctx );
static void default_sha_update( void *ctx, void *data, ULONG len );
static void default_sha_final( void *ctx, BYTE *digest );
static void default_rc4_key( void *ctx, ULONG len, const BYTE *key );
static void default_rc4_crypt( void *ctx, ULONG len, BYTE *data );
static void default_hmac( const BYTE *Key, ULONG KeyLen, const BYTE *Data, ULONG DataLen,
                           const BYTE *Data2, ULONG Data2Len, BYTE *Digest );
static void default_des_parity( BYTE *Key, ULONG len );
static void default_key_table( ULONG Type, void *KeyTable, void *Key );
static void default_block_crypt( ULONG Type, void *Out, void *In, void *KeyTable, ULONG Enc );
static void default_block_cbc( ULONG Type, ULONG Len, void *Out, void *In,
                                void *KeyTable, ULONG Enc, void *Feedback );
static LONG default_modexp( void *Result, void *Base, void *Exp, void *Modulus, ULONG Len );

static const struct xc_crypto_vector xc_default_vector =
{
    default_sha_init,
    default_sha_update,
    default_sha_final,
    default_rc4_key,
    default_rc4_crypt,
    default_hmac,
    NULL, /* PKEncPublic: unimplemented in Cxbx too */
    NULL, /* PKDecPrivate: unimplemented in Cxbx too */
    NULL, /* PKGetKeyLen: unimplemented in Cxbx too */
    NULL, /* VerifyPKCS1Signature: Cxbx returns TRUE; handled in wrapper */
    default_modexp,
    default_des_parity,
    default_key_table,
    default_block_crypt,
    default_block_cbc,
    NULL, /* CryptService: dummy returning 0; handled in wrapper */
};

static struct xc_crypto_vector xc_current_vector =
{
    default_sha_init,
    default_sha_update,
    default_sha_final,
    default_rc4_key,
    default_rc4_crypt,
    default_hmac,
    NULL, NULL, NULL, NULL,
    default_modexp,
    default_des_parity,
    default_key_table,
    default_block_crypt,
    default_block_cbc,
    NULL,
};

/* ======================================================================
 * Default implementations (wired into the vector above)
 * ====================================================================== */
static void default_sha_init( void *ctx )
{
    sha1_init( (SHA1_CTX_INLINE *)((BYTE *)ctx + XBOX_SHA_STATE_OFF) );
}

static void default_sha_update( void *ctx, void *data, ULONG len )
{
    sha1_update( (SHA1_CTX_INLINE *)((BYTE *)ctx + XBOX_SHA_STATE_OFF),
                 (const BYTE *)data, len );
}

static void default_sha_final( void *ctx, BYTE *digest )
{
    sha1_final( (SHA1_CTX_INLINE *)((BYTE *)ctx + XBOX_SHA_STATE_OFF), digest );
}

static void default_rc4_key( void *ctx, ULONG len, const BYTE *key )
{
    rc4_key( (RC4_CTX *)ctx, len, key );
}

static void default_rc4_crypt( void *ctx, ULONG len, BYTE *data )
{
    rc4_crypt( (RC4_CTX *)ctx, len, data );
}

/* XcHMAC(Key,KeyLen,Data,DataLen,Data2,Data2Len,OutDigest[20]).
 * Keys longer than the 64-byte block are truncated (Cxbx JumpedHMAC). */
static void default_hmac( const BYTE *Key, ULONG KeyLen,
                           const BYTE *Data, ULONG DataLen,
                           const BYTE *Data2, ULONG Data2Len,
                           BYTE *Digest )
{
    BYTE kpad[64], ipad[64], opad[64], inner[20];
    SHA1_CTX_INLINE ctx;
    ULONG i;

    if (KeyLen > 64) KeyLen = 64;
    memset(kpad, 0, 64);
    if (Key && KeyLen) memcpy(kpad, Key, KeyLen);

    for (i=0;i<64;i++) { ipad[i]=kpad[i]^0x36; opad[i]=kpad[i]^0x5c; }
    sha1_init(&ctx);
    sha1_update(&ctx, ipad, 64);
    if (Data && DataLen)   sha1_update(&ctx, (const BYTE*)Data,  DataLen);
    if (Data2 && Data2Len) sha1_update(&ctx, (const BYTE*)Data2, Data2Len);
    sha1_final(&ctx, inner);

    sha1_init(&ctx);
    sha1_update(&ctx, opad, 64);
    sha1_update(&ctx, inner, 20);
    sha1_final(&ctx, Digest);
    SecureZeroMemory(kpad, sizeof(kpad));
    SecureZeroMemory(ipad, sizeof(ipad));
    SecureZeroMemory(opad, sizeof(opad));
}

/* XcDESKeyParity: set odd parity bit (bit 0) on each DES key byte
 * (same as mbedtls_des_key_set_parity used by Cxbx). */
static void default_des_parity( BYTE *Key, ULONG len )
{
    ULONG i, cnt;
    BYTE b, v;
    for (i = 0; i < len; i++) {
        b = Key[i] & 0xFE;
        cnt = 0; v = b >> 1;
        while (v) { cnt += v & 1; v >>= 1; }
        Key[i] = b | (cnt & 1 ? 0 : 1);
    }
}

/* XcKeyTable: import DES (8-byte) or 2-key 3DES (16-byte K1,K2) key,
 * storing a BCRYPT_KEY_HANDLE at table[0]. 3DES expands to K1|K2|K1. */
static void default_key_table( ULONG Type, void *KeyTable, void *Key )
{
    BCRYPT_KEY_HANDLE *hkey = (BCRYPT_KEY_HANDLE *)KeyTable;
    BYTE keybuf[24];
    ULONG keylen;
    bcrypt_init();
    if (Type == 0)
    {
        memcpy( keybuf, Key, 8 );
        keylen = 8;
    }
    else
    {
        memcpy( keybuf, Key, 16 );
        memcpy( keybuf + 16, Key, 8 ); /* K3 = K1 */
        keylen = 24;
    }
    if (*hkey) { BCryptDestroyKey(*hkey); *hkey = NULL; }
    BCryptGenerateSymmetricKey(alg_for_type(Type), hkey, NULL, 0,
                               keybuf, keylen, 0);
    SecureZeroMemory(keybuf, sizeof(keybuf));
}

/* XcBlockCrypt: ECB single block, Enc=1 encrypt, Enc=0 decrypt */
static void default_block_crypt( ULONG Type, void *Out, void *In,
                                 void *KeyTable, ULONG Enc )
{
    BCRYPT_KEY_HANDLE hkey = *(BCRYPT_KEY_HANDLE *)KeyTable;
    ULONG res;
    if (!hkey) return;
    if (Enc)
        BCryptEncrypt(hkey, (BYTE *)In, 8, NULL, NULL, 0, (BYTE *)Out, 8, &res, 0);
    else
        BCryptDecrypt(hkey, (BYTE *)In, 8, NULL, NULL, 0, (BYTE *)Out, 8, &res, 0);
}

/* XcBlockCryptCBC: CBC mode, Feedback is IV (modified in-place) */
static void default_block_cbc( ULONG Type, ULONG Len, void *Out,
                               void *In, void *KeyTable, ULONG Enc,
                               void *Feedback )
{
    BCRYPT_KEY_HANDLE hkey = *(BCRYPT_KEY_HANDLE *)KeyTable;
    ULONG res;
    if (!hkey) return;
    if (Enc)
        BCryptEncrypt(hkey, (BYTE *)In, Len, NULL,
                      (BYTE *)Feedback, 8, (BYTE *)Out, Len, &res, 0);
    else
        BCryptDecrypt(hkey, (BYTE *)In, Len, NULL,
                      (BYTE *)Feedback, 8, (BYTE *)Out, Len, &res, 0);
}

/* ======================================================================
 * Exported Xc* wrappers — dispatch through the (possibly title-updated)
 * crypto vector, exactly like Cxbx routes every Xc* through
 * UpdatedCryptoStruct.
 * ====================================================================== */
void WINAPI XBOXKRNL_XcSHAInit(void *ctx)
{
    xc_current_vector.pXcSHAInit( ctx );
}

void WINAPI XBOXKRNL_XcSHAUpdate(void *ctx, void *data, ULONG len)
{
    xc_current_vector.pXcSHAUpdate( ctx, data, len );
}

void WINAPI XBOXKRNL_XcSHAFinal(void *ctx, BYTE *digest)
{
    xc_current_vector.pXcSHAFinal( ctx, digest );
}

void WINAPI XBOXKRNL_XcRC4Key(void *ctx, ULONG len, const BYTE *key)
{
    xc_current_vector.pXcRC4Key( ctx, len, key );
}

void WINAPI XBOXKRNL_XcRC4Crypt(void *ctx, ULONG len, BYTE *data)
{
    xc_current_vector.pXcRC4Crypt( ctx, len, data );
}

void WINAPI XBOXKRNL_XcHMAC(const BYTE *Key, ULONG KeyLen,
                              const BYTE *Data, ULONG DataLen,
                              const BYTE *Data2, ULONG Data2Len,
                              BYTE *Digest)
{
    xc_current_vector.pXcHMAC( Key, KeyLen, Data, DataLen, Data2, Data2Len, Digest );
}

/* XcDESKeyParity(Key, len) */
void WINAPI XBOXKRNL_XcDESKeyParity(BYTE *Key, ULONG len)
{
    xc_current_vector.pXcDESKeyParity( Key, len );
}

/* XcKeyTable(Type, KeyTable, Key) */
void WINAPI XBOXKRNL_XcKeyTable(ULONG Type, void *KeyTable, void *Key)
{
    xc_current_vector.pXcKeyTable( Type, KeyTable, Key );
}

/* XcBlockCrypt(Type, Out, In, KeyTable, Enc) */
void WINAPI XBOXKRNL_XcBlockCrypt(ULONG Type, void *Out, void *In,
                                    void *KeyTable, ULONG Enc)
{
    xc_current_vector.pXcBlockCrypt( Type, Out, In, KeyTable, Enc );
}

/* XcBlockCryptCBC(Type, Len, Out, In, KeyTable, Enc, Feedback) */
void WINAPI XBOXKRNL_XcBlockCryptCBC(ULONG Type, ULONG Len, void *Out,
                                       void *In, void *KeyTable, ULONG Enc,
                                       void *Feedback)
{
    xc_current_vector.pXcBlockCryptCBC( Type, Len, Out, In, KeyTable, Enc, Feedback );
}

/* ======================================================================
 * RSA / PKCS#1: unimplemented stubs with Cxbx parity (Cxbx
 * LOG_UNIMPLEMENTED + return 0, and Verify returning TRUE).
 * ====================================================================== */
LONG WINAPI XBOXKRNL_XcModExp(void *Result, void *Base, void *Exp,
                                void *Modulus, ULONG Len)
{
    if (xc_current_vector.pXcModExp)
        return xc_current_vector.pXcModExp( Result, Base, Exp, Modulus, Len );
    if (Result) memset(Result, 0, Len);
    return 0;
}

LONG WINAPI XBOXKRNL_XcPKEncPublic(void *Key, void *Input, void *Output)
{
    if (xc_current_vector.pXcPKEncPublic)
        return xc_current_vector.pXcPKEncPublic( Key, Input, Output );
    FIXME("XcPKEncPublic: stub (unimplemented in Cxbx too)\n");
    return 0;
}

LONG WINAPI XBOXKRNL_XcPKDecPrivate(void *Key, void *Input, void *Output)
{
    if (xc_current_vector.pXcPKDecPrivate)
        return xc_current_vector.pXcPKDecPrivate( Key, Input, Output );
    FIXME("XcPKDecPrivate: stub (unimplemented in Cxbx too)\n");
    return 0;
}

LONG WINAPI XBOXKRNL_XcPKGetKeyLen(void *Key)
{
    if (xc_current_vector.pXcPKGetKeyLen)
        return xc_current_vector.pXcPKGetKeyLen( Key );
    return 0;
}

LONG WINAPI XBOXKRNL_XcVerifyPKCS1Signature(void *Hash, void *PublicKey, void *Signature)
{
    if (xc_current_vector.pXcVerifyPKCS1Signature)
        return xc_current_vector.pXcVerifyPKCS1Signature( Hash, PublicKey, Signature );
    TRACE("XcVerifyPKCS1Signature: no verifier installed, reporting verified (Cxbx parity)\n");
    return 1; /* TRUE = verified */
}

/* ======================================================================
 * XcCryptService - dummy returning 0 (Cxbx: "just returns zero
 * regardless of the input arguments, which are left unchanged").
 * ====================================================================== */
LONG WINAPI XBOXKRNL_XcCryptService(ULONG ServiceCode, void *ServiceData)
{
    if (xc_current_vector.pXcCryptService)
        return xc_current_vector.pXcCryptService( ServiceCode, ServiceData );
    return 0;
}

/* ======================================================================
 * XcUpdateCrypto(NewVector, ROMVector) - install title-supplied crypto
 * implementations for non-NULL entries; return the previous (ROM)
 * implementations when asked (Cxbx XcUpdateCrypto, ordinal 351).
 * ====================================================================== */
void WINAPI XBOXKRNL_XcUpdateCrypto(void *CryptoData, void *UpdateFlags)
{
    const struct xc_crypto_vector *nv = (const struct xc_crypto_vector *)CryptoData;
    struct xc_crypto_vector *rom = (struct xc_crypto_vector *)UpdateFlags;
    void **cur, **newv;
    ULONG i;
    /* Hand back the ROM (default) implementations, like Cxbx does. */
    if (rom) *rom = xc_default_vector;
    if (!nv) return;
    /* Install entry-by-entry so a partially-filled vector can't NULL out
     * implementations the title didn't mean to replace. */
    cur = (void **)&xc_current_vector;
    newv = (void **)nv;
    for (i = 0; i < sizeof(xc_current_vector) / sizeof(void *); i++)
        if (newv[i]) cur[i] = newv[i];
}
