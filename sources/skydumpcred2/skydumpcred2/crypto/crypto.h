// PureNoise CryptoLib (c) 1997-2004, PureNoise Ltd Vaduz <www.cryptolib.com>

#ifndef _crypto_h_
#define _crypto_h_

#if defined(__MACH__) && defined(__APPLE__)
	#include <pthread.h>
#endif

#ifndef ECC_BITS
	//! Strength of Elliptic Curve algorithms is currently about a half the size of its modulus.
	//! Therefore for 256-bit symmetric keys 512-bit ECC keys are required. For 128-bit symmetric keys 512-bit ECC keys are required.
	//! \brief Elliptic Curve key size in bits (normally should be defined with -DECC_BITS=n compiler option, minimum 256)
	#define ECC_BITS		512
#endif

//! \brief it's <b>extern</b> for C and it's <b>extern "C"</b> for C++
#ifndef EXTERN
	#ifdef __cplusplus
		#define EXTERN extern "C"
	#else	// __cplusplus
		#define EXTERN extern
	#endif	// __cplusplus
#endif // EXTERN

#if defined(_M_ALPHA) || defined(__alpha) || defined(_M_IX86) || defined(__i386__) || defined(__vax__)
	#undef BIG_ENDIAN
	//! \brief defined for Intel/Alpha/Vax (Least Significant First byte order)
	#ifndef LITTLE_ENDIAN
		#define LITTLE_ENDIAN
	#endif
#else
	#undef LITTLE_ENDIAN
	//! \brief defined for weird processors like Sparc etc. (Most Significant First byte order)
	#ifndef BIG_ENDIAN
		#define BIG_ENDIAN
	#endif
#endif // BIG/LITTLE ENDIAN

// basic types and platform-dependant fast rotation and byte swapping functions. I wish there was a bit count operation too...

#ifndef u8
	#define u8				unsigned char
#endif
#ifndef u16
	#define u16				unsigned short
#endif
#ifndef u32
	#define u32				unsigned long
#endif

#if defined(__GNUC__)
	
	#ifndef u64
		#define u64				unsigned long long
	#endif
 	#ifndef __cdecl
		#define __cdecl			__attribute__((cdecl))
	#endif
	#ifndef __fastcall
		#define __fastcall		__attribute__((fastcall))
	#endif
	#ifndef __inline
		#define __inline		inline
	#endif
	#ifndef __forceinline
		#define __forceinline	__inline__
	#endif
	
#elif defined(_MSC_VER)
	
	#ifndef u64
		#define u64				unsigned __int64
	#endif
	#include <stdlib.h>
	#pragma intrinsic 			(_lrotr, _lrotl)
	
#elif defined(__MACH__) && defined(__APPLE__)

	#ifndef u64
		#define u64				unsigned long long
	#endif
	#ifndef __cdecl
		#define __cdecl
	#endif
	#ifndef __fastcall
		#define __fastcall
	#endif
	#ifndef __forceinline
		#define __forceinline	__inline
	#endif
	
#endif

// slow basic rotations and byte swapping, useful for constants or if there's no other choice

//! \brief Multiple shifts right 32-bit rotation operation for constants
//! \returns x rotated right by n bit
#ifndef ROTR32
	#define ROTR32(x, n)			((((u32) (x)) >> ((n) & 31)) | (((u32) (x)) << ((0-(n)) & 31)))
#endif
//! \brief Multiple shifts left 32-bit rotation operation for constants
//! \returns x rotated left by n bit
#ifndef ROTL32
	#define ROTL32(x, n)			((((u32) (x)) << ((n) & 31)) | (((u32) (x)) >> ((0-(n)) & 31)))
#endif
//! \brief Multiple shifts right 64-bit rotation operation for constants
//! \returns x rotated right by n bit
#ifndef ROTR64
	#define ROTR64(x, n)			((((u64) (x)) >> ((n) & 63)) | (((u64) (x)) << ((0-(n)) & 63)))
#endif
//! \brief Multiple shifts left 64-bit rotation operation for constants
//! \returns x rotated left by n bit
#ifndef ROTL64
	#define ROTL64(x, n)			((((u64) (x)) << ((n) & 63)) | (((u64) (x)) >> ((0-(n)) & 63)))
#endif
//! \brief Multiple shifts 32-bit byte swapping operation for constants
//! \returns x in the opposite byte order
#ifndef BSWAP32
	#define BSWAP32(x)				((ROTL32 ((u32) (x), 8) & 0x00FF00FFU) | (ROTR32 ((u32) (x), 8) & 0xFF00FF00U))
#endif

//! \brief Multiple shifts 64-bit byte swapping operation for constants
//! \returns x in the opposite byte order
#if defined (__GNUG__) || defined (__APPLE__)
	#ifndef BSWAP64
		#define BSWAP64(x)			((ROTL64 ((u64) (x), 8) & 0x000000ff000000ffLL) | (ROTL64 ((u64) (x), 24) & 0x0000ff000000ff00LL) | (ROTR64 ((u64) (x), 24) & 0x00ff000000ff0000LL) | (ROTR64 ((u64) (x), 8) & 0xff000000ff000000LL))
	#endif
#else
	#ifndef BSWAP64
		#define BSWAP64(x)			((ROTL64 ((u64) (x), 8) & 0x000000ff000000ffUL) | (ROTL64 ((u64) (x), 24) & 0x0000ff000000ff00UL) | (ROTR64 ((u64) (x), 24) & 0x00ff000000ff0000UL) | (ROTR64 ((u64) (x), 8) & 0xff000000ff000000UL))
	#endif
#endif

//! \brief Faster function-based right 32-bit rotation (should not be used for constants)
//! \returns x rotated right by n bit
#ifndef rotr32
#define rotr32(x, n)				_lrotr (x, n)	// using ROR x,n on Intel
#endif
//! \brief Faster function-based left 32-bit rotation (should not be used for constants)
//! \returns x rotated left by n bit
#ifndef rotl32
#define rotl32(x, n)				_lrotl (x, n)	// using ROL x,n on Intel
#endif
//! \brief Faster function-based right 64-bit rotation (should not be used for constants)
//! \returns x rotated right by n bit
#ifndef rotr64
#define rotr64(x, n)				ROTR64 (x, n)	// I haven't seen built-in 64-bit rotation functions yet, sticking with slower shifts for now
#endif
//! \brief Faster function-based left 64-bit rotation (should not be used for constants)
//! \returns x rotated left by n bit
#ifndef rotl64
#define rotl64(x, n)				ROTL64 (x, n)	// I haven't seen built-in 64-bit rotation functions yet, sticking with slower shifts for now
#endif
//! \brief Faster function-based 64-bit byte swapping (should not be used for constants)
//! \returns x in the opposite byte order
#if defined (__GNUG__) || defined (__APPLE__)
	#define bswap64(x)				((rotl64 ((u64) (x), 8) & 0x000000ff000000ffLL) | (rotl64 ((u64) (x), 24) & 0x0000ff000000ff00LL) | (rotr64 ((u64) (x), 24) & 0x00ff000000ff0000LL) | (rotr64 ((u64) (x), 8) & 0xff000000ff000000LL))
#else
	#define bswap64(x)				((rotl64 ((u64) (x), 8) & 0x000000ff000000ffUL)  | (rotl64 ((u64) (x), 24) & 0x0000ff000000ff00UL) | (rotr64 ((u64) (x), 24) & 0x00ff000000ff0000UL) | (rotr64 ((u64) (x), 8) & 0xff000000ff000000UL))
#endif

#include <string.h>	// is needed by all platforms for memset, memcpy etc

//! \def hex_sleep \brief 32-bit sleep function (high 16-bit word represents the number of seconds, low 16-bit word represents the fraction of a second)
#if defined (WIN32) || defined (_WIN32) || defined (WIN32_WINNT) || defined (_WIN32_WINNT) || defined (__WIN32__) || defined (WINDOWS) || defined (_WINDOWS)
	
	#include <process.h>
#if (_WIN32_WINNT < 0x0400)
	extern u32 __stdcall	SwitchToThread (void);
#endif
	#define hex_sleep(n)			SleepEx (((n) + 63) >> 6, 1)
	#define thread_yield()			SwitchToThread ()
	#define bzero(a,b)				memset (a, 0, b)
	#define flockfile(x)
	#define funlockfile(x)
	
#else
	
	#include <time.h>
	#include <sched.h>
	#include <strings.h>
	
	#ifndef SOCKET
		#define SOCKET					int
	#endif
	#ifndef closesocket
		#define closesocket(a)			close(a)
	#endif
	#ifndef recv
		#define recv(a,b,c,d)			read(a,b,c)
	#endif
	#ifndef _rmtmp
		#define	_rmtmp()
	#endif
	#ifndef send
		#define send(a,b,c,d)			write(a,b,c)
	#endif
	#ifndef _snprintf
		#define _snprintf				snprintf
	#endif
	#ifndef thread_yield
		#define thread_yield()			sched_yield()
	#endif
	
	static __forceinline u32 __cdecl hex_sleep (u32 n)
	{
		struct timespec req = {n >> 16, (n & 0xFFFFU) * 0x5F5U + 1};
		struct timespec rem;
		
		nanosleep (&req, &rem);
		return (rem.tv_sec << 16) + (rem.tv_nsec + 0x5F4U) / 0x5F5U;
	}
	
#endif

//! \brief The most important union for optimal byte/word/dword/qword manipulations
#ifndef _OCTET_
#define _OCTET_
typedef union _OCTET
{
	unsigned __int64		u64n[1];
	unsigned long			u32n[2];
	unsigned char			u8n[8];
	u64				Q[1];
	u32				D[2];
	u16				W[4];
	u8				B[8];
}	OCTET;
#endif


#define BITCOUNT_TYPE				u32
#define BIT(C)						(((BITCOUNT_TYPE)1)<<((C)&(sizeof(BITCOUNT_TYPE)*8-1)))
#define BIT_MASK(C)					(((BITCOUNT_TYPE)-1)/(BIT(BIT(C))+1))
#define BIT_COUNT(x,C)				(((x)&BIT_MASK(C))+(((x)>>C)&BIT_MASK(C)))

static __forceinline BITCOUNT_TYPE __cdecl bit_count (BITCOUNT_TYPE n)
{
	n = BIT_COUNT (n, 0);
	n = BIT_COUNT (n, 1);
	n = BIT_COUNT (n, 2);
	n = BIT_COUNT (n, 3);
	n = BIT_COUNT (n, 4);
	return n;
}

//! \def bswap32 \brief 32-bit byte swapping for variables (should not be used for constants)
//! \def bswap32 \returns x in the opposite byte order

//! \def clock_counter \brief the most sensitive time/clock counter available, the best source of randomness
//! \def clock_counter \returns processor clock counter

#if (defined(_MSC_VER) || defined (__GNUC__)) && (defined (_M_IX86) || defined (__i386__) || defined (i386))
	#if defined(_MSC_VER)
		#define CRYPTO_INLINE_ASM 3
		#pragma warning (push)
		#pragma warning (disable:4035)
		static __forceinline u32 __cdecl bswap32 (u32 x) {__asm {mov eax,x} __asm {bswap eax}}	// a faster function implementation for variables
		static __forceinline u64 __cdecl clock_counter (void) { __asm {_emit 0x0F} __asm {_emit 0x31} }
		#pragma warning (pop)
	#else	// GCC
		#define CRYPTO_INLINE_ASM 4
		static __forceinline u32 _lrotl (u32 x, u32 r) { return (x << r) | (x >> (32-r)); }
		static __forceinline u32 _lrotr (u32 x, u32 r) { return (x >> r) | (x << (32-r)); }
		static __forceinline u32 bswap32 (u32 x) { __asm__ ("bswapl %0" : "=r" (x) : "0" (x)); return x; }
		static __forceinline u64 clock_counter (void) { register OCTET r; __asm__ __volatile__ (".byte 0x0F, 0x31" : "=a" (r.D[0]), "=d" (r.D[1])); return r.Q[0]; }
	#endif
#elif defined (__GNUC__) && (defined (sparc) || defined (__sparc) || defined (sun) || defined (__sun))
		#define CRYPTO_INLINE_ASM 5
	#ifndef bswap32					// need a faster function implementation for variables
		#define bswap32(x)			((rotl32 ((u32)(x), 8) & 0x00FF00FFU) | (rotr32 ((u32)(x), 8) & 0xFF00FF00U))
	#endif
	#ifdef __sparc_v9__
	extern u8 clock_counter_type;
	static __forceinline u64 clock_counter (void)
	{
		register u32 x, y;
		
		if (clock_counter_type == 1)
		{
			__asm__ __volatile__ ("rd %%tick, %0; clruw %0, %1; srlx %0, 32, %0" : "=r" (x), "=r" (y) : "0" (x), "1" (y));
			return ((u64) x << 32) | y;
		}
		return gethrtime ();
	}
	#else
		#define clock_counter		gethrtime
	#endif // __sparc_v9__
	static __forceinline u32 _beginthread (void (__cdecl *proc) (void *), u32 stack_size, void *arg)
	{
		u32			tid = 0xFFFFFFFFU;
		thr_create (0, stack_size, &proc, arg, 0, &tid);
		return tid;
	}
	
#else
	
	#ifndef bswap32					/* should be a faster function implementation for variables */
		#define bswap32(x)			((rotl32 ((u32)(x), 8) & 0x00FF00FFU) | (rotr32 ((u32)(x), 8) & 0xFF00FF00U))
	#endif
	
	#if defined(__MACH__) && defined(__APPLE__)
	// TODO: get the code below fixed
		#include <stdint.h>
		//#include <kern/clock.h>
		//extern void			clock_get_system_nanotime(
		//					uint32_t			*secs,
		//				  uint32_t			*nanosecs);
		static __forceinline u64 clock_counter (void)
		{
			//uint32_t s, ns;
			//clock_get_system_nanotime( &s, &ns );
			//return (((u64) s) << 32) | ns;
			return time(0);
		}
	
		static __forceinline u32 _beginthread (void * (*func) (void *), u32 stackSize, void *arg)
		{
			pthread_t thread;
			return pthread_create (&thread, 0, func, arg);
		}
		
	#else
		EXTERN u64			clock_counter (void);
		#include <stdint.h>
		#include <kern/clock.h>
		extern void			clock_get_system_nanotime(
							uint32_t			*secs,
						  uint32_t			*nanosecs);
		static __forceinline u64 clock_counter (void)
		{
			uint32_t s, ns;
			clock_get_system_nanotime( &s, &ns );
			return (((u64) s) << 32) | ns;
		}
	
		static __forceinline u32 _beginthread (void * (*func) (void *), u32 stackSize, void *arg)
		{
			pthread_t thread;
			return pthread_create (&thread, 0, func, arg);
		}
		
	#endif	/* APPLE */

#endif

#ifdef CRYPTO_INLINE_ASM
	#ifdef CRYPTO_NOASM
		#undef CRYPTO_NOASM
	#endif
#else
	#ifndef CRYPTO_NOASM
		#define CRYPTO_NOASM
	#endif
#endif

//! \def LSF16	\brief slow 16-bit processor dependant byte ordering for constants
//! \def LSF16	\returns unchanged 16 bit x for Intel and byte swapped x for Sparc

//! \def LSF32	\brief slow 32-bit processor dependant byte ordering for constants
//! \def LSF32	\returns unchanged 32 bit x for Intel and byte swapped x for Sparc

//! \def LSF64	\brief slow 64-bit processor dependant byte ordering for constants
//! \def LSF64	\returns unchanged 64 bit x for Intel and byte swapped x for Sparc

//! \def LSF64D	\brief slow 64-bit processor dependant dword ordering for constants
//! \def LSF64D	\returns unchanged 64 bit x for Intel and 32-bit word swapped x for Sparc

//! \def MSF16	\brief slow 16-bit processor dependant byte ordering for constants
//! \def MSF16	\returns unchanged 16 bit x for Sparc and byte swapped x for Intel

//! \def MSF32	\brief slow 32-bit processor dependant byte ordering for constants
//! \def MSF32	\returns unchanged 32 bit x for Sparc and byte swapped x for Intel

//! \def MSF64	\brief slow 64-bit processor dependant byte ordering for constants
//! \def MSF64	\returns unchanged 64 bit x for Sparc and byte swapped x for Intel

//! \def lsf16	\brief fast 16-bit processor dependant byte ordering for variables
//! \def lsf16	\returns unchanged 16 bit x for Intel and byte swapped x for Sparc

//! \def lsf32	\brief fast 32-bit processor dependant byte ordering for variables
//! \def lsf32	\returns unchanged 32 bit x for Intel and byte swapped x for Sparc

//! \def lsf64	\brief fast 64-bit processor dependant byte ordering for variables
//! \def lsf64	\returns unchanged 64 bit x for Intel and byte swapped x for Sparc

//! \def msf16	\brief fast 16-bit processor dependant byte ordering for variables
//! \def msf16	\returns unchanged 16 bit x for Sparc and byte swapped x for Intel

//! \def msf32	\brief fast 32-bit processor dependant byte ordering for variables
//! \def msf32	\returns unchanged 32 bit x for Sparc and byte swapped x for Intel

//! \def msf64	\brief fast 64-bit processor dependant byte ordering for variables
//! \def msf64	\returns unchanged 64 bit x for Sparc and byte swapped x for Intel

//! \def ord2	\brief pair reordering ensuring the same order on any processor
//! \def ord2	\returns unchanged index x for Intel and x with the lowest bit in the opposite order for Sparc

//! \def ord4	\brief 4 element reordering ensuring the same order on any processor
//! \def ord4	\returns unchanged index x for Intel and x with the lowest 2 bit in the opposite order for Sparc

//! \def ord8	\brief 8 element reordering ensuring the same order on any processor
//! \def ord8	\returns unchanged index x for Intel and x with the lowest 3 bit in the opposite order for Sparc

//! \def make_LSF	\brief ensures LSF byte order for an array of n 32-bit values
//! \def make_LSF	\retval x remains unchanged on Intel and n elements of x are byte swapped on Sparc

//! \def make_LSF	\brief ensures MSF byte order for an array of n 32-bit values
//! \def make_MSF	\retval x remains unchanged on Sparc and n elements of x are byte swapped on Intel

#ifdef LITTLE_ENDIAN
	#define LSF16(x)				(x)
	#define LSF32(x)				(x)
	#define LSF64(x)				(x)
	#define LSF64D(x)				(x)
	#define MSF16(x)				((((x) & 0xFF) << 8) | (((x) >> 8) & 0xFF))
	#define MSF32(x)				(BSWAP32 (x))
	#define MSF64(x)				(BSWAP64 (x))
	#define lsf16(x)				(x)
	#define lsf32(x)				(x)
	#define lsf64(x)				(x)
	#define msf16(x)				((((x) & 0xFF) << 8) | (((x) >> 8) & 0xFF))
	#define msf32(x)				(bswap32 (x))
	#define msf64(x)				(bswap64 (x))
	
	#define ord2(x)					(x)
	#define ord4(x)					(x)
	#define ord8(x)					(x)
	#define load32(y, x, i, j)		(y.D[i] = x->D[j])
	#define save32(y, x, i, j)		(y->D[i] = x.D[j])
	
#ifndef make_LSF_32
	#define make_LSF_32(x, n)
	#define make_LSF_64(x, n)
	static __forceinline void make_MSF_32 (u32    *x, u32 n) { register u32    i; for (; n; x++, n--) { i = *x; *x = bswap32 (i); } }
//	static __forceinline void make_MSF_64 (u64 *x, u32 n) { register u64 i; for (; n; x++, n--) { i = *x; *x = bswap64 (i); } }
#endif
#endif

#ifdef BIG_ENDIAN
	static __forceinline void make_LSF_32 (u32    *x, u32 n) { register u32    i; for (; n; x++, n--) { i = *x; *x = bswap32 (i); } }
	static __forceinline void make_LSF_64 (u64 *x, u32 n) { register u64 i; for (; n; x++, n--) { i = *x; *x = bswap64 (i); } }
	
	#define LSF16(x)				((((x) & 0xFF) << 8) | (((x) >> 8) & 0xFF))
	#define LSF32(x)				(BSWAP32 (x))
	#define LSF64(x)				(BSWAP64 (x))
	#define LSF64D(x)				((((u64) (x)) << 32) | (((u64) (x)) >> 32))
	#define MSF16(x)				(x)
	#define MSF32(x)				(x)
	#define MSF64(x)				(x)
	#define lsf16(x)				((((x) & 0xFF) << 8) | (((x) >> 8) & 0xFF))
	#define lsf32(x)				(bswap32 (x))
	#define lsf64(x)				(bswap64 (x))
	
	#define msf16(x)				(x)
	#define msf32(x)				(x)
	#define msf64(x)				(x)
	#define ord2(x)					((x) ^ 1)
	#define ord4(x)					((x) ^ 3)
	#define ord8(x)					((x) ^ 7)
	#define load32(y, x, i, j)		(  y.B[i*4+0] = x->B[j*4+3],  y.B[i*4+1] = x->B[j*4+2],  y.B[i*4+2] = x->B[j*4+1],  y.B[i*4+3] = x->B[j*4+0])
	#define save32(y, x, i, j)		( y->B[i*4+3] =  x.B[j*4+0], y->B[i*4+2] =  x.B[j*4+1], y->B[i*4+1] =  x.B[j*4+2], y->B[i*4+0] =  x.B[j*4+3])
	
	#define make_MSF_32(x, n)
	#define make_MSF_64(x, n)
#endif

#define byte4(x, n)					(u8) ((x) >> ((n) << 3))
#define byte4ord(x, n)				(u8) ((x) >> (ord4(n) << 3))

#ifndef __max
	#define __max(a,b)				(((a) > (b)) ? (a) : (b))	// should be defined in <stdlib.h>
#endif

#ifndef __min
	#define __min(a,b)				(((a) < (b)) ? (a) : (b))	// should be defined in <stdlib.h>
#endif

#ifdef _MSC_VER
#define rnd32()			((u32) (_rnd64b += (rotl64(_rnd64a,53) * 0x9C8F075E1A6B243DUL + 0x5AC734E821DF60B9UL) ^ clock_counter (), _rnd64a += rotl64(_rnd64b,59) * 0x2C0DE96B357481AFUL ^ 0xD8725E3901A4F6CBUL))
static u64				_rnd64a = 0xE4FDC25B98A63017UL;
static u64				_rnd64b = 0x5EA93C21F7604D8BUL;
#else
#define rnd32()			((u32) (_rnd64b += (rotl64(_rnd64a,53) * 0x9C8F075E1A6B243DULL + 0x5AC734E821DF60B9ULL) ^ clock_counter (), _rnd64a += rotl64(_rnd64b,59) * 0x2C0DE96B357481AFULL ^ 0xD8725E3901A4F6CBULL))
static u64				_rnd64a = 0xE4FDC25B98A63017ULL;
static u64				_rnd64b = 0x5EA93C21F7604D8BULL;
#endif

//! \brief extremely fast no API concurrency control
//! \pre control has to be global and volatile!
//! \param control is a 32-bit variable or a pointer to one
//! \param timeout is a 32-bit constant, a number of processor cycles we loop before giving up the thread
#define wait_for_availability(control, timeout) { u32 c; do c = (u32) clock_counter (); while (c == 0); for (;;) { if ((control == 0) && ((control = c) == c)) break; while (clock_counter () - c < timeout); if ((control == 0) && ((control = c) == c)) break; thread_yield (); } }	// this is faster than any other concurrency controlling API

//! \brief frees control allowing the nearest wait_for_availability() to fall through
#define make_available(control) (control = 0)

//! A multiprecision number (big) is an array of words with the first word representing the big's size in words. As Miracl libraries had been optimized for speed, all bigs now require a trailing zero word, therefore for a N-word big, (N + 2) words should be allocated, element [0] should be set to N and element [N+1] should be set to 0. Element [1] of the big is its least significant word and element [N] is its most significant word. For compatibility with processors implementing human-readable byte order (or so-called Network Byte Order), a big number x if stored or transmitted, should be first converted to LSF format using make_LSF (x + 1, x[0]) and then if necessary to ASCII using fast bytes2str before its output and back using str2bytes and make_LSF after its input. You also have to convert a big to LSF before calling setkey_big, encrypt_big or decrypt_big.
//!	/brief a 32-bit word is the basic multiprecision number element type, currently only 32-bit (u32 or u32) is supported. No upgrade to u64 is intended any time soon, so we stick with 32-bit words for the time being; defines work better than typedefs on some compilers;

#endif
