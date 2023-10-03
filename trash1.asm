; ---------------------------------------------------------------------------

STARTUPINFO     struc ; (sizeof=0x44, align=0x4, copyof_59)
cb              dd ?
lpReserved      dd ?                    ; offset
lpDesktop       dd ?                    ; offset
lpTitle         dd ?                    ; offset
dwX             dd ?
dwY             dd ?
dwXSize         dd ?
dwYSize         dd ?
dwXCountChars   dd ?
dwYCountChars   dd ?
dwFillAttribute dd ?
dwFlags         dd ?
wShowWindow     dw ?
cbReserved2     dw ?
lpReserved2     dd ?                    ; offset
hStdInput       dd ?                    ; offset
hStdOutput      dd ?                    ; offset
hStdError       dd ?                    ; offset
STARTUPINFO     ends

; ---------------------------------------------------------------------------

_exception      struc ; (sizeof=0x20, align=0x8, copyof_68)
                                        ; XREF: ___mingw_raise_matherr/r
type            dd ?                    ; XREF: ___mingw_raise_matherr+2A/w
name            dd ?                    ; XREF: ___mingw_raise_matherr+32/w ; offset
arg1            dq ?                    ; XREF: ___mingw_raise_matherr+1E/w
arg2            dq ?                    ; XREF: ___mingw_raise_matherr+22/w
retval          dq ?                    ; XREF: ___mingw_raise_matherr+26/w
_exception      ends

; ---------------------------------------------------------------------------

MEMORY_BASIC_INFORMATION struc ; (sizeof=0x1C, align=0x4, copyof_89)
                                        ; XREF: ___write_memory.part.0/r
BaseAddress     dd ?                    ; XREF: ___write_memory_part_0+141/r
                                        ; ___write_memory_part_0+181/r ... ; offset
AllocationBase  dd ?                    ; offset
AllocationProtect dd ?
RegionSize      dd ?                    ; XREF: ___write_memory_part_0+125/r
                                        ; ___write_memory_part_0+17A/r ...
State           dd ?
Protect         dd ?                    ; XREF: ___write_memory_part_0+B7/r
                                        ; ___write_memory_part_0+E6/r ...
Type            dd ?
MEMORY_BASIC_INFORMATION ends

; ---------------------------------------------------------------------------

FT              union ; (sizeof=0x8, align=0x8, copyof_107)
                                        ; XREF: ___security_init_cookie+E/w
                                        ; ___security_init_cookie+15/w ...
ft_scalar       dq ?
ft_struct       FILETIME ?
FT              ends

; ---------------------------------------------------------------------------

FILETIME        struc ; (sizeof=0x8, align=0x4, copyof_105) ; XREF: FT/r
dwLowDateTime   dd ?
dwHighDateTime  dd ?
FILETIME        ends

; ---------------------------------------------------------------------------

LARGE_INTEGER   union ; (sizeof=0x8, align=0x8, copyof_103)
                                        ; XREF: ___security_init_cookie+6F/r
                                        ; ___security_init_cookie+72/r ...
_anon_0         $F50D1B4661C66265C46503353F437A80 ?
u               $F50D1B4661C66265C46503353F437A80 ?
QuadPart        dq ?
LARGE_INTEGER   ends

; ---------------------------------------------------------------------------

$F50D1B4661C66265C46503353F437A80 struc ; (sizeof=0x8, align=0x4, copyof_101)
                                        ; XREF: LARGE_INTEGER/r
                                        ; LARGE_INTEGER/r
LowPart         dd ?
HighPart        dd ?
$F50D1B4661C66265C46503353F437A80 ends

; ---------------------------------------------------------------------------

_startupinfo    struc ; (sizeof=0x4, align=0x4, copyof_65)
                                        ; XREF: .bss:__bss_start__/r
newmode         dd ?                    ; XREF: _pre_cpp_init+20/w
_startupinfo    ends

; ---------------------------------------------------------------------------

IMAGE_TLS_DIRECTORY struc ; (sizeof=0x18, align=0x4, copyof_76)
                                        ; XREF: .tls:__tls_used/r
StartAddressOfRawData dd ?
EndAddressOfRawData dd ?
AddressOfIndex  dd ?
AddressOfCallBacks dd ?
SizeOfZeroFill  dd ?
Characteristics dd ?
IMAGE_TLS_DIRECTORY ends

; ---------------------------------------------------------------------------

EXCEPTION_RECORD struc ; (sizeof=0x50, align=0x4, copyof_27)
                                        ; XREF: .bss:_GS_ExceptionRecord/r
ExceptionCode   dd ?                    ; XREF: ___report_gsfailure+12/w
ExceptionFlags  dd ?                    ; XREF: ___report_gsfailure+1C/w
ExceptionRecord dd ?                    ; offset
ExceptionAddress dd ?                   ; XREF: ___report_gsfailure+2B/w ; offset
NumberParameters dd ?
ExceptionInformation dd 15 dup(?)
EXCEPTION_RECORD ends

; ---------------------------------------------------------------------------

CONTEXT         struc ; (sizeof=0x2CC, align=0x4, copyof_25)
                                        ; XREF: .bss:_GS_ContextRecord/r
ContextFlags    dd ?
Dr0             dd ?
Dr1             dd ?
Dr2             dd ?
Dr3             dd ?
Dr6             dd ?
Dr7             dd ?
FloatSave       FLOATING_SAVE_AREA ?
SegGs           dd ?
SegFs           dd ?
SegEs           dd ?
SegDs           dd ?
_Edi            dd ?
_Esi            dd ?
_Ebx            dd ?
_Edx            dd ?
_Ecx            dd ?                    ; XREF: ___report_gsfailure+3A/w
_Eax            dd ?
_Ebp            dd ?
_Eip            dd ?                    ; XREF: ___report_gsfailure+26/w
SegCs           dd ?
EFlags          dd ?
_Esp            dd ?                    ; XREF: ___report_gsfailure+C/w
SegSs           dd ?
ExtendedRegisters db 512 dup(?)
CONTEXT         ends

; ---------------------------------------------------------------------------

FLOATING_SAVE_AREA struc ; (sizeof=0x70, align=0x4, copyof_10)
                                        ; XREF: CONTEXT/r
ControlWord     dd ?
StatusWord      dd ?
TagWord         dd ?
ErrorOffset     dd ?
ErrorSelector   dd ?
DataOffset      dd ?
DataSelector    dd ?
RegisterArea    db 80 dup(?)
Cr0NpxState     dd ?
FLOATING_SAVE_AREA ends

; ---------------------------------------------------------------------------

EXCEPTION_POINTERS struc ; (sizeof=0x8, align=0x4, copyof_78)
                                        ; XREF: .rdata:_GS_ExceptionPointers/r
ExceptionRecord dd ?                    ; offset
ContextRecord   dd ?                    ; offset
EXCEPTION_POINTERS ends

; ---------------------------------------------------------------------------

CRITICAL_SECTION struc ; (sizeof=0x18, align=0x4, copyof_114)
                                        ; XREF: .bss:___mingwthr_cs/r
DebugInfo       dd ?                    ; offset
LockCount       dd ?
RecursionCount  dd ?
OwningThread    dd ?                    ; offset
LockSemaphore   dd ?                    ; offset
SpinCount       dd ?
CRITICAL_SECTION ends

; ---------------------------------------------------------------------------

; enum __enative_startup_state_0, copyof_67, width 4 bytes
__uninitialized  = 0
__initializing   = 1
__initialized    = 2

; ---------------------------------------------------------------------------

; enum _crt_app_type, copyof_132
_crt_unknown_app  = 0
_crt_console_app  = 1
_crt_gui_app     = 2

;
; +-------------------------------------------------------------------------+
; |      This file was generated by The Interactive Disassembler (IDA)      |
; |           Copyright (c) 2020 Hex-Rays, <support@hex-rays.com>           |
; |                      License info: 48-174E-39B0-5F                      |
; |          Hex-Rays SA. ¡¼ôëò¨ò¥ïá÷ú¡½, Unlimited License          |
; +-------------------------------------------------------------------------+
;
; Input SHA256 : E9923BB3C3740DABBE5E97F10D3416463E901316D1B26D8EA2B568DF0747EB58
; Input MD5    : C6F9BDB28060762E7EFB3DE27DB15430
; Input CRC32  : 774D0EE1

; File Name   : C:\Users\ÄÚÄÚ¾Æ ÇÁ·»Áî\Documents\GitHub\capstone1\HelloWorld (1).exe
; Format      : Portable executable for 80386 (PE)
; Imagebase   : 400000
; Timestamp   : 5C5E2465 (Sat Feb 09 00:52:53 2019)
; Section 1. (virtual address 00001000)
; Virtual size                  : 000017E0 (   6112.)
; Section size in file          : 00001800 (   6144.)
; Offset to raw data for section: 00000400
; Flags 60500020: Text Executable Readable
; Alignment     : 16 bytes
; OS type         :  MS Windows
; Application type:  Executable 32bit

                .686p
                .mmx
                .model flat
.intel_syntax noprefix

; ===========================================================================

; Segment type: Pure code
; Segment permissions: Read/Execute
_text           segment para public 'CODE' use32
                assume cs:_text
                ;org 401000h
                assume es:nothing, ss:nothing, ds:_data, fs:nothing, gs:nothing
; [00000002 BYTES: COLLAPSED FUNCTION ___mingw_invalidParameterHandler. PRESS CTRL-NUMPAD+ TO EXPAND]
                align 10h

; =============== S U B R O U T I N E =======================================

; Attributes: static

; int pre_c_init()
_pre_c_init     proc near               ; DATA XREF: .CRT:_mingw_pcinit¡éo

Type            = dword ptr -1Ch

                sub     esp, 1Ch
                xor     eax, eax
                cmp     word ptr ds:400000h, 5A4Dh
                mov     ds:_mingw_initltsdrot_force, 1
                mov     ds:_mingw_initltsdyn_force, 1
                mov     ds:_mingw_initltssuo_force, 1
                mov     ds:_mingw_initcharmax, 1
                jz      short loc_4010B0

loc_401048:                             ; CODE XREF: _pre_c_init+B6¡éj
                                        ; _pre_c_init+C8¡éj ...
                mov     ds:_managedapp, eax
                mov     eax, ds:_mingw_app_type
                test    eax, eax
                jz      short loc_4010A0
                mov     [esp+1Ch+Type], 2 ; Type
                call    ___set_app_type

loc_401062:                             ; CODE XREF: _pre_c_init+9C¡éj
                mov     [esp+1Ch+Type], 0FFFFFFFFh ; ptr
                call    __encode_pointer
                mov     edx, ds:__fmode
                mov     ds:___onexitend, eax
                mov     ds:___onexitbegin, eax
                mov     eax, ds:__imp___fmode
                mov     [eax], edx
                call    __setargv
                cmp     __MINGW_INSTALL_DEBUG_MATHERR, 1
                jz      short loc_401100
                xor     eax, eax
                add     esp, 1Ch
                retn
; ---------------------------------------------------------------------------
                align 10h

loc_4010A0:                             ; CODE XREF: _pre_c_init+44¡èj
                mov     [esp+1Ch+Type], 1 ; Type
                call    ___set_app_type
                jmp     short loc_401062
; ---------------------------------------------------------------------------
                align 10h

loc_4010B0:                             ; CODE XREF: _pre_c_init+36¡èj
                mov     edx, ds:40003Ch
                cmp     dword ptr [edx+400000h], 4550h
                lea     ecx, [edx+400000h]
                jnz     short loc_401048
                movzx   edx, word ptr [ecx+18h]
                cmp     dx, 10Bh
                jz      short loc_401112
                cmp     dx, 20Bh
                jnz     loc_401048
                cmp     dword ptr [ecx+84h], 0Eh
                jbe     loc_401048
                mov     edx, [ecx+0F8h]
                xor     eax, eax
                test    edx, edx
                setnz   al
                jmp     loc_401048
; ---------------------------------------------------------------------------
                align 10h

loc_401100:                             ; CODE XREF: _pre_c_init+81¡èj
                mov     [esp+1Ch+Type], offset __matherr ; f
                call    ___mingw_setusermatherr
                xor     eax, eax
                add     esp, 1Ch
                retn
; ---------------------------------------------------------------------------

loc_401112:                             ; CODE XREF: _pre_c_init+C1¡èj
                cmp     dword ptr [ecx+74h], 0Eh
                jbe     loc_401048
                mov     ecx, [ecx+0E8h]
                xor     eax, eax
                test    ecx, ecx
                setnz   al
                jmp     loc_401048
_pre_c_init     endp

; ---------------------------------------------------------------------------
                align 10h

; =============== S U B R O U T I N E =======================================

; Attributes: static

; void pre_cpp_init()
_pre_cpp_init   proc near               ; DATA XREF: .CRT:_mingw_pcppinit¡éo

var_2C          = dword ptr -2Ch
var_28          = dword ptr -28h
var_24          = dword ptr -24h
var_20          = dword ptr -20h
var_1C          = dword ptr -1Ch

                sub     esp, 2Ch
                mov     eax, ds:__newmode
                mov     [esp+2Ch+var_1C], offset __bss_start__
                mov     [esp+2Ch+var_24], offset _envp
                mov     [esp+2Ch+var_28], offset _argv
                mov     ds:__bss_start__.newmode, eax
                mov     eax, ds:__dowildcard
                mov     [esp+2Ch+var_2C], offset _argc
                mov     [esp+2Ch+var_20], eax
                call    ___getmainargs
                mov     ds:_argret, eax
                add     esp, 2Ch
                retn
_pre_cpp_init   endp

; ---------------------------------------------------------------------------
                align 10h
; [00000355 BYTES: COLLAPSED FUNCTION ___tmainCRTStartup. PRESS CTRL-NUMPAD+ TO EXPAND]
                align 10h
; [0000001A BYTES: COLLAPSED FUNCTION _WinMainCRTStartup. PRESS CTRL-NUMPAD+ TO EXPAND]
                align 10h

; =============== S U B R O U T I N E =======================================


; int mainCRTStartup()
                public _mainCRTStartup
_mainCRTStartup proc near
                sub     esp, 0Ch
                mov     ds:_mingw_app_type, 0
                call    ___security_init_cookie
                add     esp, 0Ch
                jmp     ___tmainCRTStartup
_mainCRTStartup endp

; ---------------------------------------------------------------------------
                align 10h

; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __stdcall WinMain(HINSTANCE hInst, HINSTANCE hPreInst, LPSTR lpszCmdLine, int nCmdShow)
                public _WinMain@16
_WinMain@16     proc near               ; CODE XREF: _main+38¡ép

hInst           = dword ptr  8
hPreInst        = dword ptr  0Ch
lpszCmdLine     = dword ptr  10h
nCmdShow        = dword ptr  14h

                push    ebp
                mov     ebp, esp
                sub     esp, 18h
                mov     dword ptr [esp+0Ch], 0 ; uType
                mov     dword ptr [esp+8], offset Caption ; "Welcome Message"
                mov     dword ptr [esp+4], offset Text ; "Hello World!!"
                mov     dword ptr [esp], 0 ; hWnd
                mov     eax, ds:__imp__MessageBoxA@16
                call    eax ; __imp__MessageBoxA@16
                sub     esp, 10h
                mov     eax, 0
                leave
                retn    10h
_WinMain@16     endp

; ---------------------------------------------------------------------------
                align 10h

; =============== S U B R O U T I N E =======================================

; Attributes: static

; BOOL __stdcall __dyn_tls_dtor(HANDLE hDllHandle, DWORD dwReason, LPVOID lpreserved)
                public ___dyn_tls_dtor@12
___dyn_tls_dtor@12 proc near            ; DATA XREF: .CRT:___xl_d¡éo

var_1C          = dword ptr -1Ch
reason          = dword ptr -18h
reserved        = dword ptr -14h
hDllHandle      = dword ptr  4
dwReason        = dword ptr  8
lpreserved      = dword ptr  0Ch

                sub     esp, 1Ch
                mov     eax, [esp+1Ch+dwReason]
                test    eax, eax
                jz      short loc_401580
                cmp     eax, 3
                jz      short loc_401580
                mov     eax, 1
                add     esp, 1Ch
                retn    0Ch
; ---------------------------------------------------------------------------
                align 10h

loc_401580:                             ; CODE XREF: ___dyn_tls_dtor@12+9¡èj
                                        ; ___dyn_tls_dtor@12+E¡èj
                mov     edx, [esp+1Ch+lpreserved]
                mov     [esp+1Ch+reason], eax ; reason
                mov     eax, [esp+1Ch+hDllHandle]
                mov     [esp+1Ch+reserved], edx ; reserved
                mov     [esp+1Ch+var_1C], eax ; hDllHandle
                call    ___mingw_TLScallback
                mov     eax, 1
                add     esp, 1Ch
                retn    0Ch
___dyn_tls_dtor@12 endp

; ---------------------------------------------------------------------------
                align 10h

; =============== S U B R O U T I N E =======================================


; BOOL __stdcall __dyn_tls_init(HANDLE hDllHandle, DWORD dwReason, LPVOID lpreserved)
                public ___dyn_tls_init@12
___dyn_tls_init@12 proc near            ; CODE XREF: ___tmainCRTStartup+112¡èp
                                        ; DATA XREF: .rdata:___dyn_tls_init_callback¡éo ...

var_1C          = dword ptr -1Ch
reason          = dword ptr -18h
reserved        = dword ptr -14h
hDllHandle      = dword ptr  4
dwReason        = dword ptr  8
lpreserved      = dword ptr  0Ch

                push    ebx
                sub     esp, 18h
                cmp     __CRT_MT, 2
                mov     eax, [esp+1Ch+dwReason]
                jz      short loc_4015CB
                mov     __CRT_MT, 2

loc_4015CB:                             ; CODE XREF: ___dyn_tls_init@12+F¡èj
                cmp     eax, 2
                jz      short loc_4015E1
                cmp     eax, 1
                jz      short loc_401610

loc_4015D5:                             ; CODE XREF: ___dyn_tls_init@12+3C¡éj
                                        ; ___dyn_tls_init@12+7C¡éj
                add     esp, 18h
                mov     eax, 1
                pop     ebx
                retn    0Ch
; ---------------------------------------------------------------------------

loc_4015E1:                             ; CODE XREF: ___dyn_tls_init@12+1E¡èj
                mov     ebx, offset ___xd_z
ps = ebx                                ; uintptr_t
                cmp     ps, offset ___xd_z
                jz      short loc_4015D5
                xchg    ax, ax

loc_4015F0:                             ; CODE XREF: ___dyn_tls_init@12+51¡éj
                mov     eax, [ps]
                test    eax, eax
                jz      short loc_4015F8
                call    eax

loc_4015F8:                             ; CODE XREF: ___dyn_tls_init@12+44¡èj
                add     ps, 4
                cmp     ps, offset ___xd_z
                jnz     short loc_4015F0
                add     esp, 18h
                mov     eax, 1
                pop     ps
                retn    0Ch
; ---------------------------------------------------------------------------
                align 10h

loc_401610:                             ; CODE XREF: ___dyn_tls_init@12+23¡èj
                mov     eax, [esp+1Ch+lpreserved]
                mov     [esp+1Ch+reason], 1 ; reason
                mov     [esp+1Ch+reserved], eax ; reserved
                mov     eax, [esp+1Ch+hDllHandle]
                mov     [esp+1Ch+var_1C], eax ; hDllHandle
                call    ___mingw_TLScallback
                jmp     short loc_4015D5
___dyn_tls_init@12 endp

; ---------------------------------------------------------------------------
                align 10h

; =============== S U B R O U T I N E =======================================


; int __cdecl __tlregdtor(_PVFV func)
                public ___tlregdtor
___tlregdtor    proc near

func            = dword ptr  4

                xor     eax, eax
                retn
___tlregdtor    endp

; ---------------------------------------------------------------------------
                align 10h

; =============== S U B R O U T I N E =======================================

; Attributes: static

; int my_lconv_init()
_my_lconv_init  proc near               ; DATA XREF: .CRT:___mingw_pinit¡éo
                mov     eax, ds:__imp____lconv_init
                jmp     eax
_my_lconv_init  endp

; ---------------------------------------------------------------------------
                align 10h

; =============== S U B R O U T I N E =======================================


; void *__cdecl _decode_pointer(void *codedptr)
                public __decode_pointer
__decode_pointer proc near              ; CODE XREF: _mingw_onexit+C¡ép
                                        ; _mingw_onexit+32¡ép ...

codedptr        = dword ptr  4

                mov     eax, [esp+codedptr]
                retn
__decode_pointer endp

; ---------------------------------------------------------------------------
                align 10h

; =============== S U B R O U T I N E =======================================


; void *__cdecl _encode_pointer(void *ptr)
                public __encode_pointer
__encode_pointer proc near              ; CODE XREF: _pre_c_init+59¡èp
                                        ; _mingw_onexit+71¡ép ...

ptr             = dword ptr  4

                mov     eax, [esp+ptr]
                retn
__encode_pointer endp

; ---------------------------------------------------------------------------
                align 10h

; =============== S U B R O U T I N E =======================================


; _onexit_t __cdecl mingw_onexit(_onexit_t func)
                public _mingw_onexit
_mingw_onexit   proc near               ; CODE XREF: _atexit+A¡ép

codedptr        = dword ptr -2Ch
var_28          = dword ptr -28h
var_24          = dword ptr -24h
onexitbegin     = dword ptr -14h
onexitend       = dword ptr -10h
func            = dword ptr  4

                push    ebx
                sub     esp, 28h
                mov     eax, ds:___onexitbegin
                mov     [esp+2Ch+codedptr], eax ; codedptr
                call    __decode_pointer
                cmp     eax, 0FFFFFFFFh
                mov     [esp+2Ch+onexitbegin], eax
                jz      loc_401710
                mov     [esp+2Ch+codedptr], 8
                call    __lock
                mov     eax, ds:___onexitbegin
                mov     [esp+2Ch+codedptr], eax ; codedptr
                call    __decode_pointer
                mov     [esp+2Ch+onexitbegin], eax
                mov     eax, ds:___onexitend
                mov     [esp+2Ch+codedptr], eax ; codedptr
                call    __decode_pointer
                mov     [esp+2Ch+onexitend], eax
                lea     eax, [esp+2Ch+onexitend]
                mov     [esp+2Ch+var_24], eax
                lea     eax, [esp+2Ch+onexitbegin]
                mov     [esp+2Ch+var_28], eax
                mov     eax, [esp+2Ch+func]
                mov     [esp+2Ch+codedptr], eax
                call    ___dllonexit
                mov     ebx, eax
retval = eax                            ; _onexit_t
                mov     retval, [esp+2Ch+onexitbegin]
retval = ebx                            ; _onexit_t
                mov     [esp+2Ch+codedptr], eax ; ptr
                call    __encode_pointer
                mov     ds:___onexitbegin, eax
                mov     eax, [esp+2Ch+onexitend]
                mov     [esp+2Ch+codedptr], eax ; ptr
                call    __encode_pointer
                mov     [esp+2Ch+codedptr], 8
                mov     ds:___onexitend, eax
                call    __unlock
                add     esp, 28h
                mov     eax, retval
                pop     retval
retval = eax                            ; _onexit_t
                retn
; ---------------------------------------------------------------------------
                align 10h

loc_401710:                             ; CODE XREF: _mingw_onexit+18¡èj
                mov     eax, [esp+2Ch+func]
                mov     [esp+2Ch+codedptr], eax ; Func
                call    ds:__imp___onexit
                add     esp, 28h
                pop     ebx
                retn
_mingw_onexit   endp

; ---------------------------------------------------------------------------
                align 10h

; =============== S U B R O U T I N E =======================================


; int __cdecl atexit(_PVFV func)
                public _atexit
_atexit         proc near               ; CODE XREF: ___do_global_ctors+29¡ép

var_1C          = dword ptr -1Ch
func            = dword ptr  4

                sub     esp, 1Ch
                mov     eax, [esp+1Ch+func]
                mov     [esp+1Ch+var_1C], eax ; func
                call    _mingw_onexit
                test    eax, eax
                setz    al
                add     esp, 1Ch
                movzx   eax, al
                neg     eax
                retn
_atexit         endp

; ---------------------------------------------------------------------------
                align 10h

; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __stdcall _gnu_exception_handler(EXCEPTION_POINTERS *exception_data)
                public __gnu_exception_handler@4
__gnu_exception_handler@4 proc near     ; DATA XREF: ___tmainCRTStartup+11C¡èo

exception_data  = dword ptr  8

                push    ebp
                mov     ebp, esp
                push    esi
                push    ebx
                sub     esp, 10h
                mov     ebx, [ebp+exception_data]
                mov     eax, [ebx]
                mov     eax, [eax]
                cmp     eax, 0C0000091h
                ja      short loc_4017A8
                cmp     eax, 0C000008Dh
                jnb     loc_401810
                cmp     eax, 0C0000005h
                jnz     loc_401817
                mov     dword ptr [esp+4], 0 ; Function
                mov     dword ptr [esp], 0Bh ; Signal
                call    _signal
old_handler = eax                       ; void (*)(int)
                cmp     old_handler, 1
                jz      loc_401846
                test    old_handler, old_handler
                jz      short loc_4017BD
                mov     dword ptr [esp], 0Bh
                call    old_handler
                jmp     short loc_4017FD
; ---------------------------------------------------------------------------

loc_4017A8:                             ; CODE XREF: __gnu_exception_handler@4+14¡èj
                cmp     eax, 0C0000094h
                jz      short loc_4017D1
                cmp     eax, 0C0000096h
                jz      short loc_40181E
                cmp     eax, 0C0000093h
                jz      short loc_401810

loc_4017BD:                             ; CODE XREF: __gnu_exception_handler@4+4B¡èj
                                        ; __gnu_exception_handler@4+A2¡éj ...
                mov     eax, ds:___mingw_oldexcpt_handler
                test    eax, eax
                jz      short loc_401802
                mov     [ebp+exception_data], ebx
                lea     esp, [ebp-8]
                pop     ebx
                pop     esi
                pop     ebp
                jmp     eax
; ---------------------------------------------------------------------------

loc_4017D1:                             ; CODE XREF: __gnu_exception_handler@4+5D¡èj
                xor     esi, esi

loc_4017D3:                             ; CODE XREF: __gnu_exception_handler@4+C5¡éj
reset_fpu = esi                         ; int ; Function
                mov     dword ptr [esp+4], 0
                mov     dword ptr [esp], 8 ; Signal
                call    _signal
old_handler = eax                       ; void (*)(int)
                cmp     old_handler, 1
                jz      loc_401876
                test    old_handler, old_handler
                jz      short loc_4017BD
                mov     dword ptr [esp], 8
                call    old_handler

loc_4017FD:                             ; CODE XREF: __gnu_exception_handler@4+56¡èj
                                        ; __gnu_exception_handler@4+F4¡éj ...
                mov     eax, 0FFFFFFFFh

loc_401802:                             ; CODE XREF: __gnu_exception_handler@4+74¡èj
                lea     esp, [ebp-8]
                pop     ebx
                pop     esi
                pop     ebp
                retn    4
; ---------------------------------------------------------------------------
                align 10h

loc_401810:                             ; CODE XREF: __gnu_exception_handler@4+1B¡èj
                                        ; __gnu_exception_handler@4+6B¡èj
                mov     esi, 1
                jmp     short loc_4017D3
; ---------------------------------------------------------------------------

loc_401817:                             ; CODE XREF: __gnu_exception_handler@4+26¡èj
                cmp     eax, 0C000001Dh
                jnz     short loc_4017BD

loc_40181E:                             ; CODE XREF: __gnu_exception_handler@4+64¡èj
                mov     dword ptr [esp+4], 0 ; Function
                mov     dword ptr [esp], 4 ; Signal
                call    _signal
old_handler = eax                       ; void (*)(int)
                cmp     old_handler, 1
                jz      short loc_401860
                test    old_handler, old_handler
                jz      short loc_4017BD
                mov     dword ptr [esp], 4
                call    old_handler
                jmp     short loc_4017FD
; ---------------------------------------------------------------------------

loc_401846:                             ; CODE XREF: __gnu_exception_handler@4+43¡èj
old_handler = eax                       ; void (*)(int) ; Function
                mov     dword ptr [esp+4], 1
                mov     dword ptr [esp], 0Bh ; Signal
                call    _signal
                jmp     short loc_4017FD
; ---------------------------------------------------------------------------
old_handler = eax                       ; void (*)(int)
                align 10h

loc_401860:                             ; CODE XREF: __gnu_exception_handler@4+E5¡èj
                mov     dword ptr [esp+4], 1 ; Function
                mov     dword ptr [esp], 4 ; Signal
                call    _signal
                jmp     short loc_4017FD
; ---------------------------------------------------------------------------

loc_401876:                             ; CODE XREF: __gnu_exception_handler@4+9A¡èj
old_handler = eax                       ; void (*)(int) ; Function
reset_fpu = esi                         ; int
                mov     dword ptr [esp+4], 1
                mov     dword ptr [esp], 8 ; Signal
                call    _signal
                test    reset_fpu, reset_fpu
                jz      loc_4017FD
                call    _fpreset
                jmp     loc_4017FD
__gnu_exception_handler@4 endp

; ---------------------------------------------------------------------------
                align 10h

; =============== S U B R O U T I N E =======================================


; int _setargv()
                public __setargv
__setargv       proc near               ; CODE XREF: _pre_c_init+75¡èp
                xor     eax, eax
                retn
__setargv       endp

; ---------------------------------------------------------------------------
                align 10h

; =============== S U B R O U T I N E =======================================


; void __cdecl __mingw_raise_matherr(int typ, const char *name, double a1, double a2, double rslt)
                public ___mingw_raise_matherr
___mingw_raise_matherr proc near

var_3C          = dword ptr -3Ch
ex              = _exception ptr -2Ch
typ             = dword ptr  4
name            = dword ptr  8
a1              = qword ptr  0Ch
a2              = qword ptr  14h
rslt            = qword ptr  1Ch

                sub     esp, 3Ch
                mov     eax, ds:_stUserMathErr
                fld     [esp+3Ch+a1]
                fld     [esp+3Ch+a2]
                fld     [esp+3Ch+rslt]
                test    eax, eax
                jz      short loc_4018F1
                fxch    st(2)
                mov     edx, [esp+3Ch+typ]
                fstp    [esp+3Ch+ex.arg1]
                fstp    [esp+3Ch+ex.arg2]
                fstp    [esp+3Ch+ex.retval]
                mov     [esp+3Ch+ex.type], edx
                mov     edx, [esp+3Ch+name]
                mov     [esp+3Ch+ex.name], edx
                lea     edx, [esp+3Ch+ex]
                mov     [esp+3Ch+var_3C], edx ; _exception *
                call    eax ; _stUserMathErr
                jmp     short loc_4018F7
; ---------------------------------------------------------------------------

loc_4018F1:                             ; CODE XREF: ___mingw_raise_matherr+16¡èj
                fstp    st
                fstp    st
                fstp    st

loc_4018F7:                             ; CODE XREF: ___mingw_raise_matherr+3F¡èj
                add     esp, 3Ch
                retn
___mingw_raise_matherr endp

; ---------------------------------------------------------------------------
                align 10h

; =============== S U B R O U T I N E =======================================


; void __cdecl __mingw_setusermatherr(int (*f)(_exception *))
                public ___mingw_setusermatherr
___mingw_setusermatherr proc near       ; CODE XREF: _pre_c_init+F7¡èp

f               = dword ptr  4

                mov     eax, [esp+f]
                mov     ds:_stUserMathErr, eax
                jmp     ___setusermatherr
___mingw_setusermatherr endp

; ---------------------------------------------------------------------------
                align 10h

; =============== S U B R O U T I N E =======================================


; int __cdecl _matherr(_exception *pexcept)
                public __matherr
__matherr       proc near               ; DATA XREF: _pre_c_init:loc_401100¡èo

Stream          = dword ptr -3Ch
Format          = dword ptr -38h
var_34          = dword ptr -34h
var_30          = dword ptr -30h
var_2C          = qword ptr -2Ch
var_24          = qword ptr -24h
var_1C          = qword ptr -1Ch
pexcept         = dword ptr  4

                sub     esp, 3Ch
                mov     eax, [esp+3Ch+pexcept]
                mov     edx, [eax]
                lea     ecx, [edx-1]
                mov     edx, offset aUnknownError ; "Unknown error"
                cmp     ecx, 5
                ja      short loc_40192D
                mov     edx, ds:_CSWTCH_5[ecx*4]

loc_40192D:                             ; CODE XREF: __matherr+14¡èj
type = edx                              ; const char *
                fld     qword ptr [eax+18h]
                fstp    [esp+3Ch+var_1C]
                fld     qword ptr [eax+10h]
                fstp    [esp+3Ch+var_24]
                fld     qword ptr [eax+8]
                fstp    [esp+3Ch+var_2C]
                mov     eax, [eax+4]
                mov     [esp+3Ch+var_34], type
                mov     [esp+3Ch+Format], offset Format ; "_matherr(): %s in %s(%g, %g)  (retval=%"...
                mov     [esp+3Ch+var_30], eax
                mov     eax, ds:__imp___iob
                add     eax, 40h ; '@'
                mov     [esp+3Ch+Stream], eax ; Stream
                call    _fprintf
                xor     eax, eax
                add     esp, 3Ch
                retn
__matherr       endp

; ---------------------------------------------------------------------------
                align 10h

; =============== S U B R O U T I N E =======================================

; Attributes: noreturn static

; void __report_error(const char *msg, ...)
___report_error proc near               ; CODE XREF: ___write_memory_part_0+1E4¡ép
                                        ; ___write_memory_part_0+212¡ép ...

Buffer          = dword ptr -1Ch
ElementSize     = dword ptr -18h
ElementCount    = dword ptr -14h
Stream          = dword ptr -10h
msg             = dword ptr  4
ArgList         = byte ptr  8

argp = ebx                              ; va_list
                push    argp
                sub     esp, 18h
                mov     eax, ds:__imp___iob
                mov     [esp+1Ch+ElementCount], 1Bh ; ElementCount
                lea     argp, [esp+1Ch+ArgList]
                mov     [esp+1Ch+ElementSize], 1 ; ElementSize
                mov     [esp+1Ch+Buffer], offset aMingwW64Runtim ; "Mingw-w64 runtime failure:\n"
                add     eax, 40h ; '@'
                mov     [esp+1Ch+Stream], eax ; Stream
                call    _fwrite
                mov     eax, [esp+1Ch+msg]
                mov     [esp+1Ch+ElementCount], argp ; ArgList
                mov     [esp+1Ch+ElementSize], eax ; Format
                mov     eax, ds:__imp___iob
                add     eax, 40h ; '@'
                mov     [esp+1Ch+Buffer], eax ; Stream
                call    _vfprintf
                call    _abort
___report_error endp


; =============== S U B R O U T I N E =======================================


sub_4019C1      proc near
                jmp     short ___write_memory_part_0
; ---------------------------------------------------------------------------
                align 10h
sub_4019C1      endp


; =============== S U B R O U T I N E =======================================

; Attributes: static bp-based frame

; void __usercall __write_memory_part_0(void *addr@<eax>, const void *src@<edx>, size_t len@<ecx>)
___write_memory_part_0 proc near        ; CODE XREF: sub_4019C1¡èj
                                        ; __pei386_runtime_relocator+140¡ép ...

lpBuffer        = dword ptr -48h
var_44          = dword ptr -44h
len             = dword ptr -40h
src             = dword ptr -3Ch
oldprot         = dword ptr -38h
b               = MEMORY_BASIC_INFORMATION ptr -34h

addr = eax                              ; void *
src_0 = edx                             ; const void *
len_0 = ecx                             ; size_t
                push    ebp
                mov     ebp, esp
                push    edi
                push    esi
                mov     esi, addr
                push    ebx
                sub     esp, 4Ch
                mov     [ebp+len], len_0
                mov     len_0, ds:_maxSections
                mov     [ebp+src], src_0
                test    ecx, ecx
                jle     loc_401BC0
                mov     src_0, ds:_the_secs
                xor     ebx, ebx

loc_4019F7:                             ; CODE XREF: ___write_memory_part_0+44¡éj
addr = esi                              ; void *
                mov     eax, [edx+4]
                cmp     addr, eax
                jb      short loc_401A0C
                mov     edi, [edx+8]
                add     eax, [edi+8]
                cmp     addr, eax
                jb      loc_401AE0

loc_401A0C:                             ; CODE XREF: ___write_memory_part_0+2C¡èj
                add     ebx, 1
                add     edx, 0Ch
                cmp     ebx, ecx
                jnz     short loc_4019F7

loc_401A16:                             ; CODE XREF: ___write_memory_part_0+1F2¡éj
                mov     [esp], addr     ; p
                call    ___mingw_GetSectionForAddress
                test    eax, eax
                mov     edi, eax
                jz      loc_401BE7
                lea     ecx, [ebx+ebx*2]
                shl     ecx, 2
                mov     ebx, ecx
                add     ebx, ds:_the_secs
                mov     [ebp+var_44], ecx
                mov     [ebx+8], eax
                mov     dword ptr [ebx], 0
                call    __GetPEImageBase
                mov     ecx, [ebp+var_44]
                lea     edx, [ebp+b]
                mov     [ebp+lpBuffer], edx
                add     eax, [edi+0Ch]
                mov     [ebx+4], eax
                mov     eax, ds:_the_secs
                mov     [esp+4], edx    ; lpBuffer
                mov     ebx, ds:__imp__VirtualQuery@12
                mov     dword ptr [esp+8], 1Ch ; dwLength
                mov     eax, [eax+ecx+4]
                mov     [esp], eax      ; lpAddress
                call    ebx ; __imp__VirtualQuery@12
                mov     ecx, [ebp+var_44]
                mov     edx, [ebp+lpBuffer]
                sub     esp, 0Ch
                test    eax, eax
                jz      loc_401BC7
                mov     eax, [ebp+b.Protect]
                cmp     eax, 4
                jnz     loc_401B64

loc_401A93:                             ; CODE XREF: ___write_memory_part_0+197¡éj
                                        ; ___write_memory_part_0+1CD¡éj
                add     ds:_maxSections, 1

loc_401A9A:                             ; CODE XREF: ___write_memory_part_0+119¡éj
                mov     dword ptr [esp+8], 1Ch ; dwLength
                mov     [esp+4], edx    ; lpBuffer
                mov     [esp], addr     ; lpAddress
                call    ebx ; __imp__VirtualQuery@12
                sub     esp, 0Ch
                test    eax, eax
                jz      loc_401BF7
                mov     eax, [ebp+b.Protect]
                cmp     eax, 4
                jnz     short loc_401AF0

loc_401ABE:                             ; CODE XREF: ___write_memory_part_0+123¡éj
                mov     eax, [ebp+len]
                mov     [esp], addr     ; void *
                mov     [esp+8], eax    ; Size
                mov     eax, [ebp+src]
                mov     [esp+4], eax    ; Src
                call    _memcpy

loc_401AD4:                             ; CODE XREF: ___write_memory_part_0+168¡éj
                                        ; ___write_memory_part_0+16D¡éj
                lea     esp, [ebp-0Ch]
                pop     ebx
                pop     addr
                pop     edi
                pop     ebp
                retn
; ---------------------------------------------------------------------------
addr = esi                              ; void *
                align 10h

loc_401AE0:                             ; CODE XREF: ___write_memory_part_0+36¡èj
                lea     edx, [ebp+b]
                mov     ebx, ds:__imp__VirtualQuery@12
                jmp     short loc_401A9A
; ---------------------------------------------------------------------------
                align 10h

loc_401AF0:                             ; CODE XREF: ___write_memory_part_0+EC¡èj
                cmp     eax, 40h ; '@'
                jz      short loc_401ABE
                mov     eax, [ebp+b.RegionSize]
                lea     edi, [ebp+oldprot]
                mov     ebx, ds:__imp__VirtualProtect@16
                mov     [esp+0Ch], edi  ; lpflOldProtect
                mov     dword ptr [esp+8], 40h ; '@' ; flNewProtect
                mov     [esp+4], eax    ; dwSize
                mov     eax, [ebp+b.BaseAddress]
                mov     [esp], eax      ; lpAddress
                call    ebx ; __imp__VirtualProtect@16
                mov     eax, [ebp+len]
                sub     esp, 10h
                mov     [esp+8], eax    ; Size
                mov     eax, [ebp+src]
                mov     [esp], addr     ; void *
                mov     [esp+4], eax    ; Src
                call    _memcpy
                mov     eax, [ebp+b.Protect]
                cmp     eax, 40h ; '@'
                jz      short loc_401AD4
                cmp     eax, 4
                jz      short loc_401AD4
                mov     eax, [ebp+oldprot]
                mov     [esp+0Ch], edi  ; lpflOldProtect
                mov     [esp+8], eax    ; flNewProtect
                mov     eax, [ebp+b.RegionSize]
                mov     [esp+4], eax    ; dwSize
                mov     eax, [ebp+b.BaseAddress]
                mov     [esp], eax      ; lpAddress
                call    ebx ; __imp__VirtualProtect@16
                sub     esp, 10h
                lea     esp, [ebp-0Ch]
                pop     ebx
                pop     addr
                pop     edi
                pop     ebp
                retn
; ---------------------------------------------------------------------------

loc_401B64:                             ; CODE XREF: ___write_memory_part_0+BD¡èj
addr = esi                              ; void *
                cmp     eax, 40h ; '@'
                jz      loc_401A93
                mov     eax, [ebp+b.RegionSize]
                add     ecx, ds:_the_secs
                mov     [ebp+var_44], edx
                mov     dword ptr [esp+8], 40h ; '@' ; flNewProtect
                mov     [esp+4], eax    ; dwSize
                mov     eax, [ebp+b.BaseAddress]
                mov     [esp+0Ch], ecx  ; lpflOldProtect
                mov     [esp], eax      ; lpAddress
                call    ds:__imp__VirtualProtect@16
                mov     edx, [ebp+var_44]
                sub     esp, 10h
                test    eax, eax
                jnz     loc_401A93
                call    ds:__imp__GetLastError@0
                mov     dword ptr [esp], offset msg ; "  VirtualProtect failed with code 0x%x"
                mov     [esp+4], eax
                call    ___report_error
; ---------------------------------------------------------------------------
addr = eax                              ; void *
src_0 = edx                             ; const void *
                align 10h

loc_401BC0:                             ; CODE XREF: ___write_memory_part_0+19¡èj
                xor     ebx, ebx
                jmp     loc_401A16
; ---------------------------------------------------------------------------

loc_401BC7:                             ; CODE XREF: ___write_memory_part_0+B1¡èj
addr = esi                              ; void *
                mov     eax, ds:_the_secs
                mov     eax, [eax+ecx+4]
                mov     [esp+8], eax
                mov     eax, [edi+8]
                mov     dword ptr [esp], offset aVirtualqueryFa ; "  VirtualQuery failed for %d bytes at a"...
                mov     [esp+4], eax
                call    ___report_error
; ---------------------------------------------------------------------------

loc_401BE7:                             ; CODE XREF: ___write_memory_part_0+52¡èj
                mov     [esp+4], addr
                mov     dword ptr [esp], offset aAddressPHasNoI ; "Address %p has no image-section"
                call    ___report_error
; ---------------------------------------------------------------------------

loc_401BF7:                             ; CODE XREF: ___write_memory_part_0+E0¡èj
                mov     [esp+8], addr
                mov     dword ptr [esp+4], 1Ch
                mov     dword ptr [esp], offset aVirtualqueryFa ; "  VirtualQuery failed for %d bytes at a"...
                call    ___report_error
___write_memory_part_0 endp

; ---------------------------------------------------------------------------
                align 10h

; =============== S U B R O U T I N E =======================================


; void _pei386_runtime_relocator()
                public __pei386_runtime_relocator
__pei386_runtime_relocator proc near    ; CODE XREF: ___tmainCRTStartup:loc_401297¡èp

msg             = dword ptr -5Ch
lpBuffer        = dword ptr -58h
dwLength        = dword ptr -54h
lpflOldProtect  = dword ptr -50h
var_3D          = byte ptr -3Dh

                mov     eax, ds:_was_init_60223
                test    eax, eax
                jz      short loc_401C20
                retn
; ---------------------------------------------------------------------------
                align 10h

loc_401C20:                             ; CODE XREF: __pei386_runtime_relocator+7¡èj
                push    ebp
                mov     ebp, esp
                push    edi
                push    esi
                push    ebx
                sub     esp, 4Ch
                mov     ds:_was_init_60223, 1
                call    ___mingw_GetSectionCount
mSecs = eax                             ; int
                lea     mSecs, [mSecs+mSecs*2]
                lea     eax, ds:1Eh[eax*4]
                and     eax, 0FFFFFFF0h
                call    ___chkstk_ms
                mov     ds:_maxSections, 0
                sub     esp, eax
                lea     eax, [esp+5Ch+var_3D]
                and     eax, 0FFFFFFF0h
                mov     ds:_the_secs, eax
                mov     eax, offset __RUNTIME_PSEUDO_RELOC_LIST_END___0
                sub     eax, offset __rt_psrelocs_start
                cmp     eax, 7
                jle     loc_401D11
                cmp     eax, 0Bh
                jle     loc_401DE3
                mov     eax, ds:__rt_psrelocs_start
                test    eax, eax
                jnz     loc_401D19
                mov     eax, ds:dword_404498
                test    eax, eax
                jnz     loc_401D19
                mov     edi, ds:dword_40449C
                mov     ebx, offset unk_4044A0
                test    edi, edi
                jz      loc_401DE8
                mov     ebx, offset __rt_psrelocs_start

loc_401CB0:                             ; CODE XREF: __pei386_runtime_relocator+1E7¡éj
                mov     eax, [ebx+8]
                cmp     eax, 1
                jnz     loc_401ED3
                add     ebx, 0Ch
                cmp     ebx, offset __RUNTIME_PSEUDO_RELOC_LIST_END___0
                jnb     short loc_401D11

loc_401CC7:                             ; CODE XREF: __pei386_runtime_relocator+236¡éj
                mov     edx, [ebx]
                mov     edi, [ebx+4]
                mov     ecx, [edx+400000h]
                lea     eax, [edi+400000h] ; addr
                mov     [ebp-3Ch], ecx
                movzx   ecx, byte ptr [ebx+8]
                cmp     ecx, 10h
                jz      loc_401E02
                cmp     ecx, 20h ; ' '
                jz      loc_401E89
                cmp     ecx, 8
                jz      loc_401E51
                mov     [esp+5Ch+lpBuffer], ecx
                mov     [esp+5Ch+msg], offset aUnknownPseudoR ; "  Unknown pseudo relocation bit size %d"...
                mov     dword ptr [ebp-34h], 0
                call    ___report_error
; ---------------------------------------------------------------------------

loc_401D11:                             ; CODE XREF: __pei386_runtime_relocator+5F¡èj
                                        ; __pei386_runtime_relocator+B5¡èj ...
                lea     esp, [ebp-0Ch]
                pop     ebx
                pop     esi
                pop     edi
                pop     ebp
                retn
; ---------------------------------------------------------------------------

loc_401D19:                             ; CODE XREF: __pei386_runtime_relocator+75¡èj
                                        ; __pei386_runtime_relocator+82¡èj
                mov     ebx, offset __rt_psrelocs_start

loc_401D1E:                             ; CODE XREF: __pei386_runtime_relocator+1DC¡éj
                                        ; __pei386_runtime_relocator+1ED¡éj
                cmp     ebx, offset __RUNTIME_PSEUDO_RELOC_LIST_END___0
                jnb     short loc_401D11
                lea     eax, [ebp-34h]
                mov     [ebp-3Ch], eax
                lea     esi, [esi+0]

loc_401D30:                             ; CODE XREF: __pei386_runtime_relocator+14B¡éj
                mov     edx, [ebx+4]
                mov     ecx, 4          ; len
                add     ebx, 8
                lea     eax, [edx+400000h] ; addr
                mov     edx, [edx+400000h]
                add     edx, [ebx-8]
                mov     [ebp-34h], edx
                mov     edx, [ebp-3Ch]  ; src
                call    ___write_memory_part_0
                cmp     ebx, offset __RUNTIME_PSEUDO_RELOC_LIST_END___0
                jb      short loc_401D30

loc_401D5D:                             ; CODE XREF: __pei386_runtime_relocator+23C¡éj
                mov     eax, ds:_maxSections
                xor     ebx, ebx
                test    eax, eax
                jg      short loc_401D7B
                jmp     short loc_401D11
; ---------------------------------------------------------------------------
                align 10h

loc_401D70:                             ; CODE XREF: __pei386_runtime_relocator+180¡éj
                                        ; __pei386_runtime_relocator+1D1¡éj
                add     ebx, 1
                cmp     ebx, ds:_maxSections
                jge     short loc_401D11

loc_401D7B:                             ; CODE XREF: __pei386_runtime_relocator+156¡èj
                mov     eax, ds:_the_secs
                lea     esi, [ebx+ebx*2]
                lea     edi, ds:0[esi*4]
                add     eax, edi
                mov     edx, [eax]
                test    edx, edx
                jz      short loc_401D70
                mov     ecx, [ebp-3Ch]
                mov     [esp+5Ch+dwLength], 1Ch ; dwLength
                mov     [esp+5Ch+lpBuffer], ecx ; lpBuffer
                mov     eax, [eax+4]
                mov     [esp+5Ch+msg], eax ; lpAddress
                call    ds:__imp__VirtualQuery@12
                sub     esp, 0Ch
                test    eax, eax
                jz      loc_401EAE
                lea     eax, [ebp-38h]
                mov     [esp+5Ch+lpflOldProtect], eax ; lpflOldProtect
                mov     eax, ds:_the_secs
                mov     eax, [eax+esi*4]
                mov     [esp+5Ch+dwLength], eax ; flNewProtect
                mov     eax, [ebp-28h]
                mov     [esp+5Ch+lpBuffer], eax ; dwSize
                mov     eax, [ebp-34h]
                mov     [esp+5Ch+msg], eax ; lpAddress
                call    ds:__imp__VirtualProtect@16
                sub     esp, 10h
                jmp     short loc_401D70
; ---------------------------------------------------------------------------

loc_401DE3:                             ; CODE XREF: __pei386_runtime_relocator+68¡èj
                mov     ebx, offset __rt_psrelocs_start

loc_401DE8:                             ; CODE XREF: __pei386_runtime_relocator+95¡èj
                mov     esi, [ebx]
                test    esi, esi
                jnz     loc_401D1E
                mov     ecx, [ebx+4]
                test    ecx, ecx
                jz      loc_401CB0
                jmp     loc_401D1E
; ---------------------------------------------------------------------------

loc_401E02:                             ; CODE XREF: __pei386_runtime_relocator+D2¡èj
                movzx   ecx, word ptr [edi+400000h]
                movzx   edi, cx
                mov     esi, edi
                or      esi, 0FFFF0000h
                test    cx, cx
                cmovs   edi, esi
                mov     esi, [ebp-3Ch]
                sub     edi, edx
                lea     ecx, [ebp-34h]
                sub     edi, 400000h
                mov     [ebp-3Ch], ecx
                lea     edx, [ebp-34h]  ; src
                mov     ecx, 2          ; len
                add     esi, edi
                mov     [ebp-34h], esi
                call    ___write_memory_part_0

loc_401E3D:                             ; CODE XREF: __pei386_runtime_relocator+277¡éj
                                        ; __pei386_runtime_relocator+29C¡éj
                add     ebx, 0Ch
                cmp     ebx, offset __RUNTIME_PSEUDO_RELOC_LIST_END___0
                jb      loc_401CC7
                jmp     loc_401D5D
; ---------------------------------------------------------------------------

loc_401E51:                             ; CODE XREF: __pei386_runtime_relocator+E4¡èj
                movzx   ecx, byte ptr [eax]
                movzx   edi, cl
                mov     esi, edi
                or      esi, 0FFFFFF00h
                test    cl, cl
                cmovs   edi, esi
                mov     esi, [ebp-3Ch]
                sub     edi, 400000h
                sub     edi, edx
                lea     ecx, [ebp-34h]
                add     esi, edi
                mov     [ebp-3Ch], ecx
                lea     edx, [ebp-34h]  ; src
                mov     ecx, 1          ; len
                mov     [ebp-34h], esi
                call    ___write_memory_part_0
                jmp     short loc_401E3D
; ---------------------------------------------------------------------------

loc_401E89:                             ; CODE XREF: __pei386_runtime_relocator+DB¡èj
                mov     esi, [ebp-3Ch]
                add     edx, 400000h
                lea     ecx, [ebp-34h]
                mov     [ebp-3Ch], ecx
                mov     ecx, 4          ; len
                sub     esi, edx
                add     esi, [eax]
                lea     edx, [ebp-34h]  ; src
                mov     [ebp-34h], esi
                call    ___write_memory_part_0
                jmp     short loc_401E3D
; ---------------------------------------------------------------------------

loc_401EAE:                             ; CODE XREF: __pei386_runtime_relocator+1A2¡èj
                mov     ecx, ds:_the_secs
                add     ecx, edi
                mov     eax, [ecx+4]
                mov     [esp+5Ch+dwLength], eax
                mov     eax, [ecx+8]
                mov     eax, [eax+8]
                mov     [esp+5Ch+msg], offset aVirtualqueryFa ; "  VirtualQuery failed for %d bytes at a"...
                mov     [esp+5Ch+lpBuffer], eax
                call    ___report_error
; ---------------------------------------------------------------------------

loc_401ED3:                             ; CODE XREF: __pei386_runtime_relocator+A6¡èj
                mov     [esp+5Ch+lpBuffer], eax
                mov     [esp+5Ch+msg], offset aUnknownPseudoR_0 ; "  Unknown pseudo relocation protocol ve"...
                call    ___report_error
__pei386_runtime_relocator endp

; ---------------------------------------------------------------------------
                align 10h

; =============== S U B R O U T I N E =======================================


; void fpreset()
                public _fpreset
_fpreset        proc near               ; CODE XREF: ___tmainCRTStartup+13D¡èp
                                        ; __gnu_exception_handler@4+142¡èp
                fninit
                retn
_fpreset        endp

; ---------------------------------------------------------------------------
                align 10h

; =============== S U B R O U T I N E =======================================


; void __do_global_dtors()
                public ___do_global_dtors
___do_global_dtors proc near            ; DATA XREF: ___do_global_ctors:loc_401F52¡éo
                mov     eax, _p_59264
                mov     eax, [eax]
                test    eax, eax
                jz      short locret_401F2A
                sub     esp, 0Ch
                xchg    ax, ax

loc_401F10:                             ; CODE XREF: ___do_global_dtors+25¡éj
                call    eax
                mov     eax, _p_59264
                lea     edx, [eax+4]
                mov     eax, [eax+4]
                mov     _p_59264, edx
                test    eax, eax
                jnz     short loc_401F10
                add     esp, 0Ch

locret_401F2A:                          ; CODE XREF: ___do_global_dtors+9¡èj
                rep retn
___do_global_dtors endp

; ---------------------------------------------------------------------------
                align 10h

; =============== S U B R O U T I N E =======================================


; void __do_global_ctors()
                public ___do_global_ctors
___do_global_ctors proc near            ; CODE XREF: ___main+1A¡éj

func            = dword ptr -1Ch

                push    ebx
                sub     esp, 18h
                mov     ebx, ds:___CTOR_LIST__
nptrs = ebx                             ; unsigned int
                cmp     nptrs, 0FFFFFFFFh
                jz      short loc_401F63

loc_401F3F:                             ; CODE XREF: ___do_global_ctors+47¡éj
i = ebx                                 ; unsigned int
                test    i, i
                jz      short loc_401F52

loc_401F43:                             ; CODE XREF: ___do_global_ctors+20¡éj
                call    ds:___CTOR_LIST__[i*4]
                sub     ebx, 1
i = ebx                                 ; unsigned int
                lea     esi, [esi+0]
                jnz     short loc_401F43

loc_401F52:                             ; CODE XREF: ___do_global_ctors+11¡èj
                mov     [esp+1Ch+func], offset ___do_global_dtors ; func
                call    _atexit
                add     esp, 18h
                pop     i
                retn
; ---------------------------------------------------------------------------

loc_401F63:                             ; CODE XREF: ___do_global_ctors+D¡èj
nptrs = ebx                             ; unsigned int
                xor     nptrs, nptrs
                jmp     short loc_401F69
; ---------------------------------------------------------------------------

loc_401F67:                             ; CODE XREF: ___do_global_ctors+45¡éj
nptrs = ebx                             ; unsigned int
                mov     nptrs, eax

loc_401F69:                             ; CODE XREF: ___do_global_ctors+35¡èj
                lea     eax, [nptrs+1]
                mov     edx, ds:___CTOR_LIST__[eax*4]
                test    edx, edx
                jnz     short loc_401F67
                jmp     short loc_401F3F
___do_global_ctors endp

; ---------------------------------------------------------------------------
                align 10h

; =============== S U B R O U T I N E =======================================


; void __main()
                public ___main
___main         proc near               ; CODE XREF: ___tmainCRTStartup+23D¡èp
                                        ; _main+11¡ép
                mov     ecx, ds:_initialized
                test    ecx, ecx
                jz      short loc_401F90
                rep retn
; ---------------------------------------------------------------------------
                align 10h

loc_401F90:                             ; CODE XREF: ___main+8¡èj
                mov     ds:_initialized, 1
                jmp     short ___do_global_ctors
___main         endp

; ---------------------------------------------------------------------------
                align 10h

; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; void __security_init_cookie()
                public ___security_init_cookie
___security_init_cookie proc near       ; CODE XREF: _WinMainCRTStartup+D¡èp
                                        ; _mainCRTStartup+D¡èp

var_30          = dword ptr -30h
var_2C          = dword ptr -2Ch
systime         = FT ptr -28h
perfctr         = LARGE_INTEGER ptr -20h

                push    ebp
                mov     ebp, esp
                push    edi
                push    esi
                push    ebx
                sub     esp, 2Ch
                mov     eax, ___security_cookie
                mov     dword ptr [ebp+systime], 0
                mov     dword ptr [ebp+systime+4], 0
                cmp     eax, 0BB40E64Eh
                jz      short loc_401FD2
                not     eax
                mov     ___security_cookie_complement, eax
                lea     esp, [ebp-0Ch]
                pop     ebx
                pop     esi
                pop     edi
                pop     ebp
                retn
; ---------------------------------------------------------------------------

loc_401FD2:                             ; CODE XREF: ___security_init_cookie+21¡èj
                lea     eax, [ebp+systime]
                mov     [esp], eax      ; lpSystemTimeAsFileTime
                call    ds:__imp__GetSystemTimeAsFileTime@4
                mov     esi, dword ptr [ebp+systime]
cookie = esi                            ; UINT_PTR
                mov     edi, dword ptr [ebp+systime+4]
                xor     esi, edi
cookie = esi                            ; UINT_PTR
                sub     esp, 4
                call    ds:__imp__GetCurrentProcessId@0
                mov     ebx, eax
                call    ds:__imp__GetCurrentThreadId@0
                mov     [ebp+var_2C], eax
                call    ds:__imp__GetTickCount@0
                mov     [ebp+var_30], eax
                lea     eax, [ebp+perfctr]
                mov     [esp], eax      ; lpPerformanceCount
                call    ds:__imp__QueryPerformanceCounter@4
                xor     esi, dword ptr [ebp+perfctr]
                xor     esi, dword ptr [ebp+perfctr+4]
                xor     esi, ebx
                xor     esi, [ebp+var_2C]
                sub     esp, 4
                xor     esi, [ebp+var_30]
cookie = esi                            ; UINT_PTR
                cmp     cookie, 0BB40E64Eh
                jz      short loc_402040
                mov     eax, cookie
                not     eax

loc_40202C:                             ; CODE XREF: ___security_init_cookie+AA¡éj
                mov     ___security_cookie, cookie
                mov     ___security_cookie_complement, eax
                lea     esp, [ebp-0Ch]
                pop     ebx
                pop     cookie
                pop     edi
                pop     ebp
                retn
; ---------------------------------------------------------------------------
cookie = esi                            ; UINT_PTR
                align 10h

loc_402040:                             ; CODE XREF: ___security_init_cookie+86¡èj
                mov     eax, 44BF19B0h
                mov     cookie, 0BB40E64Fh
                jmp     short loc_40202C
___security_init_cookie endp

; ---------------------------------------------------------------------------
                align 10h

; =============== S U B R O U T I N E =======================================

; Attributes: noreturn bp-based frame

; void __cdecl __report_gsfailure(ULONG_PTR StackCookie)
                public ___report_gsfailure
___report_gsfailure proc near

cookie          = dword ptr -10h
StackCookie     = dword ptr  8

                push    ebp
                mov     ebp, esp
                sub     esp, 28h
                mov     eax, [ebp+4]
                lea     edx, [ebp+4]
                mov     ds:_GS_ContextRecord._Esp, edx
                mov     ds:_GS_ExceptionRecord.ExceptionCode, 0C0000409h
                mov     ds:_GS_ExceptionRecord.ExceptionFlags, 1
                mov     ds:_GS_ContextRecord._Eip, eax
                mov     ds:_GS_ExceptionRecord.ExceptionAddress, eax
                mov     eax, [ebp+StackCookie]
                mov     dword ptr [esp], 0 ; lpTopLevelExceptionFilter
                mov     ds:_GS_ContextRecord._Ecx, eax
                mov     eax, ___security_cookie
                mov     [ebp+cookie], eax
                mov     eax, ___security_cookie_complement
                mov     [ebp+cookie+4], eax
                call    ds:__imp__SetUnhandledExceptionFilter@4
                sub     esp, 4
                mov     dword ptr [esp], offset _GS_ExceptionPointers ; ExceptionInfo
                call    ds:__imp__UnhandledExceptionFilter@4
                sub     esp, 4
                call    ds:__imp__GetCurrentProcess@0
                mov     dword ptr [esp+4], 0C0000409h ; uExitCode
                mov     [esp], eax      ; hProcess
                call    ds:__imp__TerminateProcess@8
                sub     esp, 8
                call    _abort
___report_gsfailure endp

; ---------------------------------------------------------------------------
                align 10h

; =============== S U B R O U T I N E =======================================

; Attributes: static bp-based frame

; void __mingwthr_run_key_dtors_part_0()
___mingwthr_run_key_dtors_part_0 proc near
                                        ; CODE XREF: ___mingw_TLScallback:loc_402312¡ép
                                        ; ___mingw_TLScallback:loc_402320¡ép
                push    ebp
                mov     ebp, esp
                push    edi
                push    esi
                push    ebx
                sub     esp, 1Ch
                mov     dword ptr [esp], offset ___mingwthr_cs ; lpCriticalSection
                call    ds:__imp__EnterCriticalSection@4
                mov     edi, ds:_key_dtor_list
keyp = edi                              ; volatile __mingwthr_key_t *
                mov     esi, ds:__imp__GetLastError@0
                sub     esp, 4
                test    keyp, keyp
                jz      short loc_402139
                lea     esi, [esi+0]

loc_402110:                             ; CODE XREF: ___mingwthr_run_key_dtors_part_0+57¡éj
                mov     eax, [keyp]
                mov     [esp], eax      ; dwTlsIndex
                call    ds:__imp__TlsGetValue@4
                sub     esp, 4
                mov     ebx, eax
value = eax                             ; LPVOID
                call    esi ; __imp__GetLastError@0
                test    eax, eax
                jnz     short loc_402132
                test    value, value
                jz      short loc_402132
                mov     eax, [keyp+4]
                mov     [esp], value
                call    eax

loc_402132:                             ; CODE XREF: ___mingwthr_run_key_dtors_part_0+44¡èj
                                        ; ___mingwthr_run_key_dtors_part_0+48¡èj
                mov     keyp, [keyp+8]
                test    keyp, keyp
                jnz     short loc_402110

loc_402139:                             ; CODE XREF: ___mingwthr_run_key_dtors_part_0+27¡èj
                mov     dword ptr [esp], offset ___mingwthr_cs ; lpCriticalSection
                call    ds:__imp__LeaveCriticalSection@4
                sub     esp, 4
                lea     esp, [ebp-0Ch]
                pop     ebx
                pop     esi
                pop     keyp
                pop     ebp
                retn
___mingwthr_run_key_dtors_part_0 endp

; ---------------------------------------------------------------------------
                jmp     short ____w64_mingwthr_add_key_dtor
; ---------------------------------------------------------------------------
                align 10h

; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __cdecl ___w64_mingwthr_add_key_dtor(DWORD key, void (*dtor)(void *))
                public ____w64_mingwthr_add_key_dtor
____w64_mingwthr_add_key_dtor proc near ; CODE XREF: .text:00402151¡èj

key             = dword ptr  8
dtor            = dword ptr  0Ch

                push    ebp
                mov     ebp, esp
                push    esi
                xor     esi, esi
                push    ebx
                sub     esp, 10h
                mov     eax, ds:___mingwthr_cs_init
                test    eax, eax
                jnz     short loc_402180

loc_402173:                             ; CODE XREF: ____w64_mingwthr_add_key_dtor+81¡éj
                lea     esp, [ebp-8]
                mov     eax, esi
                pop     ebx
                pop     esi
                pop     ebp
                retn
; ---------------------------------------------------------------------------
                align 10h

loc_402180:                             ; CODE XREF: ____w64_mingwthr_add_key_dtor+11¡èj
                mov     dword ptr [esp+4], 0Ch ; Size
                mov     dword ptr [esp], 1 ; Count
                call    _calloc
                test    eax, eax
                mov     ebx, eax
new_key = eax                           ; __mingwthr_key_t *
                jz      short loc_4021DC
                mov     new_key, [ebp+key]
new_key = ebx                           ; __mingwthr_key_t *
                mov     dword ptr [esp], offset ___mingwthr_cs ; lpCriticalSection
                mov     [new_key], eax
                mov     eax, [ebp+dtor]
                mov     [new_key+4], eax
                call    ds:__imp__EnterCriticalSection@4
                mov     eax, ds:_key_dtor_list
                mov     ds:_key_dtor_list, new_key
                mov     [new_key+8], eax
                sub     esp, 4
                mov     dword ptr [esp], offset ___mingwthr_cs ; lpCriticalSection
                call    ds:__imp__LeaveCriticalSection@4
                mov     eax, esi
                sub     esp, 4
                lea     esp, [ebp-8]
                pop     new_key
                pop     esi
                pop     ebp
                retn
; ---------------------------------------------------------------------------

loc_4021DC:                             ; CODE XREF: ____w64_mingwthr_add_key_dtor+38¡èj
new_key = eax                           ; __mingwthr_key_t *
                mov     esi, 0FFFFFFFFh
                jmp     short loc_402173
____w64_mingwthr_add_key_dtor endp

; ---------------------------------------------------------------------------
                align 10h

; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __cdecl ___w64_mingwthr_remove_key_dtor(DWORD key)
                public ____w64_mingwthr_remove_key_dtor
____w64_mingwthr_remove_key_dtor proc near

var_4           = dword ptr -4
key             = dword ptr  8

                push    ebp
                mov     ebp, esp
                push    ebx
                sub     esp, 14h
                mov     eax, ds:___mingwthr_cs_init
                mov     ebx, [ebp+key]
                test    eax, eax
                jnz     short loc_402210
                xor     eax, eax
                mov     ebx, [ebp+var_4]
                leave
                retn
; ---------------------------------------------------------------------------
                align 10h

loc_402210:                             ; CODE XREF: ____w64_mingwthr_remove_key_dtor+11¡èj
                mov     dword ptr [esp], offset ___mingwthr_cs ; lpCriticalSection
                call    ds:__imp__EnterCriticalSection@4
                mov     edx, ds:_key_dtor_list
                sub     esp, 4
cur_key = edx                           ; volatile __mingwthr_key_t *
                test    cur_key, cur_key
                jz      short loc_402241
                mov     eax, [cur_key]
                cmp     eax, ebx
                jnz     short loc_40223A
                jmp     short loc_402278
; ---------------------------------------------------------------------------

loc_402232:                             ; CODE XREF: ____w64_mingwthr_remove_key_dtor+4F¡éj
cur_key = eax                           ; volatile __mingwthr_key_t *
prev_key = edx                          ; volatile __mingwthr_key_t *
                mov     ecx, [cur_key]
                cmp     ecx, ebx
                jz      short loc_402258
                mov     prev_key, cur_key

loc_40223A:                             ; CODE XREF: ____w64_mingwthr_remove_key_dtor+3E¡èj
cur_key = edx                           ; volatile __mingwthr_key_t *
                mov     eax, [cur_key+8]
prev_key = edx                          ; volatile __mingwthr_key_t *
cur_key = eax                           ; volatile __mingwthr_key_t *
                test    cur_key, cur_key
                jnz     short loc_402232

loc_402241:                             ; CODE XREF: ____w64_mingwthr_remove_key_dtor+38¡èj
                mov     dword ptr [esp], offset ___mingwthr_cs ; lpCriticalSection
                call    ds:__imp__LeaveCriticalSection@4
                sub     esp, 4

loc_402251:                             ; CODE XREF: ____w64_mingwthr_remove_key_dtor+86¡éj
                xor     eax, eax
                mov     ebx, [ebp+var_4]
                leave
                retn
; ---------------------------------------------------------------------------

loc_402258:                             ; CODE XREF: ____w64_mingwthr_remove_key_dtor+46¡èj
prev_key = edx                          ; volatile __mingwthr_key_t *
cur_key = eax                           ; volatile __mingwthr_key_t *
                mov     ecx, [cur_key+8]
                mov     [prev_key+8], ecx

loc_40225E:                             ; CODE XREF: ____w64_mingwthr_remove_key_dtor+92¡éj
                mov     [esp], cur_key  ; Block
                call    _free
                mov     dword ptr [esp], offset ___mingwthr_cs ; lpCriticalSection
                call    ds:__imp__LeaveCriticalSection@4
                sub     esp, 4
                jmp     short loc_402251
; ---------------------------------------------------------------------------

loc_402278:                             ; CODE XREF: ____w64_mingwthr_remove_key_dtor+40¡èj
cur_key = edx                           ; volatile __mingwthr_key_t *
                mov     eax, [cur_key+8]
                mov     ds:_key_dtor_list, eax
                mov     eax, cur_key
                jmp     short loc_40225E
____w64_mingwthr_remove_key_dtor endp

; ---------------------------------------------------------------------------
                align 10h

; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; WINBOOL __cdecl __mingw_TLScallback(HANDLE hDllHandle, DWORD reason, LPVOID reserved)
                public ___mingw_TLScallback
___mingw_TLScallback proc near          ; CODE XREF: ___dyn_tls_dtor@12+33¡èp
                                        ; ___dyn_tls_init@12+77¡èp

hDllHandle      = dword ptr  8
reason          = dword ptr  0Ch
reserved        = dword ptr  10h

                push    ebp
                mov     ebp, esp
                sub     esp, 18h
                mov     eax, [ebp+reason]
                cmp     eax, 1
                jz      short loc_4022E4
                jb      short loc_4022B5
                cmp     eax, 3
                jnz     short loc_4022AE
                mov     eax, ds:___mingwthr_cs_init
                test    eax, eax
                jnz     short loc_402312

loc_4022AE:                             ; CODE XREF: ___mingw_TLScallback+13¡èj
                                        ; ___mingw_TLScallback+36¡éj ...
                mov     eax, 1
                leave
                retn
; ---------------------------------------------------------------------------

loc_4022B5:                             ; CODE XREF: ___mingw_TLScallback+E¡èj
                mov     eax, ds:___mingwthr_cs_init
                test    eax, eax
                jnz     short loc_402320

loc_4022BE:                             ; CODE XREF: ___mingw_TLScallback+95¡éj
                mov     eax, ds:___mingwthr_cs_init
                cmp     eax, 1
                jnz     short loc_4022AE
                mov     ds:___mingwthr_cs_init, 0
                mov     dword ptr [esp], offset ___mingwthr_cs ; lpCriticalSection
                call    ds:__imp__DeleteCriticalSection@4
                sub     esp, 4
                jmp     short loc_4022AE
; ---------------------------------------------------------------------------

loc_4022E4:                             ; CODE XREF: ___mingw_TLScallback+C¡èj
                mov     eax, ds:___mingwthr_cs_init
                test    eax, eax
                jz      short loc_402300

loc_4022ED:                             ; CODE XREF: ___mingw_TLScallback+80¡éj
                mov     ds:___mingwthr_cs_init, 1
                mov     eax, 1
                leave
                retn
; ---------------------------------------------------------------------------
                align 10h

loc_402300:                             ; CODE XREF: ___mingw_TLScallback+5B¡èj
                mov     dword ptr [esp], offset ___mingwthr_cs ; lpCriticalSection
                call    ds:__imp__InitializeCriticalSection@4
                sub     esp, 4
                jmp     short loc_4022ED
; ---------------------------------------------------------------------------

loc_402312:                             ; CODE XREF: ___mingw_TLScallback+1C¡èj
                call    ___mingwthr_run_key_dtors_part_0
                jmp     short loc_4022AE
; ---------------------------------------------------------------------------
                align 10h

loc_402320:                             ; CODE XREF: ___mingw_TLScallback+2C¡èj
                call    ___mingwthr_run_key_dtors_part_0
                jmp     short loc_4022BE
___mingw_TLScallback endp

; ---------------------------------------------------------------------------
                align 10h

; =============== S U B R O U T I N E =======================================


; WINBOOL __usercall _ValidateImageBase_part_0@<eax>(PBYTE pImageBase@<eax>)
__ValidateImageBase_part_0 proc near    ; CODE XREF: __ValidateImageBase:loc_402360¡éj
                                        ; __FindPESectionByName+35¡ép ...
pImageBase = eax                        ; PBYTE
                add     pImageBase, [pImageBase+3Ch]
pNTHeader = eax                         ; PIMAGE_NT_HEADERS
                cmp     dword ptr [pNTHeader], 4550h
                jz      short loc_402340
                xor     pNTHeader, pNTHeader
                retn
; ---------------------------------------------------------------------------
pNTHeader = eax                         ; PIMAGE_NT_HEADERS
                align 10h

loc_402340:                             ; CODE XREF: __ValidateImageBase_part_0+9¡èj
                cmp     word ptr [pNTHeader+18h], 10Bh
                setz    al
                movzx   eax, al
                retn
__ValidateImageBase_part_0 endp

; ---------------------------------------------------------------------------
                align 10h

; =============== S U B R O U T I N E =======================================


; WINBOOL __cdecl _ValidateImageBase(PBYTE pImageBase)
                public __ValidateImageBase
__ValidateImageBase proc near

pDOSHeader      = dword ptr  4

                mov     eax, [esp+pDOSHeader]
                cmp     word ptr [eax], 5A4Dh
                jz      short loc_402360
                xor     eax, eax
                retn
; ---------------------------------------------------------------------------
pDOSHeader_0 = eax                      ; PIMAGE_DOS_HEADER
                align 10h

loc_402360:                             ; CODE XREF: __ValidateImageBase+9¡èj
                jmp     short __ValidateImageBase_part_0
__ValidateImageBase endp

; ---------------------------------------------------------------------------
                align 10h

; =============== S U B R O U T I N E =======================================


; PIMAGE_SECTION_HEADER __cdecl _FindPESection(PBYTE pImageBase, DWORD_PTR rva)
                public __FindPESection
__FindPESection proc near               ; CODE XREF: ___mingw_GetSectionForAddress+3A¡ép
                                        ; __IsNonwritableInCurrentImage+35¡ép ...

pImageBase      = dword ptr  4
rva             = dword ptr  8

                push    esi
                push    ebx
                mov     edx, [esp+8+pImageBase]
                mov     ebx, [esp+8+rva]
                add     edx, [edx+3Ch]
pNTHeader = edx                         ; PIMAGE_NT_HEADERS
                movzx   esi, word ptr [pNTHeader+6]
                movzx   eax, word ptr [pNTHeader+14h]
                test    esi, esi
                lea     eax, [pNTHeader+eax+18h]
pSection = eax                          ; PIMAGE_SECTION_HEADER
                jz      short loc_4023A8
                xor     pNTHeader, pNTHeader
iSection = edx                          ; unsigned int
                nop

loc_402390:                             ; CODE XREF: __FindPESection+36¡éj
                mov     ecx, [pSection+0Ch]
                cmp     ecx, ebx
                ja      short loc_40239E
                add     ecx, [pSection+8]
                cmp     ebx, ecx
                jb      short loc_4023AA

loc_40239E:                             ; CODE XREF: __FindPESection+25¡èj
                add     iSection, 1
                add     pSection, 28h ; '('
                cmp     iSection, esi
                jb      short loc_402390

loc_4023A8:                             ; CODE XREF: __FindPESection+1B¡èj
rva_0 = ebx                             ; DWORD_PTR
                xor     pSection, pSection

loc_4023AA:                             ; CODE XREF: __FindPESection+2C¡èj
                pop     rva_0
                pop     esi
                retn
__FindPESection endp

; ---------------------------------------------------------------------------
                align 10h

; =============== S U B R O U T I N E =======================================


; PIMAGE_SECTION_HEADER __cdecl _FindPESectionByName(const char *pName)
                public __FindPESectionByName
__FindPESectionByName proc near

Str             = dword ptr -2Ch
Str2            = dword ptr -28h
MaxCount        = dword ptr -24h
pName           = dword ptr  4

                push    ebp
                push    edi
                push    esi
                xor     esi, esi
                push    ebx
                sub     esp, 1Ch
                mov     edi, [esp+2Ch+pName]
                mov     [esp+2Ch+Str], edi ; Str
                call    _strlen
                cmp     eax, 8
                ja      short loc_4023D5
                cmp     word ptr ds:400000h, 5A4Dh
                jz      short loc_4023E0

loc_4023D5:                             ; CODE XREF: __FindPESectionByName+18¡èj
                                        ; __FindPESectionByName+3C¡éj ...
                add     esp, 1Ch
                mov     eax, esi
                pop     ebx
                pop     esi
                pop     edi
                pop     ebp
                retn
; ---------------------------------------------------------------------------
                align 10h

loc_4023E0:                             ; CODE XREF: __FindPESectionByName+23¡èj
                mov     eax, 400000h    ; pImageBase
                call    __ValidateImageBase_part_0
                test    eax, eax
                jz      short loc_4023D5
                mov     eax, ds:40003Ch
                lea     edx, [eax+400000h]
pNTHeader = edx                         ; PIMAGE_NT_HEADERS
                movzx   eax, word ptr [eax+400014h]
                movzx   ebp, word ptr [pNTHeader+6]
                lea     ebx, [pNTHeader+eax+18h]
pSection = ebx                          ; PIMAGE_SECTION_HEADER
                test    ebp, ebp
                jnz     short loc_40241A
                jmp     short loc_4023D5
; ---------------------------------------------------------------------------
iSection = esi                          ; unsigned int
                align 10h

loc_402410:                             ; CODE XREF: __FindPESectionByName+80¡éj
                add     iSection, 1
                add     pSection, 28h ; '('
                cmp     iSection, ebp
                jnb     short loc_402440

loc_40241A:                             ; CODE XREF: __FindPESectionByName+5A¡èj
                mov     [esp+2Ch+MaxCount], 8 ; MaxCount
                mov     [esp+2Ch+Str2], edi ; Str2
                mov     [esp+2Ch+Str], pSection ; Str1
                call    _strncmp
                test    eax, eax
                jnz     short loc_402410
                add     esp, 1Ch
                mov     iSection, pSection
                mov     eax, esi
                pop     pSection
pSection = eax                          ; PIMAGE_SECTION_HEADER
                pop     esi
                pop     edi
                pop     ebp
                retn
; ---------------------------------------------------------------------------
pSection = ebx                          ; PIMAGE_SECTION_HEADER
iSection = esi                          ; unsigned int
                align 10h

loc_402440:                             ; CODE XREF: __FindPESectionByName+68¡èj
                add     esp, 1Ch
                xor     iSection, iSection
                pop     pSection
                mov     eax, esi
                pop     esi
                pop     edi
                pop     ebp
                retn
__FindPESectionByName endp

; ---------------------------------------------------------------------------
                align 10h

; =============== S U B R O U T I N E =======================================


; PIMAGE_SECTION_HEADER __cdecl __mingw_GetSectionForAddress(LPVOID p)
                public ___mingw_GetSectionForAddress
___mingw_GetSectionForAddress proc near ; CODE XREF: ___write_memory_part_0+49¡èp

pImageBase      = dword ptr -0Ch
var_8           = dword ptr -8
p               = dword ptr  4

                push    ebx
                xor     ebx, ebx
                sub     esp, 8
                cmp     word ptr ds:400000h, 5A4Dh
                jz      short loc_402468

loc_402461:                             ; CODE XREF: ___mingw_GetSectionForAddress+24¡éj
                add     esp, 8
                mov     eax, ebx
                pop     ebx
                retn
; ---------------------------------------------------------------------------

loc_402468:                             ; CODE XREF: ___mingw_GetSectionForAddress+F¡èj
                mov     eax, 400000h    ; pImageBase
                call    __ValidateImageBase_part_0
                test    eax, eax
                jz      short loc_402461
                mov     eax, [esp+0Ch+p]
                mov     [esp+0Ch+pImageBase], 400000h ; pImageBase
                sub     eax, 400000h
rva = eax                               ; DWORD_PTR
                mov     [esp+0Ch+var_8], rva ; rva
                call    __FindPESection
                add     esp, 8
                mov     ebx, eax
                mov     eax, ebx
                pop     ebx
                retn
___mingw_GetSectionForAddress endp

; ---------------------------------------------------------------------------
                align 10h

; =============== S U B R O U T I N E =======================================


; int __mingw_GetSectionCount()
                public ___mingw_GetSectionCount
___mingw_GetSectionCount proc near      ; CODE XREF: __pei386_runtime_relocator+23¡èp
                push    ebx
                xor     ebx, ebx
                cmp     word ptr ds:400000h, 5A4Dh
                jz      short loc_4024B2

loc_4024AE:                             ; CODE XREF: ___mingw_GetSectionCount+1E¡éj
                mov     eax, ebx
                pop     ebx
                retn
; ---------------------------------------------------------------------------

loc_4024B2:                             ; CODE XREF: ___mingw_GetSectionCount+C¡èj
                mov     eax, 400000h    ; pImageBase
                call    __ValidateImageBase_part_0
                test    eax, eax
                jz      short loc_4024AE
                mov     eax, ds:40003Ch
                movzx   ebx, word ptr [eax+400006h]
                mov     eax, ebx
                pop     ebx
                retn
___mingw_GetSectionCount endp


; =============== S U B R O U T I N E =======================================


; PIMAGE_SECTION_HEADER __cdecl _FindPESectionExec(size_t eNo)
                public __FindPESectionExec
__FindPESectionExec proc near

eNo             = dword ptr  4

pSection = edx                          ; PIMAGE_SECTION_HEADER
                push    esi
                xor     esi, esi
                cmp     word ptr ds:400000h, 5A4Dh
                push    ebx
                mov     ebx, [esp+8+eNo]
                jz      short loc_4024E8

loc_4024E3:                             ; CODE XREF: __FindPESectionExec+24¡éj
                                        ; __FindPESectionExec+42¡éj
                mov     eax, esi
                pop     ebx
                pop     esi
                retn
; ---------------------------------------------------------------------------

loc_4024E8:                             ; CODE XREF: __FindPESectionExec+11¡èj
eNo_0 = ebx                             ; size_t ; pImageBase
                mov     eax, 400000h
                call    __ValidateImageBase_part_0
                test    eax, eax
                jz      short loc_4024E3
                mov     eax, ds:40003Ch
                lea     ecx, [eax+400000h]
pNTHeader = ecx                         ; PIMAGE_NT_HEADERS
                movzx   eax, word ptr [eax+400014h]
                lea     pSection, [pNTHeader+eax+18h]
                movzx   pNTHeader, word ptr [pNTHeader+6]
                test    ecx, ecx
                jz      short loc_4024E3
                xor     eax, eax

loc_402516:                             ; CODE XREF: __FindPESectionExec+5B¡éj
iSection = eax                          ; unsigned int
                test    byte ptr [pSection+27h], 20h
                jz      short loc_402523
                test    eNo_0, eNo_0
                jz      short loc_402534
                sub     eNo_0, 1

loc_402523:                             ; CODE XREF: __FindPESectionExec+4A¡èj
                add     iSection, 1
                add     pSection, 28h ; '('
                cmp     iSection, ecx
                jb      short loc_402516
                xor     esi, esi
                mov     iSection, esi
                pop     eNo_0
                pop     esi
                retn
; ---------------------------------------------------------------------------

loc_402534:                             ; CODE XREF: __FindPESectionExec+4E¡èj
eNo_0 = ebx                             ; size_t
iSection = eax                          ; unsigned int
                mov     esi, pSection
                mov     iSection, esi
                pop     eNo_0
                pop     esi
                retn
__FindPESectionExec endp

; ---------------------------------------------------------------------------
                align 10h

; =============== S U B R O U T I N E =======================================


; PBYTE _GetPEImageBase()
                public __GetPEImageBase
__GetPEImageBase proc near              ; CODE XREF: ___write_memory_part_0+72¡èp
                cmp     word ptr ds:400000h, 5A4Dh
                jz      short loc_402550

loc_40254B:                             ; CODE XREF: __GetPEImageBase+1C¡éj
                xor     eax, eax
                retn
; ---------------------------------------------------------------------------
                align 10h

loc_402550:                             ; CODE XREF: __GetPEImageBase+9¡èj
                mov     eax, 400000h    ; pImageBase
                call    __ValidateImageBase_part_0
                test    eax, eax
                jz      short loc_40254B
                mov     eax, 400000h
                retn
__GetPEImageBase endp

; ---------------------------------------------------------------------------
                align 10h

; =============== S U B R O U T I N E =======================================


; WINBOOL __cdecl _IsNonwritableInCurrentImage(PBYTE pTarget)
                public __IsNonwritableInCurrentImage
__IsNonwritableInCurrentImage proc near

pImageBase      = dword ptr -8
rva             = dword ptr -4
pTarget         = dword ptr  4

                xor     eax, eax
                cmp     word ptr ds:400000h, 5A4Dh
                jz      short loc_402580
                retn
; ---------------------------------------------------------------------------
                align 10h

loc_402580:                             ; CODE XREF: __IsNonwritableInCurrentImage+B¡èj
                sub     esp, 8
                mov     eax, 400000h    ; pImageBase
                call    __ValidateImageBase_part_0
                test    eax, eax
                jz      short loc_4025B6
                mov     eax, [esp+8+pTarget]
                mov     [esp+8+pImageBase], 400000h ; pImageBase
                sub     eax, 400000h
rvaTarget = eax                         ; DWORD_PTR
                mov     [esp+8+rva], rvaTarget ; rva
                call    __FindPESection
pSection = eax                          ; PIMAGE_SECTION_HEADER
                test    pSection, pSection
                jz      short loc_4025C0
                mov     pSection, [pSection+24h]
                not     eax
                shr     eax, 1Fh

loc_4025B6:                             ; CODE XREF: __IsNonwritableInCurrentImage+1F¡èj
                                        ; __IsNonwritableInCurrentImage+52¡éj
                add     esp, 8
                retn
; ---------------------------------------------------------------------------
pSection = eax                          ; PIMAGE_SECTION_HEADER
                align 10h

loc_4025C0:                             ; CODE XREF: __IsNonwritableInCurrentImage+3C¡èj
                xor     pSection, pSection
                jmp     short loc_4025B6
__IsNonwritableInCurrentImage endp

; ---------------------------------------------------------------------------
                align 10h

; =============== S U B R O U T I N E =======================================


; const char *__cdecl __mingw_enum_import_library_names(int i)
                public ___mingw_enum_import_library_names
___mingw_enum_import_library_names proc near

pImageBase      = dword ptr -14h
rva             = dword ptr -10h
i               = dword ptr  4

                push    edi
                xor     edi, edi
                push    esi
                push    ebx
                sub     esp, 8
                cmp     word ptr ds:400000h, 5A4Dh
                mov     ebx, [esp+14h+i]
                jz      short loc_4025F0

loc_4025E7:                             ; CODE XREF: ___mingw_enum_import_library_names+2C¡éj
                                        ; ___mingw_enum_import_library_names+3B¡éj ...
                add     esp, 8
                mov     eax, edi
                pop     ebx
                pop     esi
                pop     edi
                retn
; ---------------------------------------------------------------------------

loc_4025F0:                             ; CODE XREF: ___mingw_enum_import_library_names+15¡èj
                mov     eax, 400000h    ; pImageBase
                call    __ValidateImageBase_part_0
                test    eax, eax
                jz      short loc_4025E7
                mov     eax, ds:40003Ch
                mov     esi, [eax+400080h]
importsStartRVA = esi                   ; DWORD
                test    importsStartRVA, importsStartRVA
                jz      short loc_4025E7
                mov     [esp+14h+rva], importsStartRVA ; rva
                mov     [esp+14h+pImageBase], 400000h ; pImageBase
                call    __FindPESection
pSection = eax                          ; PIMAGE_SECTION_HEADER
                test    pSection, pSection
                jz      short loc_4025E7
                add     importsStartRVA, 400000h
importDesc = esi                        ; PIMAGE_IMPORT_DESCRIPTOR
                mov     edx, importDesc
                jnz     short loc_402636
                jmp     short loc_4025E7
; ---------------------------------------------------------------------------
i_0 = ebx                               ; int
importDesc = edx                        ; PIMAGE_IMPORT_DESCRIPTOR
                align 10h

loc_402630:                             ; CODE XREF: ___mingw_enum_import_library_names+76¡éj
                sub     i_0, 1
                add     importDesc, 14h

loc_402636:                             ; CODE XREF: ___mingw_enum_import_library_names+59¡èj
                mov     ecx, [importDesc+4]
                test    ecx, ecx
                jnz     short loc_402644
                mov     eax, [importDesc+0Ch]
                test    eax, eax
                jz      short loc_402660

loc_402644:                             ; CODE XREF: ___mingw_enum_import_library_names+6B¡èj
                test    i_0, i_0
                jg      short loc_402630
                mov     edi, [importDesc+0Ch]
                add     esp, 8
                pop     i_0
                pop     esi
                add     edi, 400000h
                mov     eax, edi
                pop     edi
                retn
; ---------------------------------------------------------------------------
i_0 = ebx                               ; int
                align 10h

loc_402660:                             ; CODE XREF: ___mingw_enum_import_library_names+72¡èj
                add     esp, 8
                xor     edi, edi
                mov     eax, edi
                pop     i_0
                pop     esi
                pop     edi
                retn
___mingw_enum_import_library_names endp

; ---------------------------------------------------------------------------
                align 10h

; =============== S U B R O U T I N E =======================================


                public ___chkstk_ms
___chkstk_ms    proc near               ; CODE XREF: ___tmainCRTStartup+19¡èp
                                        ; __pei386_runtime_relocator+35¡èp

arg_0           = byte ptr  4

                push    ecx
                push    eax
                cmp     eax, 1000h
                lea     ecx, [esp+8+arg_0]
                jb      short loc_402692

loc_40267D:                             ; CODE XREF: ___chkstk_ms+20¡éj
                sub     ecx, 1000h
                or      dword ptr [ecx], 0
                sub     eax, 1000h
                cmp     eax, 1000h
                ja      short loc_40267D

loc_402692:                             ; CODE XREF: ___chkstk_ms+B¡èj
                sub     ecx, eax
                or      dword ptr [ecx], 0
                pop     eax
                pop     ecx
                retn
___chkstk_ms    endp

; ---------------------------------------------------------------------------
                align 4
; [00000006 BYTES: COLLAPSED FUNCTION ___set_app_type. PRESS CTRL-NUMPAD+ TO EXPAND]
                align 4
; [00000006 BYTES: COLLAPSED FUNCTION ___getmainargs. PRESS CTRL-NUMPAD+ TO EXPAND]
                align 10h

; =============== S U B R O U T I N E =======================================

; Attributes: static

; void (*mingw_get_invalid_parameter_handler())(const wchar_t *, const wchar_t *, const wchar_t *, unsigned int, uintptr_t)
_mingw_get_invalid_parameter_handler proc near
                                        ; DATA XREF: .data:__imp___get_invalid_parameter_handler¡éo
                mov     eax, ds:_handler
                retn
_mingw_get_invalid_parameter_handler endp

; ---------------------------------------------------------------------------
                align 10h

; =============== S U B R O U T I N E =======================================

; Attributes: static bp-based frame

; void (*__cdecl mingw_set_invalid_parameter_handler(void (*new_handler)(const wchar_t *, const wchar_t *, const wchar_t *, unsigned int, uintptr_t)))(const wchar_t *, const wchar_t *, const wchar_t *, unsigned int, uintptr_t)
_mingw_set_invalid_parameter_handler proc near
                                        ; DATA XREF: .data:__imp___set_invalid_parameter_handler¡éo

new_handler     = dword ptr  8

                push    ebp
                mov     ebp, esp
                sub     esp, 18h
                mov     eax, [ebp+new_handler]
                mov     dword ptr [esp], offset _handler ; Target
                mov     [esp+4], eax    ; Value
                call    ds:__imp__InterlockedExchange@8
                sub     esp, 8
                leave
                retn
_mingw_set_invalid_parameter_handler endp

; ---------------------------------------------------------------------------
                align 10h
; [00000006 BYTES: COLLAPSED FUNCTION _malloc. PRESS CTRL-NUMPAD+ TO EXPAND]
                align 4
; [00000006 BYTES: COLLAPSED FUNCTION _strlen. PRESS CTRL-NUMPAD+ TO EXPAND]
                align 10h
; [00000006 BYTES: COLLAPSED FUNCTION _memcpy. PRESS CTRL-NUMPAD+ TO EXPAND]
                align 4
; [00000006 BYTES: COLLAPSED FUNCTION __cexit. PRESS CTRL-NUMPAD+ TO EXPAND]
                align 10h
; [00000006 BYTES: COLLAPSED FUNCTION __amsg_exit. PRESS CTRL-NUMPAD+ TO EXPAND]
                align 4
; [00000006 BYTES: COLLAPSED FUNCTION __initterm. PRESS CTRL-NUMPAD+ TO EXPAND]
                align 10h
; [00000006 BYTES: COLLAPSED FUNCTION _exit. PRESS CTRL-NUMPAD+ TO EXPAND]
                align 4
; [00000006 BYTES: COLLAPSED FUNCTION __lock. PRESS CTRL-NUMPAD+ TO EXPAND]
                align 10h
; [00000006 BYTES: COLLAPSED FUNCTION ___dllonexit. PRESS CTRL-NUMPAD+ TO EXPAND]
                align 4
; [00000006 BYTES: COLLAPSED FUNCTION __unlock. PRESS CTRL-NUMPAD+ TO EXPAND]
                align 10h
; [00000006 BYTES: COLLAPSED FUNCTION _signal. PRESS CTRL-NUMPAD+ TO EXPAND]
                align 4
; [00000006 BYTES: COLLAPSED FUNCTION ___setusermatherr. PRESS CTRL-NUMPAD+ TO EXPAND]
                align 10h
; [00000006 BYTES: COLLAPSED FUNCTION _fprintf. PRESS CTRL-NUMPAD+ TO EXPAND]
                align 4
; [00000006 BYTES: COLLAPSED FUNCTION _fwrite. PRESS CTRL-NUMPAD+ TO EXPAND]
                align 10h
; [00000006 BYTES: COLLAPSED FUNCTION _vfprintf. PRESS CTRL-NUMPAD+ TO EXPAND]
                align 4
; [00000006 BYTES: COLLAPSED FUNCTION _abort. PRESS CTRL-NUMPAD+ TO EXPAND]
                align 10h
; [00000006 BYTES: COLLAPSED FUNCTION _calloc. PRESS CTRL-NUMPAD+ TO EXPAND]
                align 4
; [00000006 BYTES: COLLAPSED FUNCTION _free. PRESS CTRL-NUMPAD+ TO EXPAND]
                align 10h
; [00000006 BYTES: COLLAPSED FUNCTION _strncmp. PRESS CTRL-NUMPAD+ TO EXPAND]
                align 4
_text_20        db 66h, 90h
                align 10h
; [00000048 BYTES: COLLAPSED FUNCTION _main. PRESS CTRL-NUMPAD+ TO EXPAND]
                align 10h
                public ___CTOR_LIST__
; func_ptr __CTOR_LIST__[2]
___CTOR_LIST__  dd 0FFFFFFFFh, 0        ; DATA XREF: ___do_global_ctors+4¡èr
                                        ; ___do_global_ctors:loc_401F43¡èr ...
                public __DTOR_LIST__
; func_ptr _DTOR_LIST__[2]
__DTOR_LIST__   dd 0FFFFFFFFh, 0        ; DATA XREF: .data:_p_59264¡éo
                align 40h
                dd 200h dup(?)
_text           ends

; Section 2. (virtual address 00003000)
; Virtual size                  : 0000002C (     44.)
; Section size in file          : 00000200 (    512.)
; Offset to raw data for section: 00001C00
; Flags C0300040: Data Readable Writable
; Alignment     : 4 bytes
; ===========================================================================

; Segment type: Pure data
; Segment permissions: Read/Write
_data           segment dword public 'DATA' use32
                assume cs:_data
                ;org 403000h
                public ___mingw_winmain_nShowCmd
; DWORD __mingw_winmain_nShowCmd
___mingw_winmain_nShowCmd dd 0Ah        ; DATA XREF: ___tmainCRTStartup+1B3¡èw
                                        ; _main+16¡èr
                public __charmax
; int _charmax
__charmax       dd 0FFh
                public ___native_vcclrit_reason
; volatile unsigned int __native_vcclrit_reason
___native_vcclrit_reason dd 0FFFFFFFFh
                public ___native_dllmain_reason
; volatile unsigned int __native_dllmain_reason
___native_dllmain_reason dd 0FFFFFFFFh
; Function-local static variable
; func_ptr *p_59264
_p_59264        dd offset __DTOR_LIST__+4
                                        ; DATA XREF: ___do_global_dtors¡èr
                                        ; ___do_global_dtors+12¡èr ...
                public __CRT_MT
; int _CRT_MT
__CRT_MT        dd 2                    ; DATA XREF: ___dyn_tls_init@12+4¡èr
                                        ; ___dyn_tls_init@12+11¡èw
                public __MINGW_INSTALL_DEBUG_MATHERR
; int _MINGW_INSTALL_DEBUG_MATHERR
__MINGW_INSTALL_DEBUG_MATHERR dd 0FFFFFFFFh
                                        ; DATA XREF: _pre_c_init+7A¡èr
                public __imp___get_invalid_parameter_handler
; void (*(*__get_invalid_parameter_handler)(void))(const wchar_t *, const wchar_t *, const wchar_t *, unsigned int, uintptr_t)
__imp___get_invalid_parameter_handler dd offset _mingw_get_invalid_parameter_handler
                public __imp___set_invalid_parameter_handler
; void (*(*__set_invalid_parameter_handler)(void (*)(const wchar_t *, const wchar_t *, const wchar_t *, unsigned int, uintptr_t)))(const wchar_t *, const wchar_t *, const wchar_t *, unsigned int, uintptr_t)
__imp___set_invalid_parameter_handler dd offset _mingw_set_invalid_parameter_handler
                                        ; CODE XREF: ___tmainCRTStartup+138¡èp
; Function-local static variable
                public ___security_cookie
; UINT_PTR __security_cookie
___security_cookie dd 0BB40E64Eh        ; DATA XREF: ___security_init_cookie+9¡èr
                                        ; ___security_init_cookie:loc_40202C¡èw ...
                public ___security_cookie_complement
; UINT_PTR __security_cookie_complement
___security_cookie_complement dd 44BF19B1h
                                        ; DATA XREF: ___security_init_cookie+25¡èw
                                        ; ___security_init_cookie+92¡èw ...
                public __data_end__
__data_end__    db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db 0F2h
                db  22h ; "
                db  7Fh ; 
                db  4Fh ; O
                db  26h ; &
                db  26h ; &
                db 0A3h
                db  5Dh ; ]
                db  5Ch ; \
                db  0Ah
                db 0ABh
                db  5Eh ; ^
                db 0A0h
                db  43h ; C
                db  33h ; 3
                db  43h ; C
                db  42h ; B
                db  2Ch ; ,
                db  58h ; X
                db  30h ; 0
                db  44h ; D
                db  10h
                db 0A2h
                db 0ECh
                db 0BCh
                db  1Ah
                db 0AFh
                db 0DDh
                db  96h
                db 0DEh
                db  61h ; a
                db  41h ; A
                db 0C0h
                db 0A1h
                db  20h
                db  9Dh
                db  4Fh ; O
                db 0B2h
                db 0B0h
                db 0DFh
                db  48h ; H
                db 0F5h
                db 0E9h
                db 0C5h
                db  88h
                db  44h ; D
                db 0CDh
                db 0AFh
                db 0F9h
                db  51h ; Q
                db 0CAh
                db  2Ch ; ,
                db 0AAh
                db  16h
                db  8Eh
                db  82h
                db  2Eh ; .
                db  6Ah ; j
                db 0C8h
                db 0A3h
                db 0FCh
                db  7Ah ; z
                db 0FAh
                db 0F5h
                db  19h
                db 0DAh
                db 0D6h
                db 0D6h
                db  25h ; %
                db    2
                db 0D6h
                db  67h ; g
                db  75h ; u
                db  22h ; "
                db 0ABh
                db 0DAh
                db    3
                db 0D5h
                db 0CCh
                db    6
                db 0ADh
                db 0F3h
                db  61h ; a
                db 0BBh
                db  5Bh ; [
                db 0EAh
                db  77h ; w
                db  3Bh ; ;
                db 0F4h
                db 0B0h
                db  89h
                db 0BBh
                db 0C2h
                db  3Ah ; :
                db 0D4h
                db  37h ; 7
                db 0E2h
                db 0C4h
                db 0A1h
                db  96h
                db  16h
                db 0D3h
                db  9Ch
                db 0BDh
                db  0Eh
                db  52h ; R
                db  9Ch
                db  8Ah
                db 0E1h
                db  3Ah ; :
                db 0BCh
                db  12h
                db  1Bh
                db  2Ch ; ,
                db  79h ; y
                db  4Dh ; M
                db  81h
                db  9Bh
                db 0ECh
                db  3Eh ; >
                db  79h ; y
                db  38h ; 8
                db 0D8h
                db 0CDh
                db  86h
                db  77h ; w
                db 0E0h
                db  96h
                db  39h ; 9
                db  9Bh
                db  89h
                db 0E4h
                db  89h
                db  0Fh
                db  1Fh
                db  13h
                db 0ADh
                db  48h ; H
                db  3Ah ; :
                db  20h
                db  1Fh
                db 0CAh
                db 0C0h
                db  80h
                db  92h
                db  9Fh
                db  9Ch
                db  9Dh
                db 0C3h
                db  1Ah
                db  42h ; B
                db 0DEh
                db  69h ; i
                db  4Bh ; K
                db    1
                db  1Fh
                db  3Eh ; >
                db  29h ; )
                db  2Dh ; -
                db  62h ; b
                db  7Dh ; }
                db 0A0h
                db  7Eh ; ~
                db 0B1h
                db 0EEh
                db  92h
                db  9Bh
                db  6Ch ; l
                db 0F7h
                db 0BCh
                db  36h ; 6
                db  85h
                db 0B6h
                db  41h ; A
                db  2Eh ; .
                db  47h ; G
                db 0B3h
                db 0CDh
                db  97h
                db 0B3h
                db  8Eh
                db  82h
                db 0CAh
                db  94h
                db 0A6h
                db  5Eh ; ^
                db 0D4h
                db 0C3h
                db    0
                db  0Fh
                db  82h
                db  8Ah
                db 0DFh
                db  8Dh
                db  7Ah ; z
                db  11h
                db  3Dh ; =
                db 0DFh
                db 0C3h
                db  47h ; G
                db  1Bh
                db 0EEh
                db    8
                db 0A9h
                db  5Ch ; \
                db  8Dh
                db  7Fh ; 
                db 0D2h
                db  0Eh
                db 0C5h
                db    2
                db 0EFh
                db  3Fh ; ?
                db  85h
                db  85h
                db  23h ; #
                db  1Ah
                db 0E4h
                db  78h ; x
                db  3Eh ; >
                db    1
                db  96h
                db  30h ; 0
                db  15h
                db  47h ; G
                db  83h
                db 0F1h
                db  20h
                db 0B3h
                db 0D7h
                db  75h ; u
                db  4Eh ; N
                db 0C8h
                db  47h ; G
                db  3Ch ; <
                db 0A2h
                db 0BAh
                db  96h
                db  3Fh ; ?
                db 0F7h
                db  31h ; 1
                db 0E1h
                db 0CCh
                db  31h ; 1
                db  10h
                db  1Ch
                db 0DDh
                db    9
                db 0B6h
                db  39h ; 9
                db 0EFh
                db  6Fh ; o
                db  1Ch
                db 0DFh
                db 0C8h
                db  3Dh ; =
                db 0CBh
                db    9
                db 0A9h
                db  67h ; g
                db  96h
                db  28h ; (
                db 0E8h
                db 0A7h
                db  92h
                db  72h ; r
                db  6Eh ; n
                db  86h
                db  83h
                db  7Bh ; {
                db    6
                db  91h
                db  39h ; 9
                db  21h ; !
                db  39h ; 9
                db 0F9h
                db 0C4h
                db 0B3h
                db  65h ; e
                db 0A2h
                db 0A6h
                db 0DEh
                db  5Eh ; ^
                db 0CBh
                db    3
                db  93h
                db  75h ; u
                db  48h ; H
                db 0C7h
                db  86h
                db  9Fh
                db 0FFh
                db  3Dh ; =
                db  13h
                db  83h
                db    7
                db  6Eh ; n
                db    8
                db 0E8h
                db 0F5h
                db 0B6h
                db 0C4h
                db 0C0h
                db  28h ; (
                db  0Dh
                db  41h ; A
                db 0E5h
                db  80h
                db  16h
                db 0ECh
                db  36h ; 6
                db    0
                db 0A1h
                db 0ECh
                db  6Bh ; k
                db 0C6h
                db  2Dh ; -
                db 0D6h
                db 0B8h
                db  38h ; 8
                db 0FFh
                db  77h ; w
                db  0Dh
                db  97h
                db  43h ; C
                db 0A6h
                db 0DBh
                db  76h ; v
                db  83h
                db  82h
                db 0FDh
                db  34h ; 4
                db 0A2h
                db  69h ; i
                db  9Fh
                db  2Eh ; .
                db 0F0h
                db  25h ; %
                db  8Bh
                db  35h ; 5
                db  0Eh
                db  41h ; A
                db 0AAh
                db 0CBh
                db  34h ; 4
                db  60h ; `
                db  3Ch ; <
                db  30h ; 0
                db  49h ; I
                db 0C4h
                db  12h
                db  58h ; X
                db  2Ch ; ,
                db  83h
                db  96h
                db  7Ch ; |
                db  41h ; A
                db  5Ah ; Z
                db  7Dh ; }
                db  6Ch ; l
                db  26h ; &
                db  87h
                db 0D5h
                db 0ECh
                db 0D5h
                db 0CEh
                db 0F3h
                db 0F7h
                db  81h
                db  1Eh
                db  5Fh ; _
                db  51h ; Q
                db  52h ; R
                db  82h
                db 0BAh
                db 0D7h
                db  87h
                db 0D3h
                db 0DDh
                db  5Ah ; Z
                db 0D3h
                db 0A6h
                db  93h
                db  8Ch
                db  1Dh
                db  37h ; 7
                db 0C9h
                db  6Eh ; n
                db  95h
                db 0C2h
                db    5
                db  57h ; W
                db 0A1h
                db  1Ah
                db    9
                db  8Eh
                db 0FCh
                db  81h
                db 0ADh
                db 0E4h
                db  7Fh ; 
                db  16h
                db  59h ; Y
                db 0A9h
                db  26h ; &
                db  95h
                db  82h
                db  1Eh
                db  0Bh
                db 0D8h
                db 0EDh
                db  2Eh ; .
                db  2Eh ; .
                db 0A5h
                db  40h ; @
                db  63h ; c
                db 0FDh
                db  23h ; #
                db  1Eh
                db  1Fh
                db  25h ; %
                db  59h ; Y
                db  7Ah ; z
                db 0CCh
                db 0C2h
                db  84h
                db  56h ; V
                db  7Ah ; z
                db 0C5h
                db  69h ; i
                db    4
                db 0E4h
                db    1
                db  43h ; C
                db  49h ; I
                db  7Dh ; }
                db  17h
                db 0E6h
                db 0ACh
                db  85h
                db  87h
                db  3Bh ; ;
                db 0B6h
                db 0A5h
                db  76h ; v
                db    4
                db  0Ah
                db 0BEh
                db  3Eh ; >
                db  0Ch
                db  31h ; 1
                db  44h ; D
                db  48h ; H
                db  12h
                db  5Dh ; ]
                db  2Ch ; ,
                db  62h ; b
                db  8Eh
                db 0BFh
                db  29h ; )
                db  8Fh
                db  25h ; %
                db  0Ah
                db  2Fh ; /
                db 0F0h
                db  34h ; 4
                db 0AFh
                db 0FBh
                db 0B8h
                db  76h ; v
                db 0FEh
                db  27h ; '
                db  75h ; u
                db 0D2h
                db  9Fh
                db  21h ; !
                db  60h ; `
                db  66h ; f
                db 0A6h
                db  96h
                db 0E8h
                db 0B0h
                db  9Fh
                db  2Ch ; ,
                db 0EAh
                db 0FDh
                db 0D6h
                db 0A2h
                db  46h ; F
                db  84h
                db  3Bh ; ;
                db    0
                db 0D1h
                db  43h ; C
                db 0A4h
                db  7Dh ; }
                db  6Ah ; j
                db 0A5h
                db 0DCh
                db  89h
                db 0F2h
                db  8Fh
                db    4
                db    0
                db 0A7h
                db  11h
                db  8Ah
                db 0F6h
                db 0DDh
                db  37h ; 7
                db  24h ; $
                db 0FDh
                db  5Eh ; ^
                db 0D3h
                db 0A6h
                db  12h
                db  40h ; @
                db 0A8h
                db  70h ; p
                db  1Eh
                db  2Bh ; +
                db  78h ; x
                db  87h
                db  8Eh
                db 0B0h
                db  94h
                db  5Eh ; ^
                db  6Ch ; l
                db  21h ; !
                db 0F5h
                db  7Fh ; 
                db  17h
                db  67h ; g
                db 0DFh
                db  9Eh
                db 0B0h
                db 0CFh
                db  9Bh
                db  41h ; A
                db 0EBh
                db 0C3h
                db  59h ; Y
                db  5Bh ; [
                db 0CDh
                db 0EDh
                db  20h
                db 0FEh
                db 0F6h
                db 0ECh
                db  14h
                db 0A4h
                db  79h ; y
                db 0D4h
                db  33h ; 3
                db 0CFh
                db 0EDh
                db 0A6h
                db  8Ch
                db 0E8h
                db  0Eh
                db  0Ah
                db  7Ch ; |
                db  13h
                db  2Ch ; ,
                db 0B1h
                db  89h
                db  3Dh ; =
                db  9Dh
                db  12h
                db 0D8h
                db  23h ; #
                db 0C3h
                db  62h ; b
                db  9Ch
                db 0FBh
                db 0F7h
                db 0CFh
                db 0CAh
                db 0D8h
                db 0BDh
                db  8Dh
                db 0A2h
                db 0C7h
                db  33h ; 3
                db 0A2h
                db 0FFh
                db  40h ; @
                db 0C0h
                db 0B1h
                db 0DEh
                db  60h ; `
                db  59h ; Y
                db  4Ah ; J
                db  66h ; f
                db  42h ; B
                db  4Fh ; O
                db 0A3h
                db 0B1h
                db 0A7h
                db  59h ; Y
                db 0DBh
                db  15h
                db  4Eh ; N
                db    0
                db 0D5h
                db  77h ; w
                db  62h ; b
                db 0BCh
                db 0D8h
                db 0CFh
                db    1
                db 0FAh
                db    0
                db 0CDh
                db 0ABh
                db  39h ; 9
                db  4Ah ; J
                db  55h ; U
                db 0FBh
                db 0AEh
                db  52h ; R
                db 0C3h
                db  45h ; E
                db  59h ; Y
                db 0D2h
                db  6Fh ; o
                db 0ECh
                db  17h
                db  7Ah ; z
                db 0B0h
                db  77h ; w
                db 0E2h
                db  9Ah
                db  67h ; g
                db  88h
                db  6Bh ; k
                db  7Eh ; ~
                db  38h ; 8
                db  87h
                db    3
                db  78h ; x
                db 0DAh
                db 0EDh
                db  71h ; q
                db 0A1h
                db 0FAh
                db  18h
                db  5Ch ; \
                db  34h ; 4
                db  62h ; b
                db  21h ; !
                db  7Dh ; }
                db  20h
                db 0C7h
                db  47h ; G
                db  4Fh ; O
                db 0B6h
                db 0D6h
                db  40h ; @
                db  47h ; G
                db  48h ; H
                db 0C4h
                db  42h ; B
                db  49h ; I
                db 0CFh
                db 0E4h
                db  39h ; 9
                db 0E5h
                db  33h ; 3
                db 0E1h
                db    1
                db  71h ; q
                db    1
                db  64h ; d
                db 0D8h
                db  22h ; "
                db  34h ; 4
                db  15h
                db  1Bh
                db  15h
                db  8Bh
                db 0B7h
                db 0C2h
                db 0EEh
                db  63h ; c
                db 0A0h
                db  65h ; e
                db  9Ah
                db  1Ch
                db  3Dh ; =
                db 0AAh
                db  57h ; W
                db  8Ch
                db 0D2h
                db  96h
                db 0CCh
                db 0A8h
                db  71h ; q
                db  90h
                db 0EEh
                db 0D9h
                db 0F2h
                db 0A9h
                db 0EDh
                db  9Ch
                db  8Bh
                db 0DEh
                db 0DBh
                db  32h ; 2
                db  60h ; `
                db 0C6h
                db  88h
                db  67h ; g
                db 0DEh
                db 0C9h
                db  32h ; 2
                db 0A8h
                db  5Eh ; ^
                db 0D3h
                db 0B3h
                db 0C1h
                db  51h ; Q
                db    3
                db  6Bh ; k
                db  45h ; E
                db 0A1h
                db 0ACh
                db 0C8h
                db  8Eh
                db 0C6h
                db 0B5h
                db 0F0h
                db  96h
                db  46h ; F
                db  3Eh ; >
                db  5Ah ; Z
                db 0C4h
                db 0CAh
                db  8Dh
                db  63h ; c
                db 0C0h
                db 0B8h
                db  5Ah ; Z
                db  58h ; X
                db 0FFh
                db    7
                db  8Bh
                db  41h ; A
                db    1
                db  64h ; d
                db 0A3h
                db 0FFh
                db 0FCh
                db 0B7h
                db 0D1h
                db 0DEh
                db 0EBh
                db  20h
                db 0C1h
                db 0C5h
                db  20h
                db  23h ; #
                db 0E0h
                db  22h ; "
                db  0Ah
                db  24h ; $
                db 0FAh
                db 0D7h
                db 0C3h
                db  1Dh
                db  78h ; x
                db 0F6h
                db 0A6h
                db  87h
                db 0C6h
                db 0CCh
                db 0A3h
                db  15h
                db  79h ; y
                db  8Ah
                db 0B8h
                db  15h
                db  16h
                db 0F5h
                db  47h ; G
                db  30h ; 0
                db  26h ; &
                db  10h
                db 0F8h
                db 0A0h
                db    0
                db 0EAh
                db 0B0h
                db  68h ; h
                db 0BBh
                db  60h ; `
                db  63h ; c
                db  46h ; F
                db    1
                db  1Fh
                db  70h ; p
                db  69h ; i
                db  76h ; v
                db 0F3h
                db  1Eh
                db  46h ; F
                db  24h ; $
                db 0D5h
                db  0Fh
                db  27h ; '
                db 0B3h
                db 0F8h
                db  58h ; X
                db 0A0h
                db 0E3h
                db  48h ; H
                db  82h
                db    7
                db 0A5h
                db  93h
                db 0A5h
                db 0BFh
                db  70h ; p
                db  0Dh
                db 0DDh
                db  3Dh ; =
                db  4Eh ; N
                db  15h
                db  75h ; u
                db 0B1h
                db 0DAh
                db  22h ; "
                db 0F1h
                db  98h
                db 0FDh
                db  1Ah
                db 0B7h
                db    3
                db  20h
                db  26h ; &
                db 0A3h
                db  79h ; y
                db  82h
                db  66h ; f
                db  41h ; A
                db  6Eh ; n
                db 0BCh
                db 0CBh
                db  42h ; B
                db  64h ; d
                db  81h
                db  21h ; !
                db  38h ; 8
                db  83h
                db  38h ; 8
                db  6Eh ; n
                db  47h ; G
                db 0E5h
                db    2
                db  79h ; y
                db  9Eh
                db 0B7h
                db  87h
                db 0AFh
                db 0B1h
                db 0CFh
                db 0F1h
                db  0Ah
                db  53h ; S
                db  57h ; W
                db  8Fh
                db  34h ; 4
                db  82h
                db  56h ; V
                db  69h ; i
                db  82h
                db  6Ch ; l
                db  84h
                db 0E1h
                db  7Dh ; }
                db  28h ; (
                db  60h ; `
                db  95h
                db  20h
                db  2Bh ; +
                db  2Fh ; /
                db 0DCh
                db  5Dh ; ]
                db 0EAh
                db  84h
                db  3Ch ; <
                db 0BAh
                db 0BFh
                db 0CFh
                db  2Bh ; +
                db 0ACh
                db 0A8h
                db  5Fh ; _
                db 0C3h
                db    0
                db  7Bh ; {
                db 0A4h
                db  4Ch ; L
                db  4Bh ; K
                db  98h
                db 0C0h
                db 0DAh
                db  0Ah
                db  4Dh ; M
                db  96h
                db  1Ah
                db 0D8h
                db  98h
                db 0BCh
                db  72h ; r
                db 0C8h
                db  51h ; Q
                db  41h ; A
                db  5Bh ; [
                db 0FCh
                db  3Ch ; <
                db  41h ; A
                db  4Dh ; M
                db 0F7h
                db  6Bh ; k
                db  41h ; A
                db  2Fh ; /
                db  75h ; u
                db  65h ; e
                db  9Ah
                db  2Ch ; ,
                db 0B6h
                db  8Ah
                db  90h
                db  9Eh
                db 0E6h
                db 0FAh
                db  35h ; 5
                db  8Dh
                db  6Ch ; l
                db  7Ch ; |
                db 0D6h
                db 0B4h
                db    8
                db  3Eh ; >
                db  3Dh ; =
                db  2Fh ; /
                db 0CFh
                db  89h
                db  24h ; $
                db  1Fh
                db  35h ; 5
                db 0DAh
                db  81h
                db 0D0h
                db  7Fh ; 
                db  7Fh ; 
                db  9Dh
                db  5Ah ; Z
                db  7Ch ; |
                db  2Fh ; /
                db 0C2h
                db  0Fh
                db  89h
                db 0F2h
                db  11h
                db  93h
                db 0FBh
                db  9Bh
                db 0ACh
                db 0A8h
                db  24h ; $
                db 0B3h
                db 0CFh
                db 0FEh
                db  8Eh
                db 0BAh
                db 0ECh
                db  82h
                db  4Fh ; O
                db 0E5h
                db 0F9h
                db  7Dh ; }
                db 0A8h
                db  59h ; Y
                db 0F5h
                db  19h
                db    9
                db  5Dh ; ]
                db  16h
                db 0FAh
                db  7Ch ; |
                db 0A2h
                db  34h ; 4
                db  79h ; y
                db  28h ; (
                db  8Fh
                db 0B8h
                db  1Eh
                db  76h ; v
                db  5Bh ; [
                db 0AAh
                db  1Bh
                db  7Ch ; |
                db  24h ; $
                db  0Eh
                db  98h
                db  30h ; 0
                db 0ABh
                db  78h ; x
                db 0A6h
                db  4Fh ; O
                db 0BBh
                db 0ACh
                db 0B7h
                db  1Dh
                db  84h
                db  24h ; $
                db  84h
                db 0ACh
                db  9Fh
                db  69h ; i
                db 0AFh
                db 0DCh
                db  1Eh
                db  39h ; 9
                db  7Ch ; |
                db  81h
                db  68h ; h
                db 0CAh
                db 0F3h
                db  72h ; r
                db 0AAh
                db 0E2h
                db 0A3h
                db 0D0h
                db 0C5h
                db  2Ah ; *
                db  18h
                db  15h
                db  0Eh
                db  2Bh ; +
                db 0C0h
                db  68h ; h
                db 0F2h
                db  4Bh ; K
                db  14h
                db  37h ; 7
                db 0D2h
                db 0EAh
                db 0FDh
                db  94h
                db 0D7h
                db  3Ah ; :
                db    9
                db  95h
                db 0EEh
                db 0FAh
                db  30h ; 0
                db 0C2h
                db 0CBh
                db 0E2h
                db  9Eh
                db 0D2h
                db  43h ; C
                db  30h ; 0
                db 0BBh
                db  1Ah
                db 0F9h
                db 0D7h
                db  82h
                db  32h ; 2
                db    3
                db  36h ; 6
                db  57h ; W
                db 0E0h
                db  91h
                db    2
                db 0C8h
                db  51h ; Q
                db  96h
                db  76h ; v
                db 0B8h
                db  35h ; 5
                db  3Bh ; ;
                db  92h
                db 0EDh
                db  98h
                db  93h
                db  82h
                db  96h
                db 0F9h
                db 0D1h
                db 0DCh
                db  19h
                db  43h ; C
                db 0DCh
                db  5Ch ; \
                db 0C6h
                db  0Eh
                db  2Fh ; /
                db 0C5h
                db    0
                db  1Ah
                db  39h ; 9
                db  95h
                db  1Ah
                db 0D0h
                db  1Ah
                db 0FBh
                db  38h ; 8
                db  21h ; !
                db  5Bh ; [
                db  6Dh ; m
                db 0ABh
                db  0Eh
                db  8Ch
                db    2
                db  62h ; b
                db  47h ; G
                db 0A6h
                db 0DCh
                db  21h ; !
                db    6
                db  60h ; `
                db 0B7h
                db  30h ; 0
                db 0CFh
                db  0Dh
                db  63h ; c
                db  16h
                db  9Fh
                db 0F8h
                db  30h ; 0
                db 0C0h
                db 0A2h
                db 0B5h
                db  89h
                db  9Bh
                db  0Eh
                db  64h ; d
                db 0ACh
                db  24h ; $
                db 0E6h
                db  76h ; v
                db  28h ; (
                db  6Ah ; j
                db  2Eh ; .
                db 0AEh
                db  3Fh ; ?
                db  54h ; T
                db  51h ; Q
                db  21h ; !
                db 0DBh
                db  39h ; 9
                db  12h
                db  1Ah
                db  38h ; 8
                db 0EFh
                db  8Eh
                db  38h ; 8
                db 0CBh
                db  15h
                db  62h ; b
                db 0A4h
                db 0A1h
                db  8Ch
                db  38h ; 8
                db 0E5h
                db 0F0h
                db  3Dh ; =
                db  1Fh
                db 0E3h
                db 0DEh
                db 0ADh
                db 0A3h
                db  88h
                db 0DBh
                db  11h
                db  47h ; G
                db 0BCh
                db 0CBh
                db  4Eh ; N
                db  86h
                db 0A5h
                db 0A0h
                db  78h ; x
                db  13h
                db 0D1h
                db    7
                db  3Fh ; ?
                db  46h ; F
                db  9Dh
                db    7
                db  10h
                db 0A9h
                db  1Eh
                db  9Fh
                db 0B6h
                db  4Eh ; N
                db  3Eh ; >
                db  6Ah ; j
                db  39h ; 9
                db 0FBh
                db 0D9h
                db  40h ; @
                db  62h ; b
                db  66h ; f
                db  4Fh ; O
                db  26h ; &
                db 0FEh
                db  19h
                db 0F3h
                db  7Fh ; 
                db  76h ; v
                db  1Ah
                db  9Dh
                db  4Bh ; K
                db  7Ah ; z
                db  45h ; E
                db 0BCh
                db  1Eh
                db  3Ch ; <
                db  42h ; B
                db  66h ; f
                db  36h ; 6
                db 0EFh
                db  3Eh ; >
                db 0D5h
                db  72h ; r
                db 0C7h
                db  9Bh
                db    7
                db 0E8h
                db  43h ; C
                db    3
                db  41h ; A
                db  9Bh
                db 0D4h
                db 0CAh
                db  55h ; U
                db  8Bh
                db    8
                db  14h
                db  45h ; E
                db 0CBh
                db  6Eh ; n
                db  84h
                db  0Dh
                db  41h ; A
                db 0ACh
                db    0
                db  0Dh
                db  12h
                db  0Ch
                db  6Dh ; m
                db  42h ; B
                db 0ADh
                db 0AAh
                db  39h ; 9
                db  56h ; V
                db    8
                db  2Ch ; ,
                db 0B5h
                db 0A5h
                db  4Ch ; L
                db  87h
                db 0F7h
                db  5Bh ; [
                db 0B9h
                db 0A1h
                db 0EBh
                db 0F8h
                db    5
                db  89h
                db 0D7h
                db  2Dh ; -
                db  47h ; G
                db  5Bh ; [
                db  7Eh ; ~
                db  2Fh ; /
                db  81h
                db 0C7h
                db    3
                db    8
                db 0CEh
                db  28h ; (
                db  4Fh ; O
                db  55h ; U
                db  7Dh ; }
                db 0EAh
                db 0A5h
                db  41h ; A
                db  8Dh
                db  78h ; x
                db  45h ; E
                db  5Ch ; \
                db  25h ; %
                db  48h ; H
                db  22h ; "
                db  37h ; 7
                db 0D0h
                db  56h ; V
                db  2Ch ; ,
                db  59h ; Y
                db  42h ; B
                db 0C5h
                db  2Fh ; /
                db  80h
                db 0DDh
                db  5Eh ; ^
                db 0F3h
                db  89h
                db  57h ; W
                db  25h ; %
                db  91h
                db 0BCh
                db  28h ; (
                db  85h
                db 0F9h
                db  12h
                db  6Bh ; k
                db  48h ; H
                db  43h ; C
                db  2Dh ; -
                db  7Dh ; }
                db  8Fh
                db  7Ch ; |
                db  71h ; q
                db 0A9h
                db  66h ; f
                db  97h
                db 0D6h
                db  7Bh ; {
                db  39h ; 9
                db  1Eh
                db 0BBh
                db  82h
                db  67h ; g
                db 0C6h
                db  84h
                db 0EEh
                db  6Ch ; l
                db 0F5h
                db  51h ; Q
                db  34h ; 4
                db  6Bh ; k
                db 0E5h
                db  63h ; c
                db 0DCh
                db 0BDh
                db 0CDh
                db  4Dh ; M
                db  78h ; x
                db  41h ; A
                db  0Ah
                db  63h ; c
                db  95h
                db  86h
                db  30h ; 0
                db 0C1h
                db 0C9h
                db  92h
                db  65h ; e
                db 0F9h
                db 0CFh
                db 0E8h
                db  3Ah ; :
                db 0F3h
                db  25h ; %
                db  4Ah ; J
                db  66h ; f
                db 0E3h
                db  20h
                db  82h
                db    4
                db    7
                db  3Eh ; >
                db 0BBh
                db  1Fh
                db  5Ch ; \
                db 0E5h
                db  60h ; `
                db 0F6h
                db  17h
                db  7Ch ; |
                db  73h ; s
                db  12h
                db  14h
                db  57h ; W
                db 0A7h
                db 0F0h
                db  2Bh ; +
                db 0DDh
                db 0D9h
                db 0D2h
                db 0A7h
                db 0A6h
                db  36h ; 6
                db  43h ; C
                db  22h ; "
                db  23h ; #
                db 0B8h
                db 0DFh
                db 0B7h
                db 0B7h
                db  63h ; c
                db 0D5h
                db 0EAh
                db 0ACh
                db 0E3h
                db 0BEh
                db  83h
                db 0A5h
                db  7Eh ; ~
                db  18h
                db  10h
                db    2
                db  79h ; y
                db  59h ; Y
                db  68h ; h
                db 0FBh
                db  64h ; d
                db  3Fh ; ?
                db 0BBh
                db  23h ; #
                db  26h ; &
                db 0C8h
                db  9Dh
                db  3Ah ; :
                db  72h ; r
                db 0B9h
                db  0Bh
                db  94h
                db 0B4h
                db  30h ; 0
                db 0FFh
                db 0E4h
                db 0B4h
                db  24h ; $
                db  2Fh ; /
                db 0F4h
                db  16h
                db 0E5h
                db 0B5h
                db  89h
                db  24h ; $
                db 0BBh
                db 0F5h
                db 0ECh
                db  62h ; b
                db 0E1h
                db  8Dh
                db  91h
                db 0ACh
                db  49h ; I
                db  52h ; R
                db  5Fh ; _
                db 0FCh
                db 0F2h
                db  21h ; !
                db 0B7h
                db  5Fh ; _
                db 0BAh
                db  6Eh ; n
                db  5Bh ; [
                db  76h ; v
                db 0D4h
                db 0FDh
                db  7Fh ; 
                db 0D9h
                db 0D4h
                db  38h ; 8
                db 0D4h
                db  51h ; Q
                db  80h
                db  3Fh ; ?
                db 0D1h
                db  97h
                db  3Ah ; :
                db  3Fh ; ?
                db  48h ; H
                db  8Ch
                db 0E9h
                db 0BBh
                db  84h
                db 0F3h
                db  25h ; %
                db  6Ch ; l
                db 0FFh
                db  34h ; 4
                db  5Dh ; ]
                db  7Ah ; z
                db  2Fh ; /
                db 0F8h
                db    0
                db  7Dh ; }
                db  9Ch
                db 0D2h
                db 0CFh
                db  7Ch ; |
                db 0FAh
                db  7Ch ; |
                db  6Bh ; k
                db 0C2h
                db  1Dh
                db  1Bh
                db  54h ; T
                db 0E0h
                db  25h ; %
                db  43h ; C
                db 0E0h
                db 0B3h
                db 0B2h
                db  55h ; U
                db 0BBh
                db  86h
                db 0B9h
                db  16h
                db 0E2h
                db 0C5h
                db 0D7h
                db  84h
                db 0CAh
                db 0F6h
                db  5Ch ; \
                db 0A9h
                db  23h ; #
                db  2Fh ; /
                db 0A9h
                db  71h ; q
                db  92h
                db  76h ; v
                db 0B5h
                db  72h ; r
                db 0B1h
                db  41h ; A
                db  55h ; U
                db  43h ; C
                db 0F2h
                db  0Bh
                db 0BAh
                db  69h ; i
                db 0A6h
                db 0E2h
                db 0EAh
                db 0CFh
                db  28h ; (
                db 0DAh
                db    7
                db 0E2h
                db 0B2h
                db 0DBh
                db  54h ; T
                db  3Ch ; <
                db  64h ; d
                db  79h ; y
                db  44h ; D
                db  78h ; x
                db 0D3h
                db  58h ; X
                db 0B4h
                db 0E4h
                db  26h ; &
                db  15h
                db    8
                db  2Ch ; ,
                db 0A6h
                db  9Dh
                db 0FAh
                db  61h ; a
                db  6Ch ; l
                db  94h
                db  19h
                db  89h
                db  3Ch ; <
                db  3Bh ; ;
                db 0BAh
                db  59h ; Y
                db  82h
                db  95h
                db  89h
                db  6Ah ; j
                db 0A3h
                db 0A5h
                db  44h ; D
                db 0DBh
                db  71h ; q
                db  4Dh ; M
                db  3Eh ; >
                db 0C6h
                db  43h ; C
                db  6Eh ; n
                db  8Fh
                db 0DFh
                db  4Ch ; L
                db 0EDh
                db  3Bh ; ;
                db  13h
                db 0B1h
                db 0B3h
                db 0FBh
                db 0A6h
                db  8Ch
                db 0D7h
                db  82h
                db 0C3h
                db  0Eh
                db  5Fh ; _
                db  93h
                db 0D6h
                db  80h
                db 0DBh
                db  1Eh
                db 0F7h
                db  31h ; 1
                db  70h ; p
                db  74h ; t
                db  99h
                db  0Dh
                db    5
                db 0AAh
                db  56h ; V
                db  90h
                db  5Bh ; [
                db    2
                db  23h ; #
                db 0A0h
                db  53h ; S
                db  7Fh ; 
                db 0E0h
                db 0AAh
                db 0DBh
                db 0FCh
                db  80h
                db 0E5h
                db 0C1h
                db  61h ; a
                db  19h
                db 0ABh
                db 0F4h
                db  33h ; 3
                db 0EEh
                db 0D5h
                db 0D2h
                db 0DEh
                db  7Dh ; }
                db 0F6h
                db  83h
                db  1Fh
                db  2Fh ; /
                db  2Ah ; *
                db  85h
                db 0D6h
                db 0EDh
                db  0Ch
                db  1Ch
                db  0Bh
                db 0ACh
                db  3Ch ; <
                db 0CBh
                db  94h
                db  73h ; s
                db 0E4h
                db    3
                db  30h ; 0
                db  9Ch
                db 0AFh
                db  9Fh
                db 0A8h
                db  8Bh
                db 0EEh
                db  63h ; c
                db  21h ; !
                db 0B6h
                db  0Fh
                db 0BAh
                db  3Dh ; =
                db  3Eh ; >
                db  3Eh ; >
                db 0FEh
                db  72h ; r
                db  34h ; 4
                db  6Ch ; l
                db  83h
                db  58h ; X
                db  95h
                db  7Ah ; z
                db 0D6h
                db  9Ah
                db  75h ; u
                db  50h ; P
                db 0BEh
                db  96h
                db    8
                db  1Dh
                db  96h
                db  2Bh ; +
                db  5Ah ; Z
                db    4
                db  88h
                db  62h ; b
                db 0BEh
                db 0FBh
                db  9Ch
                db  5Eh ; ^
                db  55h ; U
                db  5Bh ; [
                db 0BBh
                db    3
                db  5Dh ; ]
                db    6
                db    9
                db  75h ; u
                db  56h ; V
                db  1Eh
                db 0FDh
                db  3Dh ; =
                db  99h
                db  6Ch ; l
                db  36h ; 6
                db  0Dh
                db 0F6h
                db 0CAh
                db  26h ; &
                db  93h
                db  56h ; V
                db  81h
                db  23h ; #
                db  45h ; E
                db 0ACh
                db  0Dh
                db 0F8h
                db 0DBh
                db 0C1h
                db  85h
                db 0E6h
                db 0F2h
                db 0E3h
                db 0F4h
                db  46h ; F
                db  3Dh ; =
                db  3Eh ; >
                db 0A9h
                db 0D0h
                db  88h
                db  96h
                db 0CAh
                db  68h ; h
                db 0ADh
                db  7Dh ; }
                db  5Fh ; _
                db  48h ; H
                db  8Dh
                db  75h ; u
                db  65h ; e
                db 0DFh
                db    2
                db    0
                db  4Bh ; K
                db  4Eh ; N
                db  77h ; w
                db  5Fh ; _
                db  3Ch ; <
                db  3Ah ; :
                db  73h ; s
                db  66h ; f
                db 0A5h
                db  53h ; S
                db  7Fh ; 
                db 0CBh
                db 0FFh
                db  60h ; `
                db    0
                db  2Bh ; +
                db 0A8h
                db    1
                db 0BAh
                db 0F7h
                db 0F9h
                db  9Eh
                db 0D2h
                db 0E9h
                db  6Bh ; k
                db  4Eh ; N
                db  91h
                db  58h ; X
                db 0EAh
                db  74h ; t
                db  1Eh
                db 0EDh
                db 0FBh
                db  0Bh
                db 0F3h
                db  4Dh ; M
                db  16h
                db 0C4h
                db 0CEh
                db  3Eh ; >
                db  26h ; &
                db 0B4h
                db  43h ; C
                db 0FCh
                db 0E9h
                db  16h
                db  7Bh ; {
                db  8Fh
                db  9Ch
                db  94h
                db 0C6h
                db  7Bh ; {
                db 0FCh
                db  3Ah ; :
                db 0E4h
                db  7Eh ; ~
                db  3Ah ; :
                db  36h ; 6
                db  53h ; S
                db  0Eh
                db    3
                db  66h ; f
                db 0D7h
                db  75h ; u
                db 0A7h
                db  55h ; U
                db 0FAh
                db  2Fh ; /
                db  10h
                db  7Fh ; 
                db  15h
                db  66h ; f
                db 0BCh
                db 0AFh
                db  4Ah ; J
                db  68h ; h
                db  10h
                db  26h ; &
                db 0D6h
                db  5Ch ; \
                db  32h ; 2
                db  31h ; 1
                db 0E6h
                db 0D9h
                db 0C1h
                db  97h
                db  9Dh
                db 0DEh
                db  0Dh
                db  6Bh ; k
                db  58h ; X
                db  4Fh ; O
                db  7Fh ; 
                db 0E3h
                db 0CBh
                db  0Eh
                db 0F9h
                db  99h
                db  1Fh
                db  0Eh
                db  8Ah
                db 0B8h
                db  33h ; 3
                db  6Ch ; l
                db  8Ah
                db 0CEh
                db 0BDh
                db 0CDh
                db 0EDh
                db 0F0h
                db  5Dh ; ]
                db  9Fh
                db  77h ; w
                db  42h ; B
                db  9Bh
                db 0C1h
                db  10h
                db  26h ; &
                db  3Eh ; >
                db 0C7h
                db 0A1h
                db  9Dh
                db  34h ; 4
                db  28h ; (
                db 0EEh
                db  67h ; g
                db 0B9h
                db  6Dh ; m
                db 0F2h
                db  50h ; P
                db  31h ; 1
                db 0D4h
                db  1Dh
                db  8Bh
                db  16h
                db  10h
                db  7Dh ; }
                db    3
                db 0A9h
                db  7Fh ; 
                db  35h ; 5
                db  15h
                db    2
                db 0C0h
                db  8Eh
                db 0D3h
                db  75h ; u
                db  6Ch ; l
                db  1Dh
                db  59h ; Y
                db  49h ; I
                db 0FAh
                db 0F2h
                db  55h ; U
                db 0C0h
                db  0Eh
                db  88h
                db 0F9h
                db  76h ; v
                db 0AAh
                db 0CFh
                db  41h ; A
                db  6Bh ; k
                db 0A5h
                db 0A4h
                db  2Dh ; -
                db  39h ; 9
                db 0EAh
                db  8Eh
                db  8Eh
                db  86h
                db  86h
                db  61h ; a
                db 0A2h
                db  29h ; )
                db 0BDh
                db 0BDh
                db  17h
                db 0F4h
                db  93h
                db  52h ; R
                db  5Fh ; _
                db 0D4h
                db  42h ; B
                db  30h ; 0
                db 0FDh
                db 0E3h
                db  73h ; s
                db 0B6h
                db 0FEh
                db 0CEh
                db 0E6h
                db 0BAh
                db 0E6h
                db  94h
                db  52h ; R
                db  0Ah
                db  3Ch ; <
                db  0Bh
                db  96h
                db  1Dh
                db  46h ; F
                db 0CCh
                db  69h ; i
                db 0E3h
                db 0B3h
                db 0D3h
                db 0A5h
                db 0DCh
                db  65h ; e
                db  20h
                db  90h
                db  42h ; B
                db  46h ; F
                db 0CFh
                db  96h
                db  75h ; u
                db  41h ; A
                db 0D8h
                db 0BEh
                db 0FBh
                db  9Fh
                db 0ECh
                db  79h ; y
                db  76h ; v
                db  0Ah
                db 0F6h
                db 0F8h
                db 0B4h
                db  0Bh
                db  0Eh
                db  90h
                db  46h ; F
                db  0Fh
                db 0BAh
                db 0E4h
                db  0Fh
                db  13h
                db  51h ; Q
                db  24h ; $
                db 0F3h
                db  74h ; t
                db  29h ; )
                db  91h
                db    8
                db 0ADh
                db  77h ; w
                db  62h ; b
                db 0D2h
                db  0Bh
                db 0F6h
                db  70h ; p
                db  11h
                db  69h ; i
                db  2Eh ; .
                db  9Bh
                db  4Ch ; L
                db  81h
                db  67h ; g
                db  61h ; a
                db 0CCh
                db  8Ch
                db 0D4h
                db 0C8h
                db 0DAh
                db  12h
                db  3Fh ; ?
                db 0D7h
                db    1
                db  47h ; G
                db  3Fh ; ?
                db  60h ; `
                db 0AAh
                db  13h
                db  93h
                db  5Bh ; [
                db  0Eh
                db  1Dh
                db 0FBh
                db  3Eh ; >
                db    7
                db 0CEh
                db  84h
                db  45h ; E
                db 0C9h
                db  6Dh ; m
                db 0ABh
                db 0C8h
                db 0AAh
                db  1Fh
                db  9Eh
                db  36h ; 6
                db 0D6h
                db  50h ; P
                db 0E2h
                db 0A8h
                db  0Eh
                db 0CFh
                db 0FAh
                db    3
                db  7Eh ; ~
                db 0C7h
                db  5Ah ; Z
                db  9Eh
                db  5Ch ; \
                db  5Dh ; ]
                db  9Eh
                db 0EFh
                db 0DBh
                db  1Ah
                db    7
                db  91h
                db  8Ah
                db 0CEh
                db  71h ; q
                db  8Eh
                db  24h ; $
                db  38h ; 8
                db  0Fh
                db  75h ; u
                db 0C2h
                db 0E3h
                db 0C6h
                db  75h ; u
                db 0E9h
                db  7Bh ; {
                db 0E2h
                db 0B5h
                db 0E5h
                db  0Bh
                db  77h ; w
                db  74h ; t
                db  5Ah ; Z
                db 0EDh
                db  1Ch
                db  14h
                db  24h ; $
                db    7
                db 0DDh
                db 0FDh
                db 0BAh
                db 0BBh
                db  43h ; C
                db  70h ; p
                db  98h
                db  97h
                db  6Ah ; j
                db  79h ; y
                db  3Fh ; ?
                db 0DDh
                db 0DDh
                db  4Bh ; K
                db 0ABh
                db  82h
                db  42h ; B
                db  21h ; !
                db 0F0h
                db 0ACh
                db  11h
                db    3
                db  25h ; %
                db  28h ; (
                db  29h ; )
                db 0E2h
                db  23h ; #
                db    7
                db 0A6h
                db  95h
                db  40h ; @
                db  9Bh
                db  6Bh ; k
                db 0C3h
                db 0FBh
                db 0C9h
                db 0C7h
                db  60h ; `
                db 0DDh
                db  38h ; 8
                db    8
                db 0EAh
                db 0B4h
                db 0EAh
                db  29h ; )
                db  75h ; u
                db  86h
                db 0A7h
                db  21h ; !
                db  9Fh
                db 0C7h
                db 0C1h
                db  26h ; &
                db  53h ; S
                db 0A6h
                db 0BEh
                db 0D2h
                db 0DAh
                db    0
                db 0D2h
                db  22h ; "
                db  32h ; 2
                db  43h ; C
                db  7Ch ; |
                db  51h ; Q
                db  9Dh
                db  1Dh
                db 0F4h
                db 0A4h
                db  24h ; $
                db  55h ; U
                db  22h ; "
                db  14h
                db 0ABh
                db 0CEh
                db  14h
                db  2Dh ; -
                db 0F8h
                db  84h
                db 0A8h
                db  50h ; P
                db  0Eh
                db 0B2h
                db 0D4h
                db    3
                db  47h ; G
                db  53h ; S
                db  2Eh ; .
                db  25h ; %
                db 0D5h
                db  18h
                db  2Ah ; *
                db 0F6h
                db  2Dh ; -
                db  11h
                db  5Dh ; ]
                db  0Ch
                db  26h ; &
                db  90h
                db 0C5h
                db  26h ; &
                db  92h
                db  5Ch ; \
                db  9Fh
                db 0D6h
                db 0AAh
                db 0F6h
                db 0B2h
                db  6Ch ; l
                db  87h
                db  76h ; v
                db  18h
                db  94h
                db  83h
                db  3Ch ; <
                db 0B3h
                db 0C2h
                db  7Eh ; ~
                db 0ADh
                db 0F6h
                db  47h ; G
                db  2Eh ; .
                db 0C9h
                db  64h ; d
                db  68h ; h
                db 0F3h
                db  55h ; U
                db 0F7h
                db 0DEh
                db 0E4h
                db  50h ; P
                db 0D2h
                db 0D9h
                db  2Ch ; ,
                db 0A2h
                db  13h
                db  0Dh
                db 0A3h
                db 0BCh
                db  0Fh
                db 0E0h
                db  86h
                db 0AAh
                db  8Eh
                db 0B0h
                db  99h
                db  79h ; y
                db  49h ; I
                db  97h
                db  9Ah
                db  63h ; c
                db  7Ah ; z
                db 0ADh
                db  72h ; r
                db  4Bh ; K
                db 0F1h
                db  28h ; (
                db 0EAh
                db 0E4h
                db 0D0h
                db  4Eh ; N
                db  92h
                db  0Fh
                db  7Eh ; ~
                db  0Eh
                db 0F9h
                db 0EDh
                db  5Ah ; Z
                db 0EAh
                db  90h
                db 0F8h
                db  66h ; f
                db    2
                db  15h
                db  10h
                db  64h ; d
                db  56h ; V
                db  9Eh
                db  54h ; T
                db  77h ; w
                db  74h ; t
                db 0FBh
                db 0C3h
                db  49h ; I
                db  17h
                db  1Eh
                db  15h
                db  31h ; 1
                db 0E0h
                db 0DCh
                db  3Fh ; ?
                db    8
                db 0BBh
                db  80h
                db  77h ; w
                db 0F6h
                db  1Ch
                db  51h ; Q
                db    9
                db 0F5h
                db  95h
                db 0A4h
                db  66h ; f
                db  4Ah ; J
                db 0C2h
                db  8Ah
                db 0BDh
                db  58h ; X
                db  44h ; D
                db  49h ; I
                db 0B5h
                db  6Fh ; o
                db  61h ; a
                db 0CEh
                db  2Dh ; -
                db  0Ch
                db  64h ; d
                db  36h ; 6
                db  54h ; T
                db  3Ch ; <
                db 0B8h
                db  22h ; "
                db  4Ch ; L
                db  2Eh ; .
                db  5Dh ; ]
                db 0FCh
                db  54h ; T
                db  83h
                db 0B6h
                db 0BFh
                db  11h
                db  38h ; 8
                db  1Bh
                db 0C4h
                db  2Ah ; *
                db  20h
                db  66h ; f
                db  56h ; V
                db 0F7h
                db 0DCh
                db 0DBh
                db 0A7h
                db  86h
                db  8Eh
                db 0C7h
                db 0E6h
                db  1Eh
                db 0ECh
                db 0ECh
                db 0D0h
                db 0EFh
                db  61h ; a
                db  35h ; 5
                db 0B9h
                db  39h ; 9
                db 0ADh
                db 0E7h
                db  46h ; F
                db 0FBh
                db  4Bh ; K
                db  44h ; D
                db  9Dh
                db  15h
                db 0C3h
                db 0FFh
                db  52h ; R
                db 0FAh
                db 0B2h
                db  13h
                db  6Eh ; n
                db    0
                db 0AEh
                db  88h
                db    3
                db  66h ; f
                db  6Bh ; k
                db  98h
                db 0BCh
                db  46h ; F
                db 0D9h
                db 0E2h
                db 0E9h
                db  7Ch ; |
                db  35h ; 5
                db  26h ; &
                db 0A1h
                db  2Ah ; *
                db 0B3h
                db  21h ; !
                db  46h ; F
                db 0CDh
                db  92h
                db 0D7h
                db  5Eh ; ^
                db  34h ; 4
                db 0B9h
                db  6Fh ; o
                db  65h ; e
                db  1Dh
                db  34h ; 4
                db  2Dh ; -
                db  8Fh
                db 0AFh
                db  3Fh ; ?
                db  30h ; 0
                db  5Ah ; Z
                db 0CEh
                db 0AFh
                db 0B1h
                db  48h ; H
                db  39h ; 9
                db  22h ; "
                db 0C6h
                db  0Eh
                db  63h ; c
                db  2Ah ; *
                db    7
                db  46h ; F
                db  0Bh
                db  2Ch ; ,
                db  37h ; 7
                db 0F9h
                db  3Fh ; ?
                db  9Ch
                db 0A1h
                db 0B6h
                db  2Fh ; /
                db 0F5h
                db 0B2h
                db 0C4h
                db  4Eh ; N
                db  3Eh ; >
                db  60h ; `
                db  49h ; I
                db 0E1h
                db  57h ; W
                db  5Dh ; ]
                db  1Ah
                db 0E2h
                db  1Fh
                db  51h ; Q
                db  23h ; #
                db  0Bh
                db  56h ; V
                db 0C1h
                db  23h ; #
                db 0D5h
                db 0AFh
                db  19h
                db 0B6h
                db  1Eh
                db  66h ; f
                db    3
                db  50h ; P
                db 0F5h
                db  68h ; h
                db  85h
                db 0D5h
                db  17h
                db 0C8h
                db  4Dh ; M
                db  28h ; (
                db 0B3h
                db  0Bh
                db  2Eh ; .
                db 0ACh
                db    8
                db  48h ; H
                db 0DFh
                db 0FBh
                db  5Ah ; Z
                db 0F3h
                db  4Bh ; K
                db 0F9h
                db  45h ; E
                db  70h ; p
                db  24h ; $
                db 0E1h
                db  35h ; 5
                db 0CBh
                db 0FCh
                db 0A6h
                db 0AFh
                db  39h ; 9
                db  20h
                db 0B6h
                db 0BAh
                db  85h
                db  78h ; x
                db  38h ; 8
                db 0EFh
                db  34h ; 4
                db 0BEh
                db  79h ; y
                db 0BAh
                db 0F6h
                db  43h ; C
                db  58h ; X
                db  55h ; U
                db  1Dh
                db 0EBh
                db 0AFh
                db 0D6h
                db 0C2h
                db 0EBh
                db 0DAh
                db 0ADh
                db 0C8h
                db  4Dh ; M
                db  35h ; 5
                db  79h ; y
                db  89h
                db  60h ; `
                db 0F6h
                db 0FEh
                db  6Ah ; j
                db 0B0h
                db  67h ; g
                db 0C0h
                db 0F5h
                db  51h ; Q
                db  93h
                db  8Bh
                db  74h ; t
                db  24h ; $
                db  65h ; e
                db 0ACh
                db  32h ; 2
                db 0BCh
                db 0C4h
                db 0D9h
                db 0F2h
                db  4Eh ; N
                db 0E6h
                db    4
                db 0FDh
                db  40h ; @
                db 0B9h
                db  6Eh ; n
                db  66h ; f
                db 0BEh
                db 0FDh
                db 0B2h
                db  9Fh
                db 0B3h
                db  64h ; d
                db  45h ; E
                db  1Ah
                db  2Dh ; -
                db  20h
                db  56h ; V
                db  75h ; u
                db 0CAh
                db  68h ; h
                db  41h ; A
                db  88h
                db 0FAh
                db 0FEh
                db  36h ; 6
                db 0EFh
                db  43h ; C
                db 0CFh
                db 0CBh
                db  6Eh ; n
                db  6Ch ; l
                db 0BDh
                db 0FAh
                db 0BCh
                db  8Ah
                db  5Fh ; _
                db 0DCh
                db 0B4h
                db  65h ; e
                db  4Ch ; L
                db 0C3h
                db  61h ; a
                db  0Eh
                db  3Dh ; =
                db 0B4h
                db    2
                db  9Eh
                db  33h ; 3
                db 0D0h
                db 0E2h
                db  2Ch ; ,
                db  8Bh
                db 0B4h
                db  28h ; (
                db  63h ; c
                db  6Fh ; o
                db  45h ; E
                db  10h
                db  9Dh
                db  78h ; x
                db  67h ; g
                db 0EFh
                db  8Eh
                db 0A5h
                db  24h ; $
                db  61h ; a
                db 0F8h
                db 0E2h
                db  9Fh
                db 0A2h
                db  4Dh ; M
                db 0EBh
                db  66h ; f
                db  13h
                db  55h ; U
                db  24h ; $
                db 0AAh
                db  0Ch
                db  59h ; Y
                db  23h ; #
                db    5
                db 0FEh
                db  21h ; !
                db  4Dh ; M
                db  1Eh
                db 0FDh
                db  1Dh
                db  3Eh ; >
                db  1Ah
                db 0EBh
                db 0D0h
                db 0C1h
                db  0Dh
                db 0B6h
                db  13h
                db 0B1h
                db  47h ; G
                db  80h
                db 0A7h
                db  62h ; b
                db  96h
                db  28h ; (
                db  33h ; 3
                db  66h ; f
                db  1Fh
                db 0B7h
                db  0Ah
                db    5
                db  0Eh
                db 0ECh
                db  4Bh ; K
                db  95h
                db  34h ; 4
                db 0FFh
                db  3Fh ; ?
                db 0D0h
                db  84h
                db  91h
                db  0Dh
                db 0C5h
                db 0DFh
                db  8Eh
                db 0F0h
                db 0DDh
                db  90h
                db  81h
                db  2Ah ; *
                db  32h ; 2
                db  1Bh
                db  0Ch
                db  0Fh
                db  9Ch
                db  66h ; f
                db 0CEh
                db  61h ; a
                db  2Ch ; ,
                db  99h
                db  12h
                db 0C7h
                db 0FDh
                db 0EAh
                db  3Eh ; >
                db  32h ; 2
                db 0E7h
                db  59h ; Y
                db 0D6h
                db 0DDh
                db 0FCh
                db 0F4h
                db  28h ; (
                db 0DAh
                db  93h
                db    9
                db  9Fh
                db  7Bh ; {
                db  14h
                db  53h ; S
                db  42h ; B
                db  76h ; v
                db  3Ah ; :
                db  54h ; T
                db  25h ; %
                db    7
                db  2Ch ; ,
                db 0A1h
                db 0B5h
                db  77h ; w
                db  65h ; e
                db 0F7h
                db  20h
                db 0E6h
                db  74h ; t
                db  9Ah
                db  77h ; w
                db  89h
                db 0AAh
                db  8Bh
                db 0EDh
                db  2Ah ; *
                db 0D5h
                db  96h
                db 0C4h
                db 0D5h
                db  3Fh ; ?
                db  59h ; Y
                db 0A1h
                db  26h ; &
                db  11h
                db    4
                db  89h
                db  96h
                db  6Dh ; m
                db 0C1h
                db 0D0h
                db 0F0h
                db  23h ; #
                db  20h
                db 0DAh
                db  17h
                db  63h ; c
                db  7Eh ; ~
                db 0C3h
                db 0CEh
                db    3
                db  71h ; q
                db 0C4h
                db 0A1h
                db  80h
                db  24h ; $
                db    7
                db  6Eh ; n
                db  21h ; !
                db  78h ; x
                db 0CDh
                db  5Ah ; Z
                db 0D4h
                db 0C7h
                db  5Dh ; ]
                db 0F7h
                db  4Ah ; J
                db  7Dh ; }
                db  45h ; E
                db 0E8h
                db  0Ch
                db  0Ch
                db  53h ; S
                db  5Fh ; _
                db 0CEh
                db  4Fh ; O
                db 0D8h
                db    5
                db  53h ; S
                db  55h ; U
                db 0A8h
                db  1Dh
                db  32h ; 2
                db 0E0h
                db  31h ; 1
                db  9Dh
                db  4Dh ; M
                db  2Bh ; +
                db  6Ch ; l
                db 0A9h
                db 0ACh
                db  54h ; T
                db 0C6h
                db  26h ; &
                db 0A8h
                db  90h
                db 0C7h
                db 0DEh
                db  30h ; 0
                db 0E7h
                db  94h
                db 0E8h
                db 0DEh
                db  0Dh
                db 0F8h
                db 0D7h
                db  2Dh ; -
                db 0F7h
                db 0A0h
                db  8Eh
                db  88h
                db  74h ; t
                db  36h ; 6
                db  8Ch
                db  92h
                db  20h
                db  0Eh
                db  15h
                db  91h
                db 0FEh
                db 0FAh
                db 0C4h
                db 0DEh
                db  80h
                db 0B2h
                db  2Ch ; ,
                db 0E2h
                db  48h ; H
                db  4Ch ; L
                db 0D6h
                db 0F1h
                db  2Eh ; .
                db  44h ; D
                db  8Ch
                db  71h ; q
                db  4Dh ; M
                db 0E0h
                db  54h ; T
                db 0DCh
                db  5Bh ; [
                db 0CFh
                db  3Dh ; =
                db  4Fh ; O
                db  3Fh ; ?
                db  7Fh ; 
                db 0BFh
                db 0E0h
                db 0B4h
                db  25h ; %
                db 0D6h
                db  97h
                db 0F8h
                db  8Eh
                db 0FAh
                db 0A6h
                db 0E7h
                db 0E3h
                db  1Ch
                db 0A1h
                db 0DCh
                db  89h
                db  67h ; g
                db 0BCh
                db 0D2h
                db 0C2h
                db  54h ; T
                db 0FFh
                db  8Ch
                db 0C7h
                db 0BDh
                db  3Bh ; ;
                db 0F1h
                db  21h ; !
                db 0C0h
                db  29h ; )
                db 0FEh
                db 0D8h
                db    3
                db 0F3h
                db  34h ; 4
                db  67h ; g
                db  9Ah
                db 0C0h
                db 0E3h
                db  59h ; Y
                db  6Bh ; k
                db  40h ; @
                db  8Eh
                db  63h ; c
                db  87h
                db  9Ah
                db  69h ; i
                db  66h ; f
                db  25h ; %
                db  84h
                db  81h
                db  0Eh
                db  0Bh
                db  93h
                db  3Ch ; <
                db  2Fh ; /
                db  20h
                db 0AEh
                db  40h ; @
                db  6Bh ; k
                db 0AEh
                db 0D1h
                db 0FFh
                db  43h ; C
                db  7Ah ; z
                db 0F5h
                db 0C2h
                db  6Ch ; l
                db  35h ; 5
                db  10h
                db  65h ; e
                db  9Bh
                db  29h ; )
                db  13h
                db  33h ; 3
                db  48h ; H
                db 0C6h
                db  4Ah ; J
                db  9Dh
                db 0FEh
                db 0E7h
                db  2Fh ; /
                db  80h
                db  93h
                db  79h ; y
                db 0BDh
                db 0ADh
                db  44h ; D
                db  83h
                db  5Ch ; \
                db  33h ; 3
                db  41h ; A
                db  8Dh
                db 0CCh
                db  3Ah ; :
                db  0Eh
                db  38h ; 8
                db 0DBh
                db  13h
                db 0B9h
                db 0FAh
                db  3Dh ; =
                db 0BDh
                db 0C8h
                db 0FEh
                db 0C4h
                db 0C2h
                db 0A3h
                db 0D3h
                db  1Dh
                db 0C9h
                db 0C8h
                db  6Eh ; n
                db  5Bh ; [
                db  99h
                db    3
                db 0CAh
                db 0B3h
                db 0B9h
                db  26h ; &
                db    7
                db 0D3h
                db 0DFh
                db 0B0h
                db  74h ; t
                db  44h ; D
                db 0FEh
                db 0DAh
                db  46h ; F
                db 0DBh
                db 0E4h
                db  4Bh ; K
                db  36h ; 6
                db  95h
                db  1Bh
                db    8
                db  25h ; %
                db 0E3h
                db  23h ; #
                db 0DFh
                db 0D9h
                db 0D6h
                db  2Ch ; ,
                db 0D8h
                db 0D2h
                db 0A5h
                db  0Ch
                db 0EAh
                db  3Ch ; <
                db  2Ch ; ,
                db  96h
                db 0E2h
                db  9Bh
                db 0B0h
                db  25h ; %
                db  5Fh ; _
                db  45h ; E
                db  41h ; A
                db 0D4h
                db 0B9h
                db 0CBh
                db 0C6h
                db  33h ; 3
                db  4Fh ; O
                db  7Fh ; 
                db  53h ; S
                db    9
                db  31h ; 1
                db    3
                db 0FDh
                db  35h ; 5
                db  78h ; x
                db 0CAh
                db 0BAh
                db  66h ; f
                db  64h ; d
                db 0C7h
                db  53h ; S
                db  5Bh ; [
                db  98h
                db  26h ; &
                db  4Bh ; K
                db 0CCh
                db 0B5h
                db  4Dh ; M
                db  90h
                db  2Bh ; +
                db  5Eh ; ^
                db  3Fh ; ?
                db  30h ; 0
                db  58h ; X
                db  83h
                db 0D0h
                db 0DDh
                db  22h ; "
                db 0BFh
                db 0B8h
                db 0FDh
                db 0B0h
                db  96h
                db  0Bh
                db 0C4h
                db  73h ; s
                db 0A9h
                db  74h ; t
                db  86h
                db 0D5h
                db  41h ; A
                db  87h
                db 0DAh
                db 0D4h
                db  46h ; F
                db  57h ; W
                db 0D2h
                db 0D3h
                db  6Ch ; l
                db  37h ; 7
                db  95h
                db  6Bh ; k
                db  38h ; 8
                db  95h
                db  40h ; @
                db    9
                db  92h
                db  5Eh ; ^
                db  82h
                db 0C0h
                db  33h ; 3
                db 0E0h
                db  51h ; Q
                db  59h ; Y
                db  30h ; 0
                db 0C9h
                db  45h ; E
                db 0CDh
                db  78h ; x
                db  57h ; W
                db 0F5h
                db 0B5h
                db  80h
                db  93h
                db  7Dh ; }
                db 0DAh
                db  7Ch ; |
                db  61h ; a
                db  6Ah ; j
                db  8Ah
                db  80h
                db  31h ; 1
                db  65h ; e
                db  4Eh ; N
                db  25h ; %
                db  66h ; f
                db  25h ; %
                db 0F6h
                db  3Dh ; =
                db 0FAh
                db  29h ; )
                db  51h ; Q
                db 0F8h
                db 0F5h
                db  3Eh ; >
                db  59h ; Y
                db 0F5h
                db 0F7h
                db 0B7h
                db    1
                db 0ADh
                db  23h ; #
                db 0ADh
                db 0A2h
                db  75h ; u
                db 0AAh
                db 0A2h
                db  75h ; u
                db  36h ; 6
                db  81h
                db  9Fh
                db  64h ; d
                db 0C7h
                db  9Bh
                db  67h ; g
                db 0B0h
                db  89h
                db 0DDh
                db 0D5h
                db 0EBh
                db  99h
                db  68h ; h
                db  2Ah ; *
                db  8Bh
                db 0B3h
                db  57h ; W
                db  97h
                db  4Ch ; L
                db  0Ah
                db 0E0h
                db  4Fh ; O
                db 0F9h
                db  0Eh
                db 0C5h
                db    0
                db  4Eh ; N
                db  54h ; T
                db  34h ; 4
                db  9Ah
                db 0C1h
                db 0D9h
                db  5Eh ; ^
                db 0DAh
                db 0B8h
                db  44h ; D
                db  0Ch
                db  4Bh ; K
                db  82h
                db  7Bh ; {
                db 0D6h
                db    0
                db 0F5h
                db  0Fh
                db 0BEh
                db  93h
                db 0DEh
                db    1
                db 0F2h
                db  33h ; 3
                db 0B9h
                db 0F5h
                db 0A3h
                db 0CBh
                db 0EEh
                db  6Ah ; j
                db 0BEh
                db 0A0h
                db  80h
                db 0D5h
                db  91h
                db  6Eh ; n
                db    7
                db  37h ; 7
                db  5Dh ; ]
                db 0A6h
                db  99h
                db  94h
                db  29h ; )
                db 0BAh
                db 0D7h
                db  2Fh ; /
                db 0EFh
                db  75h ; u
                db  2Bh ; +
                db 0E2h
                db 0CAh
                db  72h ; r
                db  5Dh ; ]
                db 0F3h
                db 0F1h
                db 0B4h
                db 0E8h
                db 0F8h
                db  13h
                db  57h ; W
                db  2Bh ; +
                db  66h ; f
                db 0B9h
                db 0EFh
                db  85h
                db  7Bh ; {
                db  0Dh
                db 0ACh
                db    4
                db 0E4h
                db  43h ; C
                db 0FFh
                db  56h ; V
                db 0ECh
                db 0FDh
                db 0E5h
                db 0F7h
                db 0C4h
                db  0Ch
                db  56h ; V
                db  95h
                db  8Ah
                db 0F0h
                db 0CEh
                db  1Ch
                db  7Ch ; |
                db 0B1h
                db  93h
                db  8Ah
                db  89h
                db 0E9h
                db  98h
                db 0EBh
                db  7Eh ; ~
                db  29h ; )
                db 0D5h
                db 0C6h
                db 0DAh
                db 0C2h
                db  26h ; &
                db 0DEh
                db  26h ; &
                db 0AAh
                db  1Eh
                db  61h ; a
                db  77h ; w
                db    1
                db  33h ; 3
                db 0F3h
                db  61h ; a
                db 0CFh
                db  6Dh ; m
                db 0E4h
                db  78h ; x
                db    4
                db    0
                db  3Bh ; ;
                db 0F3h
                db 0F5h
                db  7Eh ; ~
                db 0D4h
                db 0D6h
                db  84h
                db  2Fh ; /
                db  26h ; &
                db    6
                db  39h ; 9
                db  42h ; B
                db  75h ; u
                db  8Dh
                db  88h
                db    3
                db  11h
                db 0E8h
                db 0B1h
                db 0E9h
                db 0BFh
                db  4Fh ; O
                db  21h ; !
                db  8Dh
                db 0A1h
                db 0A8h
                db 0CFh
                db  39h ; 9
                db  5Ch ; \
                db 0ACh
                db  4Eh ; N
                db 0ABh
                db  0Ah
                db 0A9h
                db 0C9h
                db 0D3h
                db  7Ch ; |
                db  22h ; "
                db 0FFh
                db    2
                db  49h ; I
                db 0F2h
                db 0E0h
                db  58h ; X
                db 0CEh
                db  75h ; u
                db  92h
                db  0Fh
                db 0FAh
                db  21h ; !
                db  97h
                db 0C0h
                db 0C2h
                db  9Dh
                db  57h ; W
                db  79h ; y
                db  63h ; c
                db  9Ah
                db  19h
                db 0F6h
                db  6Bh ; k
                db  63h ; c
                db    0
                db  67h ; g
                db  2Ch ; ,
                db 0D4h
                db  15h
                db 0FBh
                db 0E6h
                db 0A8h
                db  43h ; C
                db  8Ch
                db 0C3h
                db 0B3h
                db  73h ; s
                db  82h
                db 0DCh
                db  20h
                db    4
                db  19h
                db  14h
                db  9Ah
                db  5Eh ; ^
                db 0EAh
                db  6Eh ; n
                db 0AFh
                db  61h ; a
                db 0F5h
                db  48h ; H
                db  39h ; 9
                db 0E2h
                db 0E7h
                db 0BFh
                db  82h
                db 0BEh
                db    5
                db  2Ch ; ,
                db 0F9h
                db  1Bh
                db  8Bh
                db  0Dh
                db 0E4h
                db    7
                db  24h ; $
                db  71h ; q
                db 0B0h
                db  8Eh
                db  1Ah
                db 0FCh
                db  66h ; f
                db  87h
                db  3Ah ; :
                db  55h ; U
                db  42h ; B
                db  35h ; 5
                db  7Dh ; }
                db  5Fh ; _
                db  93h
                db  62h ; b
                db 0E3h
                db 0FBh
                db  3Bh ; ;
                db 0F4h
                db 0E9h
                db    0
                db  8Bh
                db 0BEh
                db 0DEh
                db  46h ; F
                db 0DDh
                db  34h ; 4
                db  0Ch
                db  8Bh
                db  5Dh ; ]
                db  3Ah ; :
                db  25h ; %
                db 0ACh
                db 0C1h
                db  4Fh ; O
                db 0E6h
                db  67h ; g
                db  59h ; Y
                db 0E9h
                db 0A7h
                db  26h ; &
                db  32h ; 2
                db 0A1h
                db 0F1h
                db 0F3h
                db  97h
                db  6Fh ; o
                db  6Bh ; k
                db  57h ; W
                db 0D8h
                db  95h
                db 0BDh
                db  6Ah ; j
                db  4Bh ; K
                db 0BBh
                db 0CAh
                db 0D5h
                db 0D3h
                db 0E4h
                db 0E0h
                db 0C4h
                db  26h ; &
                db  5Dh ; ]
                db  78h ; x
                db 0F2h
                db 0A5h
                db 0A2h
                db  91h
                db  0Ch
                db    4
                db  17h
                db 0A2h
                db  6Ch ; l
                db 0FAh
                db 0EEh
                db 0FAh
                db  1Fh
                db 0EDh
                db  69h ; i
                db  58h ; X
                db  5Bh ; [
                db 0FBh
                db  79h ; y
                db 0F0h
                db 0C6h
                db    6
                db  77h ; w
                db  67h ; g
                db  91h
                db  6Eh ; n
                db 0BBh
                db 0FBh
                db  7Bh ; {
                db 0A0h
                db 0BEh
                db  36h ; 6
                db  78h ; x
                db  8Eh
                db  45h ; E
                db  5Bh ; [
                db 0AAh
                db 0E1h
                db  56h ; V
                db 0AFh
                db 0D1h
                db    7
                db  0Bh
                db  9Bh
                db 0DCh
                db 0C8h
                db 0C4h
                db  0Bh
                db 0C5h
                db  7Ch ; |
                db 0C9h
                db  17h
                db  4Dh ; M
                db  58h ; X
                db  39h ; 9
                db  46h ; F
                db 0ACh
                db 0F2h
                db  0Bh
                db 0F2h
                db  9Eh
                db  33h ; 3
                db  5Bh ; [
                db 0A1h
                db  53h ; S
                db  8Dh
                db  49h ; I
                db 0B1h
                db  40h ; @
                db  83h
                db  96h
                db  0Dh
                db  0Dh
                db  91h
                db 0E7h
                db  53h ; S
                db 0DAh
                db 0FAh
                db  36h ; 6
                db  1Dh
                db 0B2h
                db  3Eh ; >
                db 0CAh
                db  1Ah
                db  2Ch ; ,
                db  9Fh
                db  31h ; 1
                db 0A2h
                db  86h
                db  9Dh
                db 0A6h
                db  35h ; 5
                db 0C2h
                db 0E2h
                db 0F5h
                db  7Fh ; 
                db 0AFh
                db  9Bh
                db 0F1h
                db  12h
                db 0C9h
                db  85h
                db  64h ; d
                db 0ECh
                db  1Fh
                db  35h ; 5
                db  3Dh ; =
                db 0ECh
                db 0AEh
                db  46h ; F
                db    4
                db  63h ; c
                db    0
                db  40h ; @
                db  53h ; S
                db  75h ; u
                db 0D5h
                db 0C5h
                db 0D5h
                db  0Fh
                db 0FBh
                db  3Eh ; >
                db 0F0h
                db 0F6h
                db 0D9h
                db  50h ; P
                db  4Ch ; L
                db  26h ; &
                db  7Eh ; ~
                db  18h
                db  80h
                db  52h ; R
                db  94h
                db  5Ah ; Z
                db 0AFh
                db 0A0h
                db    7
                db  67h ; g
                db 0F2h
                db 0ABh
                db 0A2h
                db  27h ; '
                db 0F6h
                db  3Ah ; :
                db 0C5h
                db  3Ch ; <
                db 0A6h
                db 0B1h
                db 0FBh
                db    9
                db  0Ah
                db 0DFh
                db  68h ; h
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
_data           ends

; Section 3. (virtual address 00004000)
; Virtual size                  : 000004AC (   1196.)
; Section size in file          : 00000600 (   1536.)
; Offset to raw data for section: 00001E00
; Flags 40300040: Data Readable
; Alignment     : 4 bytes
; ===========================================================================

; Segment type: Pure data
; Segment permissions: Read
_rdata          segment dword public 'DATA' use32
                assume cs:_rdata
                ;org 404000h
; const CHAR Caption[]
Caption         db 'Welcome Message',0  ; DATA XREF: _WinMain@16+E¡èo
; const CHAR Text[]
Text            db 'Hello World!!',0    ; DATA XREF: _WinMain@16+16¡èo
                align 10h
                public ___dyn_tls_init_callback
; const PIMAGE_TLS_CALLBACK __dyn_tls_init_callback
___dyn_tls_init_callback dd offset ___dyn_tls_init@12
                                        ; DATA XREF: ___tmainCRTStartup:loc_401272¡èr
aUnknownError   db 'Unknown error',0    ; DATA XREF: __matherr+C¡èo
                align 4
; const char Format[]
Format          db '_matherr(): %s in %s(%g, %g)  (retval=%g)',0Ah,0
                                        ; DATA XREF: __matherr+39¡èo
                align 10h
aArgumentDomain db 'Argument domain error (DOMAIN)',0
                                        ; DATA XREF: .rdata:_CSWTCH_5¡éo
aArgumentSingul db 'Argument singularity (SIGN)',0
                                        ; DATA XREF: .rdata:00404144¡éo
                align 4
aOverflowRangeE db 'Overflow range error (OVERFLOW)',0
                                        ; DATA XREF: .rdata:00404148¡éo
aTheResultIsToo db 'The result is too small to be represented (UNDERFLOW)',0
                                        ; DATA XREF: .rdata:0040414C¡éo
                align 4
aTotalLossOfSig db 'Total loss of significance (TLOSS)',0
                                        ; DATA XREF: .rdata:00404150¡éo
                align 4
aPartialLossOfS db 'Partial loss of significance (PLOSS)',0
                                        ; DATA XREF: .rdata:00404154¡éo
                align 10h
_CSWTCH_5       dd offset aArgumentDomain ; DATA XREF: __matherr+16¡èr
                                        ; "Argument domain error (DOMAIN)"
                dd offset aArgumentSingul ; "Argument singularity (SIGN)"
                dd offset aOverflowRangeE ; "Overflow range error (OVERFLOW)"
                dd offset aTheResultIsToo ; "The result is too small to be represent"...
                dd offset aTotalLossOfSig ; "Total loss of significance (TLOSS)"
                dd offset aPartialLossOfS ; "Partial loss of significance (PLOSS)"
aMingwW64Runtim db 'Mingw-w64 runtime failure:',0Ah,0
                                        ; DATA XREF: ___report_error+1D¡èo
; const char aAddressPHasNoI[]
aAddressPHasNoI db 'Address %p has no image-section',0
                                        ; DATA XREF: ___write_memory_part_0+21B¡èo
; const char aVirtualqueryFa[]
aVirtualqueryFa db '  VirtualQuery failed for %d bytes at address %p',0
                                        ; DATA XREF: ___write_memory_part_0+207¡èo
                                        ; ___write_memory_part_0+233¡èo ...
                align 4
; const char msg[]
msg             db '  VirtualProtect failed with code 0x%x',0
                                        ; DATA XREF: ___write_memory_part_0+1D9¡èo
                align 10h
; const char aUnknownPseudoR_0[]
aUnknownPseudoR_0 db '  Unknown pseudo relocation protocol version %d.',0Ah,0
                                        ; DATA XREF: __pei386_runtime_relocator+2C7¡èo
                align 4
; const char aUnknownPseudoR[]
aUnknownPseudoR db '  Unknown pseudo relocation bit size %d.',0Ah,0
                                        ; DATA XREF: __pei386_runtime_relocator+EE¡èo
                align 10h
; const EXCEPTION_POINTERS GS_ExceptionPointers
_GS_ExceptionPointers EXCEPTION_POINTERS <offset _GS_ExceptionRecord, \
                                        ; DATA XREF: ___report_gsfailure+58¡èo
                                    offset _GS_ContextRecord>
_rdata          db  10h
                db  1Ch
                db    0
                db    0
                db  47h ; G
                db  43h ; C
                db  43h ; C
                db  3Ah ; :
                db  20h
                db  28h ; (
                db  47h ; G
                db  4Eh ; N
                db  55h ; U
                db  29h ; )
                db  20h
                db  34h ; 4
                db  2Eh ; .
                db  38h ; 8
                db  2Eh ; .
                db  31h ; 1
                db    0
                db    0
                db    0
                db    0
                db  47h ; G
                db  43h ; C
                db  43h ; C
                db  3Ah ; :
                db  20h
                db  28h ; (
                db  47h ; G
                db  4Eh ; N
                db  55h ; U
                db  29h ; )
                db  20h
                db  34h ; 4
                db  2Eh ; .
                db  38h ; 8
                db  2Eh ; .
                db  31h ; 1
                db    0
                db    0
                db    0
                db    0
                db  47h ; G
                db  43h ; C
                db  43h ; C
                db  3Ah ; :
                db  20h
                db  28h ; (
                db  74h ; t
                db  64h ; d
                db  6Dh ; m
                db  36h ; 6
                db  34h ; 4
                db  2Dh ; -
                db  32h ; 2
                db  29h ; )
                db  20h
                db  34h ; 4
                db  2Eh ; .
                db  38h ; 8
                db  2Eh ; .
                db  31h ; 1
                db    0
                db    0
                db    0
                db    0
                db  47h ; G
                db  43h ; C
                db  43h ; C
                db  3Ah ; :
                db  20h
                db  28h ; (
                db  47h ; G
                db  4Eh ; N
                db  55h ; U
                db  29h ; )
                db  20h
                db  34h ; 4
                db  2Eh ; .
                db  38h ; 8
                db  2Eh ; .
                db  31h ; 1
                db    0
                db    0
                db    0
                db    0
                db  47h ; G
                db  43h ; C
                db  43h ; C
                db  3Ah ; :
                db  20h
                db  28h ; (
                db  47h ; G
                db  4Eh ; N
                db  55h ; U
                db  29h ; )
                db  20h
                db  34h ; 4
                db  2Eh ; .
                db  38h ; 8
                db  2Eh ; .
                db  31h ; 1
                db    0
                db    0
                db    0
                db    0
                db  47h ; G
                db  43h ; C
                db  43h ; C
                db  3Ah ; :
                db  20h
                db  28h ; (
                db  47h ; G
                db  4Eh ; N
                db  55h ; U
                db  29h ; )
                db  20h
                db  34h ; 4
                db  2Eh ; .
                db  38h ; 8
                db  2Eh ; .
                db  31h ; 1
                db    0
                db    0
                db    0
                db    0
                db  47h ; G
                db  43h ; C
                db  43h ; C
                db  3Ah ; :
                db  20h
                db  28h ; (
                db  47h ; G
                db  4Eh ; N
                db  55h ; U
                db  29h ; )
                db  20h
                db  34h ; 4
                db  2Eh ; .
                db  38h ; 8
                db  2Eh ; .
                db  31h ; 1
                db    0
                db    0
                db    0
                db    0
                db  47h ; G
                db  43h ; C
                db  43h ; C
                db  3Ah ; :
                db  20h
                db  28h ; (
                db  47h ; G
                db  4Eh ; N
                db  55h ; U
                db  29h ; )
                db  20h
                db  34h ; 4
                db  2Eh ; .
                db  38h ; 8
                db  2Eh ; .
                db  31h ; 1
                db    0
                db    0
                db    0
                db    0
                db  47h ; G
                db  43h ; C
                db  43h ; C
                db  3Ah ; :
                db  20h
                db  28h ; (
                db  47h ; G
                db  4Eh ; N
                db  55h ; U
                db  29h ; )
                db  20h
                db  34h ; 4
                db  2Eh ; .
                db  38h ; 8
                db  2Eh ; .
                db  31h ; 1
                db    0
                db    0
                db    0
                db    0
                db  47h ; G
                db  43h ; C
                db  43h ; C
                db  3Ah ; :
                db  20h
                db  28h ; (
                db  47h ; G
                db  4Eh ; N
                db  55h ; U
                db  29h ; )
                db  20h
                db  34h ; 4
                db  2Eh ; .
                db  38h ; 8
                db  2Eh ; .
                db  31h ; 1
                db    0
                db    0
                db    0
                db    0
                db  47h ; G
                db  43h ; C
                db  43h ; C
                db  3Ah ; :
                db  20h
                db  28h ; (
                db  47h ; G
                db  4Eh ; N
                db  55h ; U
                db  29h ; )
                db  20h
                db  34h ; 4
                db  2Eh ; .
                db  38h ; 8
                db  2Eh ; .
                db  31h ; 1
                db    0
                db    0
                db    0
                db    0
                db  47h ; G
                db  43h ; C
                db  43h ; C
                db  3Ah ; :
                db  20h
                db  28h ; (
                db  47h ; G
                db  4Eh ; N
                db  55h ; U
                db  29h ; )
                db  20h
                db  34h ; 4
                db  2Eh ; .
                db  38h ; 8
                db  2Eh ; .
                db  31h ; 1
                db    0
                db    0
                db    0
                db    0
                db  47h ; G
                db  43h ; C
                db  43h ; C
                db  3Ah ; :
                db  20h
                db  28h ; (
                db  47h ; G
                db  4Eh ; N
                db  55h ; U
                db  29h ; )
                db  20h
                db  34h ; 4
                db  2Eh ; .
                db  38h ; 8
                db  2Eh ; .
                db  31h ; 1
                db    0
                db    0
                db    0
                db    0
                db  47h ; G
                db  43h ; C
                db  43h ; C
                db  3Ah ; :
                db  20h
                db  28h ; (
                db  47h ; G
                db  4Eh ; N
                db  55h ; U
                db  29h ; )
                db  20h
                db  34h ; 4
                db  2Eh ; .
                db  38h ; 8
                db  2Eh ; .
                db  31h ; 1
                db    0
                db    0
                db    0
                db    0
                db  47h ; G
                db  43h ; C
                db  43h ; C
                db  3Ah ; :
                db  20h
                db  28h ; (
                db  47h ; G
                db  4Eh ; N
                db  55h ; U
                db  29h ; )
                db  20h
                db  34h ; 4
                db  2Eh ; .
                db  38h ; 8
                db  2Eh ; .
                db  31h ; 1
                db    0
                db    0
                db    0
                db    0
                db  47h ; G
                db  43h ; C
                db  43h ; C
                db  3Ah ; :
                db  20h
                db  28h ; (
                db  47h ; G
                db  4Eh ; N
                db  55h ; U
                db  29h ; )
                db  20h
                db  34h ; 4
                db  2Eh ; .
                db  38h ; 8
                db  2Eh ; .
                db  31h ; 1
                db    0
                db    0
                db    0
                db    0
                db  47h ; G
                db  43h ; C
                db  43h ; C
                db  3Ah ; :
                db  20h
                db  28h ; (
                db  47h ; G
                db  4Eh ; N
                db  55h ; U
                db  29h ; )
                db  20h
                db  34h ; 4
                db  2Eh ; .
                db  38h ; 8
                db  2Eh ; .
                db  31h ; 1
                db    0
                db    0
                db    0
                db    0
                db  47h ; G
                db  43h ; C
                db  43h ; C
                db  3Ah ; :
                db  20h
                db  28h ; (
                db  47h ; G
                db  4Eh ; N
                db  55h ; U
                db  29h ; )
                db  20h
                db  34h ; 4
                db  2Eh ; .
                db  38h ; 8
                db  2Eh ; .
                db  31h ; 1
                db    0
                db    0
                db    0
                db    0
                db  47h ; G
                db  43h ; C
                db  43h ; C
                db  3Ah ; :
                db  20h
                db  28h ; (
                db  47h ; G
                db  4Eh ; N
                db  55h ; U
                db  29h ; )
                db  20h
                db  34h ; 4
                db  2Eh ; .
                db  38h ; 8
                db  2Eh ; .
                db  31h ; 1
                db    0
                db    0
                db    0
                db    0
                db  47h ; G
                db  43h ; C
                db  43h ; C
                db  3Ah ; :
                db  20h
                db  28h ; (
                db  47h ; G
                db  4Eh ; N
                db  55h ; U
                db  29h ; )
                db  20h
                db  34h ; 4
                db  2Eh ; .
                db  38h ; 8
                db  2Eh ; .
                db  31h ; 1
                db    0
                db    0
                db    0
                db    0
                db  47h ; G
                db  43h ; C
                db  43h ; C
                db  3Ah ; :
                db  20h
                db  28h ; (
                db  47h ; G
                db  4Eh ; N
                db  55h ; U
                db  29h ; )
                db  20h
                db  34h ; 4
                db  2Eh ; .
                db  38h ; 8
                db  2Eh ; .
                db  31h ; 1
                db    0
                db    0
                db    0
                db    0
                db  47h ; G
                db  43h ; C
                db  43h ; C
                db  3Ah ; :
                db  20h
                db  28h ; (
                db  47h ; G
                db  4Eh ; N
                db  55h ; U
                db  29h ; )
                db  20h
                db  34h ; 4
                db  2Eh ; .
                db  38h ; 8
                db  2Eh ; .
                db  31h ; 1
                db    0
                db    0
                db    0
                db    0
                db  47h ; G
                db  43h ; C
                db  43h ; C
                db  3Ah ; :
                db  20h
                db  28h ; (
                db  47h ; G
                db  4Eh ; N
                db  55h ; U
                db  29h ; )
                db  20h
                db  34h ; 4
                db  2Eh ; .
                db  38h ; 8
                db  2Eh ; .
                db  31h ; 1
                db    0
                db    0
                db    0
                db    0
                db  47h ; G
                db  43h ; C
                db  43h ; C
                db  3Ah ; :
                db  20h
                db  28h ; (
                db  47h ; G
                db  4Eh ; N
                db  55h ; U
                db  29h ; )
                db  20h
                db  34h ; 4
                db  2Eh ; .
                db  38h ; 8
                db  2Eh ; .
                db  31h ; 1
                db    0
                db    0
                db    0
                db    0
                db  47h ; G
                db  43h ; C
                db  43h ; C
                db  3Ah ; :
                db  20h
                db  28h ; (
                db  74h ; t
                db  64h ; d
                db  6Dh ; m
                db  36h ; 6
                db  34h ; 4
                db  2Dh ; -
                db  32h ; 2
                db  29h ; )
                db  20h
                db  34h ; 4
                db  2Eh ; .
                db  38h ; 8
                db  2Eh ; .
                db  31h ; 1
                db    0
                db    0
                db    0
                db    0
                db  47h ; G
                db  43h ; C
                db  43h ; C
                db  3Ah ; :
                db  20h
                db  28h ; (
                db  47h ; G
                db  4Eh ; N
                db  55h ; U
                db  29h ; )
                db  20h
                db  34h ; 4
                db  2Eh ; .
                db  38h ; 8
                db  2Eh ; .
                db  31h ; 1
                db    0
                db    0
                db    0
                db    0
                db  47h ; G
                db  43h ; C
                db  43h ; C
                db  3Ah ; :
                db  20h
                db  28h ; (
                db  47h ; G
                db  4Eh ; N
                db  55h ; U
                db  29h ; )
                db  20h
                db  34h ; 4
                db  2Eh ; .
                db  38h ; 8
                db  2Eh ; .
                db  31h ; 1
                db    0
                db    0
                db    0
                db    0
                db  47h ; G
                db  43h ; C
                db  43h ; C
                db  3Ah ; :
                db  20h
                db  28h ; (
                db  47h ; G
                db  4Eh ; N
                db  55h ; U
                db  29h ; )
                db  20h
                db  34h ; 4
                db  2Eh ; .
                db  38h ; 8
                db  2Eh ; .
                db  31h ; 1
                db    0
                db    0
                db    0
                db    0
                public __rt_psrelocs_start
__rt_psrelocs_start dd 0                ; DATA XREF: __pei386_runtime_relocator+57¡èo
                                        ; __pei386_runtime_relocator+6E¡èr ...
dword_404498    dd 0                    ; DATA XREF: __pei386_runtime_relocator+7B¡èr
dword_40449C    dd 1                    ; DATA XREF: __pei386_runtime_relocator+88¡èr
unk_4044A0      db  20h                 ; DATA XREF: __pei386_runtime_relocator+8E¡èo
                db  30h ; 0
                db    0
                db    0
                db 0B9h
                db  12h
                db    0
                db    0
                db  20h
                db    0
                db    0
                db    0
                public __RUNTIME_PSEUDO_RELOC_LIST_END___0
__RUNTIME_PSEUDO_RELOC_LIST_END___0 db    0
                                        ; DATA XREF: __pei386_runtime_relocator+52¡èo
                                        ; __pei386_runtime_relocator+AF¡èo ...
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
_rdata          ends

; Section 4. (virtual address 00005000)
; Virtual size                  : 000003F0 (   1008.)
; Section size in file          : 00000000 (      0.)
; Offset to raw data for section: 00000000
; Flags C0600080: Bss Readable Writable
; Alignment     : 32 bytes
; ===========================================================================

; Segment type: Uninitialized
; Segment permissions: Read/Write
_bss            segment align_32 public 'BSS' use32
                assume cs:_bss
                ;org 405000h
                assume es:nothing, ss:nothing, ds:_data, fs:nothing, gs:nothing
                public __bss_start__
; _startupinfo _bss_start__
__bss_start__   _startupinfo <?>        ; DATA XREF: _pre_cpp_init+8¡èo
                                        ; _pre_cpp_init+20¡èw
; int has_cctor
_has_cctor      dd ?                    ; DATA XREF: ___tmainCRTStartup+D2¡èw
                                        ; ___tmainCRTStartup+281¡èr
; int managedapp
_managedapp     dd ?                    ; DATA XREF: _pre_c_init:loc_401048¡èw
                                        ; ___tmainCRTStartup+26E¡èr
; int mainret
_mainret        dd ?                    ; DATA XREF: ___tmainCRTStartup+276¡èw
                                        ; ___tmainCRTStartup+290¡èr
; int argret
_argret         dd ?                    ; DATA XREF: _pre_cpp_init+3A¡èw
; char **envp
_envp           dd ?                    ; DATA XREF: _pre_cpp_init+10¡èo
                                        ; ___tmainCRTStartup+247¡èr ...
; char **argv
_argv           dd ?                    ; DATA XREF: _pre_cpp_init+18¡èo
                                        ; ___tmainCRTStartup+1D6¡èr ...
; int argc
_argc           dd ?                    ; DATA XREF: _pre_cpp_init+2A¡èo
                                        ; ___tmainCRTStartup:loc_401338¡èr ...
                public _mingw_initltssuo_force
; int mingw_initltssuo_force
_mingw_initltssuo_force dd ?            ; DATA XREF: _pre_c_init+22¡èw
                public _mingw_initltsdyn_force
; int mingw_initltsdyn_force
_mingw_initltsdyn_force dd ?            ; DATA XREF: _pre_c_init+18¡èw
                public _mingw_initltsdrot_force
; int mingw_initltsdrot_force
_mingw_initltsdrot_force dd ?           ; DATA XREF: _pre_c_init+E¡èw
                public __tls_index
; ULONG _tls_index
__tls_index     dd ?
                public _mingw_initcharmax
; int mingw_initcharmax
_mingw_initcharmax dd ?                 ; DATA XREF: _pre_c_init+2C¡èw
                public _mingw_app_type
; int mingw_app_type
_mingw_app_type dd ?                    ; DATA XREF: _pre_c_init+3D¡èr
                                        ; ___tmainCRTStartup+61¡èr ...
                public __fmode
; int _fmode
__fmode         dd ?                    ; DATA XREF: _pre_c_init+5E¡èr
                public __newmode
; int _newmode
__newmode       dd ?                    ; DATA XREF: _pre_cpp_init+3¡èr
                public __dowildcard
; int _dowildcard
__dowildcard    dd ?                    ; DATA XREF: _pre_cpp_init+25¡èr
                public ___mingw_oldexcpt_handler
; LPTOP_LEVEL_EXCEPTION_FILTER __mingw_oldexcpt_handler
___mingw_oldexcpt_handler dd ?          ; DATA XREF: ___tmainCRTStartup+12C¡èw
                                        ; __gnu_exception_handler@4:loc_4017BD¡èr
; fUserMathErr stUserMathErr
_stUserMathErr  dd ?                    ; DATA XREF: ___mingw_raise_matherr+3¡èr
                                        ; ___mingw_setusermatherr+4¡èw
; Function-local static variable
; int was_init_60223
_was_init_60223 dd ?                    ; DATA XREF: __pei386_runtime_relocator¡èr
                                        ; __pei386_runtime_relocator+19¡èw
; int maxSections
_maxSections    dd ?                    ; DATA XREF: ___write_memory_part_0+E¡èr
                                        ; ___write_memory_part_0:loc_401A93¡èw ...
; sSecInfo_0 *the_secs
_the_secs       dd ?                    ; DATA XREF: ___write_memory_part_0+1F¡èr
                                        ; ___write_memory_part_0+60¡èr ...
; int initialized
_initialized    dd ?                    ; DATA XREF: ___main¡èr
                                        ; ___main:loc_401F90¡èw
                align 10h
; CONTEXT GS_ContextRecord
_GS_ContextRecord CONTEXT <?>           ; DATA XREF: .rdata:_GS_ExceptionPointers¡èo
                align 20h
; EXCEPTION_RECORD GS_ExceptionRecord
_GS_ExceptionRecord EXCEPTION_RECORD <?>
                                        ; DATA XREF: ___report_gsfailure+12¡èw
                                        ; .rdata:_GS_ExceptionPointers¡èo ...
                align 20h
; volatile __mingwthr_key_t *key_dtor_list
_key_dtor_list  dd ?                    ; DATA XREF: ___mingwthr_run_key_dtors_part_0+16¡èr
                                        ; ____w64_mingwthr_add_key_dtor+52¡èr ...
; volatile int __mingwthr_cs_init
___mingwthr_cs_init dd ?                ; DATA XREF: ____w64_mingwthr_add_key_dtor+A¡èr
                                        ; ____w64_mingwthr_remove_key_dtor+7¡èr ...
; CRITICAL_SECTION __mingwthr_cs
___mingwthr_cs  CRITICAL_SECTION <?>    ; DATA XREF: ___mingwthr_run_key_dtors_part_0+9¡èo
                                        ; ___mingwthr_run_key_dtors_part_0:loc_402139¡èo ...
; char _RUNTIME_PSEUDO_RELOC_LIST__
__RUNTIME_PSEUDO_RELOC_LIST__ db ?
; char _RUNTIME_PSEUDO_RELOC_LIST_END__[3]
__RUNTIME_PSEUDO_RELOC_LIST_END__ db 3 dup(?)
; LONG handler
_handler        dd ?                    ; DATA XREF: _mingw_get_invalid_parameter_handler¡èr
                                        ; _mingw_set_invalid_parameter_handler+9¡èo
                public ___mingw_winmain_lpCmdLine
; LPSTR __mingw_winmain_lpCmdLine
___mingw_winmain_lpCmdLine dd ?         ; DATA XREF: ___tmainCRTStartup:loc_401314¡èw
                                        ; _main+27¡èr
                public ___mingw_winmain_hInstance
; HINSTANCE __mingw_winmain_hInstance
___mingw_winmain_hInstance dd ?         ; DATA XREF: ___tmainCRTStartup+147¡èw
                                        ; _main+30¡èr
                public ___onexitend
; _PVFV *__onexitend
___onexitend    dd ?                    ; DATA XREF: _pre_c_init+64¡èw
                                        ; _mingw_onexit+3B¡èr ...
                public ___onexitbegin
; _PVFV *__onexitbegin
___onexitbegin  dd ?                    ; DATA XREF: _pre_c_init+69¡èw
                                        ; _mingw_onexit+4¡èr ...
                public ___native_startup_lock
; LONG __native_startup_lock
___native_startup_lock dd ?             ; DATA XREF: ___tmainCRTStartup+A5¡èo
                                        ; ___tmainCRTStartup+2FB¡èo
                public ___native_startup_state
; volatile __enative_startup_state_0 __native_startup_state
___native_startup_state dd ?            ; DATA XREF: ___tmainCRTStartup+B5¡èr
                                        ; ___tmainCRTStartup:loc_401245¡èr ...
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                public __bss_end__
__bss_end__     db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
_bss            ends

;
; Imports from KERNEL32.dll
;
; Section 5. (virtual address 00006000)
; Virtual size                  : 000005E0 (   1504.)
; Section size in file          : 00000600 (   1536.)
; Offset to raw data for section: 00002400
; Flags C0300040: Data Readable Writable
; Alignment     : 4 bytes
; ===========================================================================

; Segment type: Externs
; _idata
; void __stdcall _DeleteCriticalSection_4(LPCRITICAL_SECTION lpCriticalSection)
                extrn __imp__DeleteCriticalSection@4:dword
                                        ; CODE XREF: ___mingw_TLScallback+49¡èp
                                        ; DATA XREF: ___mingw_TLScallback+49¡èr
; void __stdcall _EnterCriticalSection_4(LPCRITICAL_SECTION lpCriticalSection)
                extrn __imp__EnterCriticalSection@4:dword
                                        ; CODE XREF: ___mingwthr_run_key_dtors_part_0+10¡èp
                                        ; ____w64_mingwthr_add_key_dtor+4C¡èp ...
; HANDLE __stdcall _GetCurrentProcess_0()
                extrn __imp__GetCurrentProcess@0:dword
                                        ; CODE XREF: ___report_gsfailure+68¡èp
                                        ; DATA XREF: ___report_gsfailure+68¡èr
; DWORD __stdcall _GetCurrentProcessId_0()
                extrn __imp__GetCurrentProcessId@0:dword
                                        ; CODE XREF: ___security_init_cookie+49¡èp
                                        ; DATA XREF: ___security_init_cookie+49¡èr
; DWORD __stdcall _GetCurrentThreadId_0()
                extrn __imp__GetCurrentThreadId@0:dword
                                        ; CODE XREF: ___security_init_cookie+51¡èp
                                        ; DATA XREF: ___security_init_cookie+51¡èr
; DWORD __stdcall _GetLastError_0()
                extrn __imp__GetLastError@0:dword
                                        ; CODE XREF: ___write_memory_part_0+1D3¡èp
                                        ; ___mingwthr_run_key_dtors_part_0+40¡èp
                                        ; DATA XREF: ...
; void __stdcall _GetStartupInfoA_4(LPSTARTUPINFOA lpStartupInfo)
                extrn __imp__GetStartupInfoA@4:dword
                                        ; CODE XREF: ___tmainCRTStartup+313¡èp
                                        ; DATA XREF: ___tmainCRTStartup+313¡èr
; void __stdcall _GetSystemTimeAsFileTime_4(LPFILETIME lpSystemTimeAsFileTime)
                extrn __imp__GetSystemTimeAsFileTime@4:dword
                                        ; CODE XREF: ___security_init_cookie+38¡èp
                                        ; DATA XREF: ___security_init_cookie+38¡èr
; DWORD __stdcall _GetTickCount_0()
                extrn __imp__GetTickCount@0:dword
                                        ; CODE XREF: ___security_init_cookie+5A¡èp
                                        ; DATA XREF: ___security_init_cookie+5A¡èr
; void __stdcall _InitializeCriticalSection_4(LPCRITICAL_SECTION lpCriticalSection)
                extrn __imp__InitializeCriticalSection@4:dword
                                        ; CODE XREF: ___mingw_TLScallback+77¡èp
                                        ; DATA XREF: ___mingw_TLScallback+77¡èr
; LONG __stdcall _InterlockedCompareExchange_12(volatile LONG *Destination, LONG Exchange, LONG Comperand)
                extrn __imp__InterlockedCompareExchange@12:dword
                                        ; CODE XREF: ___tmainCRTStartup+AC¡èp
                                        ; DATA XREF: ___tmainCRTStartup+74¡èr
; LONG __stdcall _InterlockedExchange_8(volatile LONG *Target, LONG Value)
                extrn __imp__InterlockedExchange@8:dword
                                        ; CODE XREF: ___tmainCRTStartup+302¡èp
                                        ; _mingw_set_invalid_parameter_handler+14¡èp
                                        ; DATA XREF: ...
; void __stdcall _LeaveCriticalSection_4(LPCRITICAL_SECTION lpCriticalSection)
                extrn __imp__LeaveCriticalSection@4:dword
                                        ; CODE XREF: ___mingwthr_run_key_dtors_part_0+60¡èp
                                        ; ____w64_mingwthr_add_key_dtor+6A¡èp ...
; BOOL __stdcall _QueryPerformanceCounter_4(LARGE_INTEGER *lpPerformanceCount)
                extrn __imp__QueryPerformanceCounter@4:dword
                                        ; CODE XREF: ___security_init_cookie+69¡èp
                                        ; DATA XREF: ___security_init_cookie+69¡èr
; LPTOP_LEVEL_EXCEPTION_FILTER __stdcall _SetUnhandledExceptionFilter_4(LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter)
                extrn __imp__SetUnhandledExceptionFilter@4:dword
                                        ; CODE XREF: ___tmainCRTStartup+123¡èp
                                        ; ___report_gsfailure+4F¡èp
                                        ; DATA XREF: ...
; void __stdcall _Sleep_4(DWORD dwMilliseconds)
                extrn __imp__Sleep@4:dword
                                        ; CODE XREF: ___tmainCRTStartup+94¡èp
                                        ; DATA XREF: ___tmainCRTStartup+7D¡èr
; BOOL __stdcall TerminateProcess(HANDLE hProcess, UINT uExitCode)
                extrn __imp__TerminateProcess@8:dword
                                        ; CODE XREF: ___report_gsfailure+79¡èp
                                        ; DATA XREF: ___report_gsfailure+79¡èr
; LPVOID __stdcall TlsGetValue(DWORD dwTlsIndex)
                extrn __imp__TlsGetValue@4:dword
                                        ; CODE XREF: ___mingwthr_run_key_dtors_part_0+35¡èp
                                        ; DATA XREF: ___mingwthr_run_key_dtors_part_0+35¡èr
; LONG __stdcall _UnhandledExceptionFilter_4(struct _EXCEPTION_POINTERS *ExceptionInfo)
                extrn __imp__UnhandledExceptionFilter@4:dword
                                        ; CODE XREF: ___report_gsfailure+5F¡èp
                                        ; DATA XREF: ___report_gsfailure+5F¡èr
; BOOL __stdcall _VirtualProtect_16(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
                extrn __imp__VirtualProtect@16:dword
                                        ; CODE XREF: ___write_memory_part_0+147¡èp
                                        ; ___write_memory_part_0+187¡èp ...
; SIZE_T __stdcall _VirtualQuery_12(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength)
                extrn __imp__VirtualQuery@12:dword
                                        ; CODE XREF: ___write_memory_part_0+A4¡èp
                                        ; ___write_memory_part_0+D9¡èp ...

;
; Imports from msvcrt.dll
;
                extrn __imp____dllonexit:dword
                                        ; DATA XREF: ___dllonexit¡èr
                extrn __imp____getmainargs:dword
                                        ; DATA XREF: ___getmainargs¡èr
                extrn __imp____initenv:dword
                                        ; DATA XREF: ___tmainCRTStartup+242¡èr
                extrn __imp____lconv_init:dword
                                        ; DATA XREF: _my_lconv_init¡èr
; void __cdecl ___set_app_type(_crt_app_type Type)
                extrn __imp____set_app_type:dword
                                        ; DATA XREF: ___set_app_type¡èr
; void __cdecl ___setusermatherr(_UserMathErrorFunctionPointer UserMathErrorFunction)
                extrn __imp____setusermatherr:dword
                                        ; DATA XREF: ___setusermatherr¡èr
; char *__acmdln
                extrn __imp___acmdln:dword
                                        ; DATA XREF: ___tmainCRTStartup+142¡èr
                extrn __imp___amsg_exit:dword ; DATA XREF: __amsg_exit¡èr
; void __cdecl __cexit()
                extrn __imp___cexit:dword ; DATA XREF: __cexit¡èr
; int __fmode
                extrn __imp___fmode:dword ; DATA XREF: _pre_c_init+6E¡èr
; void __cdecl __initterm(_PVFV *First, _PVFV *Last)
                extrn __imp___initterm:dword ; DATA XREF: __initterm¡èr
; FILE __iob[]
                extrn __imp___iob:dword ; DATA XREF: __matherr+45¡èr
                                        ; ___report_error+4¡èr ...
                extrn __imp___lock:dword ; DATA XREF: __lock¡èr
; _onexit_t __cdecl __onexit(_onexit_t Func)
                extrn __imp___onexit:dword
                                        ; CODE XREF: _mingw_onexit+A7¡èp
                                        ; DATA XREF: _mingw_onexit+A7¡èr
                extrn __imp___unlock:dword ; DATA XREF: __unlock¡èr
; void __cdecl __noreturn _abort()
                extrn __imp__abort:dword ; DATA XREF: _abort¡èr
; void *__cdecl _calloc(size_t Count, size_t Size)
                extrn __imp__calloc:dword ; DATA XREF: _calloc¡èr
; void __cdecl __noreturn _exit(int Code)
                extrn __imp__exit:dword ; DATA XREF: _exit¡èr
; int _fprintf(FILE *const Stream, const char *const Format, ...)
                extrn __imp__fprintf:dword ; DATA XREF: _fprintf¡èr
; void __cdecl _free(void *Block)
                extrn __imp__free:dword ; DATA XREF: _free¡èr
; size_t __cdecl _fwrite(const void *Buffer, size_t ElementSize, size_t ElementCount, FILE *Stream)
                extrn __imp__fwrite:dword ; DATA XREF: _fwrite¡èr
; void *__cdecl _malloc(size_t Size)
                extrn __imp__malloc:dword ; DATA XREF: _malloc¡èr
; void *__cdecl _memcpy(void *, const void *Src, size_t Size)
                extrn __imp__memcpy:dword ; DATA XREF: _memcpy¡èr
; _crt_signal_t __cdecl _signal(int Signal, _crt_signal_t Function)
                extrn __imp__signal:dword ; DATA XREF: _signal¡èr
; size_t __cdecl _strlen(const char *Str)
                extrn __imp__strlen:dword ; DATA XREF: _strlen¡èr
; int __cdecl _strncmp(const char *Str1, const char *Str2, size_t MaxCount)
                extrn __imp__strncmp:dword ; DATA XREF: _strncmp¡èr
; int __cdecl _vfprintf(FILE *const Stream, const char *const Format, va_list ArgList)
                extrn __imp__vfprintf:dword ; DATA XREF: _vfprintf¡èr

;
; Imports from USER32.dll
;
; int __stdcall _MessageBoxA_16(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
                extrn __imp__MessageBoxA@16:dword
                                        ; CODE XREF: _WinMain@16+2A¡èp
                                        ; DATA XREF: _WinMain@16+25¡èr


; Section 6. (virtual address 00007000)
; Virtual size                  : 00000034 (     52.)
; Section size in file          : 00000200 (    512.)
; Offset to raw data for section: 00002A00
; Flags C0300040: Data Readable Writable
; Alignment     : 4 bytes
; ===========================================================================

; Segment type: Pure data
; Segment permissions: Read/Write
_CRT            segment dword public 'DATA' use32
                assume cs:_CRT
                ;org 407000h
                public ___crt_xc_start__
; _PVFV __crt_xc_start__[1]
___crt_xc_start__ dd 0                  ; DATA XREF: ___tmainCRTStartup+2D5¡èo
                public _mingw_pcppinit
; _PVFV mingw_pcppinit
_mingw_pcppinit dd offset _pre_cpp_init
                public ___xc_z
; _PVFV __xc_z[1]
___xc_z         dd 0                    ; DATA XREF: ___tmainCRTStartup:loc_40144D¡èo
                public ___crt_xc_end__
; _PVFV __crt_xc_end__[1]
___crt_xc_end__ dd 0                    ; DATA XREF: ___tmainCRTStartup+333¡èo
                public _mingw_pcinit
; _PIFV mingw_pcinit
_mingw_pcinit   dd offset _pre_c_init
                public ___mingw_pinit
; _PIFV __mingw_pinit
___mingw_pinit  dd offset _my_lconv_init
                public ___xi_z
; _PVFV __xi_z[1]
___xi_z         dd 0                    ; DATA XREF: ___tmainCRTStartup+32B¡èo
                public ___xl_a
; PIMAGE_TLS_CALLBACK __xl_a
___xl_a         dd 0
                public ___xl_c
; PIMAGE_TLS_CALLBACK __xl_c
___xl_c         dd offset ___dyn_tls_init@12
                public ___xl_d
; PIMAGE_TLS_CALLBACK __xl_d
___xl_d         dd offset ___dyn_tls_dtor@12
                public ___xl_z
; PIMAGE_TLS_CALLBACK __xl_z
___xl_z         dd 0
                public ___crt_xt_end__
; _PVFV __crt_xt_end__
___crt_xt_end__ dd 0
; _PVFV __xd_z
___xd_z         dd 0                    ; DATA XREF: ___dyn_tls_init@12:loc_4015E1¡èo
                                        ; ___dyn_tls_init@12+36¡èo ...
                align 1000h
_CRT            ends

; Section 7. (virtual address 00008000)
; Virtual size                  : 00000020 (     32.)
; Section size in file          : 00000200 (    512.)
; Offset to raw data for section: 00002C00
; Flags C0300040: Data Readable Writable
; Alignment     : 4 bytes
; ===========================================================================

; Segment type: Pure data
; Segment permissions: Read/Write
_tls            segment dword public 'DATA' use32
                assume cs:_tls
                ;org 408000h
                public __tls_used
; const IMAGE_TLS_DIRECTORY _tls_used
__tls_used      IMAGE_TLS_DIRECTORY <408018h, 40801Ch, 40502Ch, 407020h, 0, 0>
                public __tls_start
; char *_tls_start
__tls_start     dd 0
                public __tls_end
; char *_tls_end
__tls_end       dd 0
                public ___tls_end__
___tls_end__    db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
_tls            ends


                end _WinMainCRTStartup
