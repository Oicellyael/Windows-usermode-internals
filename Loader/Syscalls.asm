EXTERN IndirectSyscallJumpAddress : QWORD

EXTERN SsnNtOpenProcess : DWORD
EXTERN SsnNtReadVirtualMemory : DWORD
EXTERN SsnNtWriteVirtualMemory : DWORD
EXTERN SsnNtAllocateVirtualMemory : DWORD
EXTERN SsnNtFreeVirtualMemory : DWORD
EXTERN SsnNtProtectVirtualMemory : DWORD
EXTERN SsnNtDuplicateObject : DWORD

EXTERN SsnNtQuerySystemInformation : DWORD
EXTERN SsnNtQueryInformationProcess : DWORD

EXTERN SsnNtQueueApcThread : DWORD
EXTERN SsnNtGetContextThread : DWORD
EXTERN SsnNtSetContextThread : DWORD
EXTERN SsnNtResumeThread : DWORD
EXTERN SsnNtSuspendThread : DWORD

EXTERN SsnNtQueryVirtualMemory : DWORD
EXTERN SsnNtMapViewOfSection : DWORD
EXTERN SsnNtFlushInstructionCache : DWORD
EXTERN SsnNtClose : DWORD

.code

GetMyPeb PROC
    mov rax, gs:[60h]
    ret
GetMyPeb ENDP            

Syscall_NtOpenProcess PROC
    mov r10, rcx                
    mov eax, SsnNtOpenProcess     
    jmp qword ptr [IndirectSyscallJumpAddress] 
Syscall_NtOpenProcess ENDP

Syscall_NtReadVirtualMemory PROC
    mov r10, rcx
    mov eax, SsnNtReadVirtualMemory
    jmp qword ptr [IndirectSyscallJumpAddress]
Syscall_NtReadVirtualMemory ENDP

Syscall_NtWriteVirtualMemory PROC
    mov r10, rcx
    mov eax, SsnNtWriteVirtualMemory
    jmp qword ptr [IndirectSyscallJumpAddress]
Syscall_NtWriteVirtualMemory ENDP

Syscall_NtAllocateVirtualMemory PROC
    mov r10, rcx
    mov eax, SsnNtAllocateVirtualMemory
    jmp qword ptr [IndirectSyscallJumpAddress]
Syscall_NtAllocateVirtualMemory ENDP

Syscall_NtFreeVirtualMemory PROC
    mov r10, rcx
    mov eax, SsnNtFreeVirtualMemory
    jmp qword ptr [IndirectSyscallJumpAddress]
Syscall_NtFreeVirtualMemory ENDP

Syscall_NtProtectVirtualMemory PROC
    mov r10, rcx
    mov eax, SsnNtProtectVirtualMemory
    jmp qword ptr [IndirectSyscallJumpAddress]
Syscall_NtProtectVirtualMemory ENDP

Syscall_NtDuplicateObject PROC
    mov r10, rcx
    mov eax, SsnNtDuplicateObject
    jmp qword ptr [IndirectSyscallJumpAddress]
Syscall_NtDuplicateObject ENDP

Syscall_NtQuerySystemInformation PROC
    mov r10, rcx
    mov eax, SsnNtQuerySystemInformation
    jmp qword ptr [IndirectSyscallJumpAddress]
Syscall_NtQuerySystemInformation ENDP

Syscall_NtQueryInformationProcess PROC
    mov r10, rcx
    mov eax, SsnNtQueryInformationProcess
    jmp qword ptr [IndirectSyscallJumpAddress]
Syscall_NtQueryInformationProcess ENDP

Syscall_NtQueueApcThread PROC
    mov r10, rcx
    mov eax, SsnNtQueueApcThread
    jmp qword ptr [IndirectSyscallJumpAddress]
Syscall_NtQueueApcThread ENDP

Syscall_NtGetContextThread PROC
    mov r10, rcx
    mov eax, SsnNtGetContextThread
    jmp qword ptr [IndirectSyscallJumpAddress]
Syscall_NtGetContextThread ENDP

Syscall_NtSetContextThread PROC
    mov r10, rcx
    mov eax, SsnNtSetContextThread
    jmp qword ptr [IndirectSyscallJumpAddress]
Syscall_NtSetContextThread ENDP

Syscall_NtResumeThread PROC
    mov r10, rcx
    mov eax, SsnNtResumeThread
    jmp qword ptr [IndirectSyscallJumpAddress]
Syscall_NtResumeThread ENDP

Syscall_NtSuspendThread PROC
    mov r10, rcx
    mov eax, SsnNtSuspendThread
    jmp qword ptr [IndirectSyscallJumpAddress]
Syscall_NtSuspendThread ENDP

Syscall_NtQueryVirtualMemory PROC
    mov r10, rcx
    mov eax, SsnNtQueryVirtualMemory
    jmp qword ptr [IndirectSyscallJumpAddress]
Syscall_NtQueryVirtualMemory ENDP

Syscall_NtMapViewOfSection PROC
    mov r10, rcx
    mov eax, SsnNtMapViewOfSection
    jmp qword ptr [IndirectSyscallJumpAddress]
Syscall_NtMapViewOfSection ENDP

Syscall_NtFlushInstructionCache PROC
    mov r10, rcx
    mov eax, SsnNtFlushInstructionCache
    jmp qword ptr [IndirectSyscallJumpAddress]
Syscall_NtFlushInstructionCache ENDP

Syscall_NtClose PROC
    mov r10, rcx
    mov eax, SsnNtClose
    jmp qword ptr [IndirectSyscallJumpAddress]
Syscall_NtClose ENDP

END