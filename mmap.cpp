#include "Windows.h"
#include "stdint.h"
#include "stdio.h"

static LONG handler(PEXCEPTION_POINTERS ptr, uint64_t context) {
    PEXCEPTION_RECORD record = ptr->ExceptionRecord;
    if (record->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        uint8_t* base = (uint8_t*)(record->ExceptionInformation[1]);
        fprintf(stderr, "We are accessing %p and context is %llx\n", base, context);
        if (VirtualAlloc(base, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE)) {
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

int main() {
    uint8_t* closure = (uint8_t*)VirtualAlloc(NULL, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    uint8_t* data = closure + 4096 / 2;
    uint8_t* ptr = closure;
    
    uint64_t context = 0x114514;
    fprintf(stderr, "Out content is %lx\n", context);

    *ptr = 0x48; // REX.w
    ptr += 1;
    *ptr = 0xb8; // mov rax
    ptr += 1;
    memcpy(ptr, &data, 8); // mov rax, &data
    ptr += 8;
    // ; rax = &data
    // mov [rax], rdx ; save rdx
    // mov rdx, [rax+0x8] ; move pointer to 2nd arg
    // sub rsp, 0x10; reserve 2 slots as ms fastcall requires
    // call [rax + 0x10] ; go to handler
    const char tramp[] = "\x48\x89\x10\x48\x8b\x50\x08\x48\x83\xec\x10\xff\x50\x10";
    memcpy(ptr, (void*)tramp, sizeof(tramp) - 1); // Note last zero!
    ptr += sizeof(tramp) - 1;
    *ptr = 0x48; // REX.w
    ptr += 1;
    *ptr = 0xba; // mov rdx
    ptr += 1;
    memcpy(ptr, &data, 8); // mov rdx, &data
    ptr += 8;
    // ; rdx = &data
    // add rsp, 0x10 ; clean stack
    // mov rdx, [rdx] ; restore rdx
    // ret
    const char tramp2[] = "\x48\x83\xc4\x10\x48\x8b\x12\xc3";
    memcpy(ptr, (void*)tramp2, sizeof(tramp2) - 1);
    
    void* handler_address = (void*)handler;
    memcpy(data + 0x8, (void*)&context, 8);
    memcpy(data + 0x10, (void*)&handler_address, 8);
    AddVectoredExceptionHandler(0, PVECTORED_EXCEPTION_HANDLER(closure));

    uint8_t* mem = (uint8_t*)VirtualAlloc(NULL, 16384, MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    fprintf(stderr, "Reserved %p\n", mem);
    mem[0] = 0xFF;

    fprintf(stderr, "Memory content is %hhx\n", mem[0]);
}