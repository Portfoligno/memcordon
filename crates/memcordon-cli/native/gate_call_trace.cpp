#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <intrin.h>
#include <atomic>
#include "detours.h"
#include "gate_call_trace.h"

static_assert(sizeof(void*) == 8 && sizeof(WCHAR) == 2 && sizeof(NTSTATUS) == 4, "64-bit Windows ABI");
static_assert(sizeof(OBJECT_ATTRIBUTES) == 48 && offsetof(OBJECT_ATTRIBUTES, ObjectName) == 16, "object attributes ABI");
static_assert(sizeof(UNICODE_STRING) == 16 && offsetof(UNICODE_STRING, Buffer) == 8, "unicode string ABI");
using Open = NTSTATUS (NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
static std::atomic<Open> directory_open{nullptr}, event_open{nullptr};
static_assert(std::atomic<Open>::is_always_lock_free, "native original publication must be lock-free");
static const auto original_win32 = &OpenEventW;
static volatile LONG installation = 0;
static uint32_t installation_stage = 0, installation_error = 0;
static uint32_t installation_reason = 0, installation_current_thread = 0;
static IatRecord installation_iat = {};
struct Collector { TracePacket* packet; DWORD thread; };
// POD static TLS is initialized before user code, never lazily in a hook.
static __declspec(thread) Collector collector = {nullptr, 0};

static void arguments(TraceEntry* entry, POBJECT_ATTRIBUTES attributes) {
    __try {
        if (!attributes) { entry->name_malformed = 1; return; }
        entry->attributes_length = attributes->Length;
        if (attributes->Length != sizeof(OBJECT_ATTRIBUTES)) { entry->name_malformed = 1; return; }
        entry->attributes_flags = attributes->Attributes;
        entry->raw_root = reinterpret_cast<uintptr_t>(attributes->RootDirectory);
        entry->root_is_null = attributes->RootDirectory == nullptr;
        entry->arguments_readable = 1;
        if (!attributes->ObjectName) { entry->name_malformed = 1; return; }
        const UNICODE_STRING name = *attributes->ObjectName;
        entry->reported_name_bytes = name.Length;
        if ((name.Length % sizeof(WCHAR)) || name.Length > name.MaximumLength || (!name.Buffer && name.Length)) {
            entry->name_malformed = 1; return;
        }
        const size_t units = name.Length / sizeof(WCHAR);
        const size_t copied = units < 256 ? units : 256;
        for (size_t index = 0; index < copied; ++index) entry->name[index] = name.Buffer[index];
        entry->copied_name_units = static_cast<uint32_t>(copied);
        entry->name_truncated = units > copied;
        entry->name_readable = 1;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        entry->name_malformed = 1;
        entry->name_readable = 0;
    }
}

static void result(TraceEntry* entry, NTSTATUS status, PHANDLE output) {
    entry->native_status = status;
    entry->returned = 1;
    // On failure the API need not initialize its output. Never read that slot.
    if (status < 0) return;
    __try {
        if (output) {
            entry->raw_output = reinterpret_cast<uintptr_t>(*output);
            entry->output_handle_readable = 1;
            entry->output_handle_returned = *output != nullptr;
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        entry->output_handle_readable = 0;
    }
}

// The exact forwarding body is shared with the mock trampoline regression.
static NTSTATUS forward(Open original, PHANDLE output, ACCESS_MASK access, POBJECT_ATTRIBUTES attributes, TraceEntry* entry) {
    const DWORD incoming_error = GetLastError();
    if (entry) arguments(entry, attributes);
    SetLastError(incoming_error);
    const NTSTATUS status = original(output, access, attributes);
    const DWORD native_error = GetLastError();
    if (entry) result(entry, status, output);
    SetLastError(native_error);
    return status;
}

static TraceEntry* enter(uint32_t operation, ACCESS_MASK access) {
    TracePacket* packet = collector.packet;
    if (!packet) return nullptr;
    if (packet->count >= 8) { packet->overflow = packet->incomplete = 1; return nullptr; }
    TraceEntry* entry = &packet->entries[packet->count++];
    entry->sequence = packet->count;
    entry->operation = operation;
    entry->thread_id = collector.thread;
    entry->desired_access = access;
    entry->entered = 1;
    return entry;
}
static NTSTATUS NTAPI directory_hook(PHANDLE output, ACCESS_MASK access, POBJECT_ATTRIBUTES attributes) {
    TraceEntry* entry = enter(1, access);
    const NTSTATUS status = forward(directory_open.load(std::memory_order_acquire), output, access, attributes, entry);
    if (entry && (!entry->arguments_readable || !entry->name_readable || entry->name_malformed || entry->name_truncated)) collector.packet->incomplete = 1;
    return status;
}
static NTSTATUS NTAPI event_hook(PHANDLE output, ACCESS_MASK access, POBJECT_ATTRIBUTES attributes) {
    TraceEntry* entry = enter(2, access);
    const NTSTATUS status = forward(event_open.load(std::memory_order_acquire), output, access, attributes, entry);
    if (entry && (!entry->arguments_readable || !entry->name_readable || entry->name_malformed || entry->name_truncated)) collector.packet->incomplete = 1;
    return status;
}

static bool clock_live(TracePacket* packet, uint64_t frequency) {
    LARGE_INTEGER now, observed_frequency;
    if (!QueryPerformanceCounter(&now) || !QueryPerformanceFrequency(&observed_frequency)) {
        const DWORD error = GetLastError();
        packet->setup_stage = 2; packet->setup_error = error; packet->clock_live = 0; return false;
    }
    packet->finished_qpc = static_cast<uint64_t>(now.QuadPart);
    packet->clock_live = now.QuadPart >= 0 && observed_frequency.QuadPart > 0 &&
        static_cast<uint64_t>(observed_frequency.QuadPart) == frequency &&
        static_cast<uint64_t>(now.QuadPart) < packet->original_cutoff_qpc;
    if (!packet->clock_live) { packet->setup_stage = 2; packet->setup_error = ERROR_TIMEOUT; }
    return packet->clock_live != 0;
}

template<class T> static bool load_export(HMODULE module, const char* name, T* target, DWORD* error) {
    const FARPROC address = GetProcAddress(module, name);
    if (!address) { *error = GetLastError(); return false; }
    *target = reinterpret_cast<T>(address);
    return true;
}
struct Image {
    uintptr_t base, end, imports, imports_end, iat, iat_end;
    uint32_t size, timestamp;
};
static bool range(uintptr_t first, size_t bytes, uintptr_t begin, uintptr_t end) {
    return first >= begin && first <= end && bytes <= end - first;
}
static bool readable(uintptr_t first, size_t bytes, const Image& image) {
    if (!range(first, bytes, image.base, image.end)) return false;
    MEMORY_BASIC_INFORMATION memory = {};
    if (VirtualQuery(reinterpret_cast<void*>(first), &memory, sizeof(memory)) != sizeof(memory)) return false;
    const DWORD protection = memory.Protect;
    return memory.State == MEM_COMMIT && memory.Type == MEM_IMAGE &&
        memory.AllocationBase == reinterpret_cast<void*>(image.base) &&
        !(protection & (PAGE_GUARD | PAGE_NOACCESS)) &&
        range(first, bytes, reinterpret_cast<uintptr_t>(memory.BaseAddress),
              reinterpret_cast<uintptr_t>(memory.BaseAddress) + memory.RegionSize);
}
static bool same_name(const char* name, const char* expected, const Image& image, bool fold_case = false) {
    for (size_t index = 0; index < 128; ++index) {
        const uintptr_t address = reinterpret_cast<uintptr_t>(name) + index;
        if (!readable(address, 1, image)) return false;
        const auto fold = [](char value) { return value >= 'A' && value <= 'Z' ? static_cast<char>(value + ('a' - 'A')) : value; };
        if ((fold_case ? fold(name[index]) : name[index]) != (fold_case ? fold(expected[index]) : expected[index])) return false;
        if (!expected[index]) return true;
    }
    return false;
}
static bool bounded_name(uintptr_t name, const Image& image) {
    for (size_t index = 0; index < 128; ++index) {
        if (!readable(name + index, 1, image)) return false;
        if (*reinterpret_cast<const char*>(name + index) == '\0') return true;
    }
    return false;
}
static bool image(HMODULE module, Image* result) {
    __try {
        const uintptr_t base = reinterpret_cast<uintptr_t>(module);
        MEMORY_BASIC_INFORMATION mapped = {};
        if (VirtualQuery(module, &mapped, sizeof(mapped)) != sizeof(mapped) || mapped.State != MEM_COMMIT ||
            mapped.Type != MEM_IMAGE || mapped.AllocationBase != module || (mapped.Protect & (PAGE_GUARD | PAGE_NOACCESS))) return false;
        const auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(module);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0 || dos->e_lfanew > 1024 * 1024) return false;
        const auto nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
            nt->FileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64) ||
            nt->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_IAT) return false;
        const auto size = nt->OptionalHeader.SizeOfImage;
        if (size == 0 || base > UINTPTR_MAX - size) return false;
        Image value = {base, base + size, 0, 0, 0, 0, size, nt->FileHeader.TimeDateStamp};
        if (!readable(reinterpret_cast<uintptr_t>(nt), sizeof(*nt), value)) return false;
        const auto imports = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        const auto iat = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
        if (!imports.VirtualAddress || !iat.VirtualAddress || !imports.Size || !iat.Size ||
            imports.VirtualAddress > size || imports.Size > size - imports.VirtualAddress ||
            iat.VirtualAddress > size || iat.Size > size - iat.VirtualAddress) return false;
        value.imports = base + imports.VirtualAddress; value.imports_end = value.imports + imports.Size;
        value.iat = base + iat.VirtualAddress; value.iat_end = value.iat + iat.Size;
        *result = value; return true;
    } __except(EXCEPTION_EXECUTE_HANDLER) { return false; }
}
struct Discovery {
    Image image;
    TracePacket* packet;
    uint64_t frequency;
    HMODULE ntdll;
    void* directory_original;
    void* event_original;
    void** directory_slot;
    void** event_slot;
    DWORD error;
    bool native_descriptor;
};
static bool bounded_imports(Discovery* discovery) {
    // Validate all normal import descriptors/thunks before the library walks
    // them. Delay imports and instruction scanning are deliberately excluded.
    __try {
        const auto& image = discovery->image;
        size_t functions = 0;
        for (size_t descriptor = 0; descriptor < 256; ++descriptor) {
            if (!clock_live(discovery->packet, discovery->frequency)) { discovery->error = discovery->packet->setup_error; return false; }
            const uintptr_t address = image.imports + descriptor * sizeof(IMAGE_IMPORT_DESCRIPTOR);
            if (!range(address, sizeof(IMAGE_IMPORT_DESCRIPTOR), image.imports, image.imports_end) || !readable(address, sizeof(IMAGE_IMPORT_DESCRIPTOR), image)) return false;
            const auto entry = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(address);
            if (!entry->OriginalFirstThunk) return entry->FirstThunk == 0 && entry->Name == 0 && entry->TimeDateStamp == 0 && entry->ForwarderChain == 0;
            if (!entry->FirstThunk || !entry->Name || !bounded_name(image.base + entry->Name, image) ||
                !range(image.base + entry->FirstThunk, sizeof(void*), image.iat, image.iat_end) ||
                !readable(image.base + entry->FirstThunk, sizeof(void*), image)) return false;
            for (size_t index = 0; index < 4096; ++index) {
                if (++functions > 16384) { discovery->error = ERROR_BUFFER_OVERFLOW; discovery->packet->setup_reason = 6; return false; }
                if (!clock_live(discovery->packet, discovery->frequency)) { discovery->error = discovery->packet->setup_error; return false; }
                const uintptr_t thunk = image.base + entry->OriginalFirstThunk + index * sizeof(IMAGE_THUNK_DATA64);
                if (!readable(thunk, sizeof(IMAGE_THUNK_DATA64), image)) return false;
                const auto name = reinterpret_cast<IMAGE_THUNK_DATA64*>(thunk)->u1.Ordinal;
                if (!name) break;
                const uintptr_t slot = image.base + entry->FirstThunk + index * sizeof(void*);
                if (!range(slot, sizeof(void*), image.iat, image.iat_end) || !readable(slot, sizeof(void*), image)) return false;
                if (!IMAGE_SNAP_BY_ORDINAL64(name) && (name > UINT32_MAX ||
                    !readable(image.base + static_cast<uint32_t>(name), sizeof(WORD) + 1, image) ||
                    !bounded_name(image.base + static_cast<uint32_t>(name) + sizeof(WORD), image))) return false;
                if (index == 4095) { discovery->error = ERROR_BUFFER_OVERFLOW; discovery->packet->setup_reason = 6; return false; }
            }
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) { return false; }
    discovery->error = ERROR_BUFFER_OVERFLOW; discovery->packet->setup_reason = 6;
    return false;
}
static BOOL CALLBACK import_file(void* context, HMODULE module, LPCSTR name) {
    auto* state = static_cast<Discovery*>(context);
    if (!name) { state->packet->iat.discovery_complete = state->error == ERROR_SUCCESS; return FALSE; }
    if (state->error != ERROR_SUCCESS) return FALSE;
    if (++state->packet->iat.descriptor_count > 256) { state->error = ERROR_BUFFER_OVERFLOW; state->packet->setup_reason = 6; return FALSE; }
    if (!clock_live(state->packet, state->frequency)) { state->error = state->packet->setup_error; return FALSE; }
    state->native_descriptor = same_name(name, "ntdll.dll", state->image, true);
    if (state->native_descriptor && module != state->ntdll) { state->error = ERROR_INVALID_OWNER; return FALSE; }
    return TRUE;
}
static BOOL CALLBACK import_function(void* context, DWORD, LPCSTR name, void** slot) {
    auto* state = static_cast<Discovery*>(context);
    if (!slot) return state->error == ERROR_SUCCESS;
    if (state->error != ERROR_SUCCESS) return FALSE;
    if (++state->packet->iat.function_count > 16384) { state->error = ERROR_BUFFER_OVERFLOW; state->packet->setup_reason = 6; return FALSE; }
    if (!clock_live(state->packet, state->frequency)) { state->error = state->packet->setup_error; return FALSE; }
    if (!state->native_descriptor || !name) return TRUE;
    const bool directory = same_name(name, "NtOpenDirectoryObject", state->image);
    const bool event = same_name(name, "NtOpenEvent", state->image);
    if (!directory && !event) return TRUE;
    if (!range(reinterpret_cast<uintptr_t>(slot), sizeof(void*), state->image.iat, state->image.iat_end) ||
        reinterpret_cast<uintptr_t>(slot) % alignof(void*) != 0) { state->error = ERROR_INVALID_ADDRESS; state->packet->setup_reason = 5; return FALSE; }
    uint32_t& matches = directory ? state->packet->iat.directory_matches : state->packet->iat.event_matches;
    if (++matches != 1) { state->error = ERROR_DUP_NAME; state->packet->setup_reason = 3; return FALSE; }
    const auto expected = directory ? state->directory_original : state->event_original;
    if (*slot != expected) { state->error = ERROR_INVALID_DATA; state->packet->setup_reason = 4; return FALSE; }
    if (directory) state->directory_slot = slot; else state->event_slot = slot;
    return TRUE;
}
struct Page { void* base; SIZE_T size; DWORD original; bool writable; };
static bool data_page(void** slot, const Image& image, Page* page) {
    MEMORY_BASIC_INFORMATION memory = {};
    const auto address = reinterpret_cast<uintptr_t>(slot);
    if (address % alignof(void*) || !range(address, sizeof(void*), image.iat, image.iat_end) ||
        VirtualQuery(slot, &memory, sizeof(memory)) != sizeof(memory)) return false;
    SYSTEM_INFO system = {}; GetSystemInfo(&system);
    const auto size = static_cast<uintptr_t>(system.dwPageSize);
    if (!size || address / size != (address + sizeof(void*) - 1) / size || memory.State != MEM_COMMIT || memory.Type != MEM_IMAGE ||
        memory.AllocationBase != reinterpret_cast<void*>(image.base) ||
        (memory.Protect != PAGE_READONLY && memory.Protect != PAGE_READWRITE && memory.Protect != PAGE_WRITECOPY)) return false;
    const auto base = address - address % size;
    if (!range(base, size, image.base, image.end)) return false;
    *page = {reinterpret_cast<void*>(base), size, memory.Protect, false}; return true;
}
static void restore_pages(Page (&pages)[2], size_t count, TracePacket* packet) {
    auto* record = &packet->iat;
    for (size_t index = 0; index < count; ++index) {
        if (!pages[index].writable) continue;
        DWORD replaced = 0;
        if (!VirtualProtect(pages[index].base, pages[index].size, pages[index].original, &replaced)) {
            const DWORD error = GetLastError(); record->protection_error = error;
            if (!packet->setup_error) packet->setup_error = error;
            __fastfail(FAST_FAIL_FATAL_APP_EXIT);
        }
        if (replaced != PAGE_READWRITE) {
            record->protection_error = ERROR_RETRY;
            if (!packet->setup_error) packet->setup_error = ERROR_RETRY;
            __fastfail(FAST_FAIL_FATAL_APP_EXIT);
        }
        pages[index].writable = false;
    }
    record->protections_restored = 1;
}
static DWORD publish(Discovery& state, Page (&pages)[2], size_t page_count) {
    auto* record = &state.packet->iat;
    for (size_t index = 0; index < page_count; ++index) {
        DWORD original = 0;
        if (!VirtualProtect(pages[index].base, pages[index].size, PAGE_READWRITE, &original)) {
            const DWORD error = GetLastError(); record->protection_error = error;
            state.packet->setup_error = error;
            restore_pages(pages, page_count, state.packet); return error;
        }
        pages[index].writable = true;
        if (original != pages[index].original) {
            // Restore what VirtualProtect actually replaced, never a stale
            // preflight value, then refuse the changed protection ownership.
            pages[index].original = original;
            record->protection_error = ERROR_RETRY;
            state.packet->setup_error = ERROR_RETRY;
            restore_pages(pages, page_count, state.packet); return ERROR_RETRY;
        }
    }
    void* expected[2] = {state.directory_original, state.event_original};
    void* hooks[2] = {reinterpret_cast<void*>(directory_hook), reinterpret_cast<void*>(event_hook)};
    void** slots[2] = {state.directory_slot, state.event_slot};
    DWORD error = ERROR_SUCCESS;
    size_t installed = 0;
    for (; installed < 2; ++installed) {
        state.packet->setup_stage = installed == 0 ? 9 : 10;
        if (InterlockedCompareExchangePointer(slots[installed], hooks[installed], expected[installed]) != expected[installed]) {
            error = ERROR_RETRY; state.packet->setup_reason = 7; break;
        }
        if (installed == 0) record->published_directory = 1; else record->published_event = 1;
    }
    if (error != ERROR_SUCCESS) {
        state.packet->setup_error = error;
        while (installed > 0) {
            --installed;
            if (InterlockedCompareExchangePointer(slots[installed], expected[installed], hooks[installed]) != hooks[installed]) {
                record->rollback_error = ERROR_RETRY; __fastfail(FAST_FAIL_FATAL_APP_EXIT);
            }
            if (installed == 0) record->published_directory = 0; else record->published_event = 0;
        }
    }
    restore_pages(pages, page_count, state.packet);
    return error;
}
static bool publication_mock() {
    // CI self-check only: exercise the actual publication/rollback body on
    // private owned DATA slots. These sentinel values are never called.
    SYSTEM_INFO system = {}; GetSystemInfo(&system);
    void* allocation = VirtualAlloc(nullptr, system.dwPageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!allocation) return false;
    auto slots = static_cast<void**>(allocation);
    bool valid = true;
    for (uint32_t test = 0; test < 3 && valid; ++test) {
        DWORD replaced = 0;
        if (!VirtualProtect(allocation, system.dwPageSize, PAGE_READWRITE, &replaced)) { valid = false; break; }
        void* first = reinterpret_cast<void*>(static_cast<uintptr_t>(0x1000));
        void* second = reinterpret_cast<void*>(static_cast<uintptr_t>(0x2000));
        void* foreign = reinterpret_cast<void*>(static_cast<uintptr_t>(0x3000));
        slots[0] = test == 2 ? foreign : first;
        slots[1] = test == 1 ? foreign : second;
        if (!VirtualProtect(allocation, system.dwPageSize, PAGE_READONLY, &replaced)) { valid = false; break; }
        TracePacket packet = {};
        Discovery state = {}; state.packet = &packet;
        state.directory_original = first; state.event_original = second;
        state.directory_slot = &slots[0]; state.event_slot = &slots[1];
        Page pages[2] = {{allocation, system.dwPageSize, PAGE_READONLY, false}, {}};
        const DWORD error = publish(state, pages, 1);
        MEMORY_BASIC_INFORMATION observed = {};
        valid = VirtualQuery(allocation, &observed, sizeof(observed)) == sizeof(observed) &&
            observed.Protect == PAGE_READONLY && packet.iat.protections_restored == 1 &&
            packet.iat.rollback_error == 0 && packet.iat.protection_error == 0;
        if (test == 0) valid = valid && error == ERROR_SUCCESS &&
            slots[0] == reinterpret_cast<void*>(directory_hook) && slots[1] == reinterpret_cast<void*>(event_hook) &&
            packet.iat.published_directory == 1 && packet.iat.published_event == 1;
        else valid = valid && error == ERROR_RETRY && slots[0] == (test == 2 ? foreign : first) &&
            slots[1] == (test == 1 ? foreign : second) &&
            packet.iat.published_directory == 0 && packet.iat.published_event == 0;
    }
    return VirtualFree(allocation, 0, MEM_RELEASE) != FALSE && valid;
}
static DWORD install(TracePacket* packet, uint64_t frequency) {
    packet->setup_stage = 3;
    DWORD error = ERROR_PROC_NOT_FOUND;
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return GetLastError();
    Open directory = nullptr, event = nullptr;
    if (!load_export(ntdll, "NtOpenDirectoryObject", &directory, &error) || !load_export(ntdll, "NtOpenEvent", &event, &error)) return error;
    HMODULE pinned_ntdll = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
        reinterpret_cast<LPCWSTR>(directory), &pinned_ntdll)) return GetLastError();
    if (pinned_ntdll != ntdll) return ERROR_INVALID_OWNER;
    packet->setup_stage = 4;
    HMODULE kernel = GetModuleHandleW(L"kernel32.dll");
    if (!kernel) return GetLastError();
    const auto named = GetProcAddress(kernel, "OpenEventW");
    if (!named) return GetLastError();
    if (reinterpret_cast<void*>(named) != reinterpret_cast<void*>(original_win32)) { packet->setup_reason = 9; return ERROR_INVALID_ADDRESS; }
    HMODULE owner = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
        reinterpret_cast<LPCWSTR>(original_win32), &owner)) return GetLastError();
    packet->iat.owner_pinned = 1; packet->iat.owner_base = reinterpret_cast<uintptr_t>(owner);
    packet->iat.original_open_event = reinterpret_cast<uintptr_t>(original_win32);
    packet->setup_stage = 5;
    Image mapped = {};
    if (!image(owner, &mapped)) { packet->setup_reason = 5; return ERROR_BAD_EXE_FORMAT; }
    packet->iat.owner_size = mapped.size; packet->iat.owner_timestamp = mapped.timestamp;
    packet->iat.normal_iat_start = mapped.iat; packet->iat.normal_iat_end = mapped.iat_end;
    Discovery state = {mapped, packet, frequency, ntdll, reinterpret_cast<void*>(directory), reinterpret_cast<void*>(event), nullptr, nullptr, ERROR_SUCCESS, false};
    packet->setup_stage = 6;
    if (!bounded_imports(&state)) {
        packet->iat.callback_error = state.error;
        if (state.error != ERROR_SUCCESS) return state.error;
        packet->setup_reason = 5; return ERROR_BAD_EXE_FORMAT;
    }
    const BOOL enumerated = DetourEnumerateImportsEx(owner, &state, import_file, import_function);
    const DWORD enumeration_error = GetLastError();
    packet->iat.callback_error = state.error;
    if (!enumerated) return enumeration_error != ERROR_SUCCESS ? enumeration_error : ERROR_INVALID_DATA;
    if (state.error != ERROR_SUCCESS) return state.error;
    if (!packet->iat.discovery_complete) { packet->setup_reason = 10; return ERROR_INVALID_DATA; }
    if (!state.directory_slot || !state.event_slot) { packet->setup_reason = 2; return ERROR_PROC_NOT_FOUND; }
    if (state.directory_slot == state.event_slot) return ERROR_INVALID_ADDRESS;
    packet->iat.directory_slot = reinterpret_cast<uintptr_t>(state.directory_slot); packet->iat.event_slot = reinterpret_cast<uintptr_t>(state.event_slot);
    packet->iat.directory_original = reinterpret_cast<uintptr_t>(directory); packet->iat.event_original = reinterpret_cast<uintptr_t>(event);
    packet->setup_stage = 7;
    Page pages[2] = {};
    if (!data_page(state.directory_slot, mapped, &pages[0]) || !data_page(state.event_slot, mapped, &pages[1])) { packet->setup_reason = 5; return ERROR_INVALID_ADDRESS; }
    const size_t count = pages[0].base == pages[1].base ? 1 : 2;
    if (count == 1 && pages[0].original != pages[1].original) return ERROR_RETRY;
    if (!clock_live(packet, frequency)) return ERROR_TIMEOUT;
    directory_open.store(directory, std::memory_order_release); event_open.store(event, std::memory_order_release);
    packet->setup_stage = 8;
    error = publish(state, pages, count);
    if (error != ERROR_SUCCESS && packet->iat.protection_error && !packet->setup_reason) packet->setup_reason = 8;
    if (error == ERROR_SUCCESS && !clock_live(packet, frequency)) return ERROR_TIMEOUT;
    if (error == ERROR_SUCCESS) packet->setup_stage = 1;
    return error;
}
extern "C" void memcordon_gate_trace_prepare(TracePacket* packet, uint64_t cutoff, uint64_t frequency) {
    packet->version = 3; packet->original_cutoff_qpc = cutoff; packet->lifetime_policy = 1;
    packet->iat.strategy = 1;
    if (!clock_live(packet, frequency)) { packet->incomplete = 1; return; }
    packet->started_qpc = packet->finished_qpc;
    const LONG previous = InterlockedCompareExchange(&installation, 1, 0);
    if (previous != 0) {
        packet->setup_stage = previous == 2 ? 1 : previous == 3 ? installation_stage : 13;
        packet->setup_error = previous == 2 ? 0 : previous == 3 ? installation_error : ERROR_BUSY;
        packet->attached_directory = packet->attached_event = previous == 2;
        packet->incomplete = previous != 2;
        if (previous == 2 || previous == 3) {
            packet->setup_reason = installation_reason; packet->original_current_thread_id = installation_current_thread;
            packet->iat = installation_iat;
        } else packet->setup_reason = 1;
        return;
    }
    packet->original_current_thread_id = GetCurrentThreadId();
    const DWORD observed_error = install(packet, frequency);
    const DWORD error = observed_error == ERROR_SUCCESS && packet->setup_stage != 1 ? ERROR_INVALID_DATA : observed_error;
    packet->setup_error = error; packet->incomplete = error != ERROR_SUCCESS;
    packet->attached_directory = packet->iat.published_directory; packet->attached_event = packet->iat.published_event;
    installation_stage = packet->setup_stage; installation_error = error;
    installation_reason = packet->setup_reason; installation_current_thread = packet->original_current_thread_id;
    installation_iat = packet->iat;
    InterlockedExchange(&installation, error == ERROR_SUCCESS ? 2 : 3);
}

extern "C" void* memcordon_gate_trace_call(TracePacket* packet, const uint16_t* name, uint32_t* native_error, uint32_t* called) {
    const DWORD incoming = GetLastError();
    if (packet->called) { *called = 0; *native_error = ERROR_INVALID_OPERATION; return nullptr; }
    LARGE_INTEGER now;
    if (!QueryPerformanceCounter(&now)) {
        const DWORD error = GetLastError();
        packet->clock_live = 0; packet->incomplete = 1; *called = 0; *native_error = error; return nullptr;
    }
    if (now.QuadPart < 0 || static_cast<uint64_t>(now.QuadPart) >= packet->original_cutoff_qpc) {
        packet->clock_live = 0; packet->incomplete = 1; *called = 0; *native_error = ERROR_TIMEOUT; return nullptr;
    }
    collector.thread = GetCurrentThreadId();
    collector.packet = packet->setup_stage == 1 ? packet : nullptr;
    packet->armed_call_count = collector.packet ? 1 : 0;
    SetLastError(incoming);
    HANDLE event = original_win32(SYNCHRONIZE, FALSE, reinterpret_cast<LPCWSTR>(name));
    const DWORD error = GetLastError(); // Before disarming, clocks, or cleanup.
    collector.packet = nullptr;
    *called = packet->called = 1;
    *native_error = packet->outer_error = error;
    packet->outer_opened = event != nullptr;
    if (QueryPerformanceCounter(&now) && now.QuadPart >= 0) {
        packet->finished_qpc = static_cast<uint64_t>(now.QuadPart);
        packet->clock_live = packet->finished_qpc < packet->original_cutoff_qpc;
    } else { packet->clock_live = 0; packet->incomplete = 1; }
    SetLastError(error);
    return event;
}

struct Mock { PHANDLE output; ACCESS_MASK access; POBJECT_ATTRIBUTES attributes; NTSTATUS status; DWORD error; uint32_t calls; bool same; };
static __declspec(thread) Mock* mock = nullptr;
static NTSTATUS NTAPI mock_open(PHANDLE output, ACCESS_MASK access, POBJECT_ATTRIBUTES attributes) {
    mock->calls++;
    mock->same = output == mock->output && access == mock->access && attributes == mock->attributes && GetLastError() == 77;
    if (mock->status >= 0) *output = reinterpret_cast<HANDLE>(static_cast<uintptr_t>(0x1234));
    SetLastError(mock->error);
    return mock->status;
}
extern "C" uint32_t memcordon_gate_trace_mock() {
    const NTSTATUS statuses[] = {static_cast<NTSTATUS>(0), static_cast<NTSTATUS>(0xc0000022)};
    for (NTSTATUS status : statuses) {
        HANDLE output = nullptr;
        OBJECT_ATTRIBUTES attributes = {}; attributes.Length = sizeof(attributes);
        Mock observation = {&output, SYNCHRONIZE, &attributes, status, 123, 0, false};
        mock = &observation;
        TraceEntry entry = {};
        SetLastError(77);
        const NTSTATUS observed = forward(mock_open, &output, SYNCHRONIZE, &attributes, &entry);
        const DWORD error = GetLastError();
        mock = nullptr;
        if (observed != status || error != 123 || observation.calls != 1 || !observation.same || entry.native_status != status || !entry.returned) return 0;
    }
    return publication_mock() ? 1 : 0;
}
