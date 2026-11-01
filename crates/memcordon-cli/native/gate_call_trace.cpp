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
static RouteRecord installation_route = {};
struct Collector { TracePacket* packet; DWORD thread; };
// POD static TLS is initialized before user code, never lazily in a hook.
static __declspec(thread) Collector collector = {nullptr, 0};
// These references belong to the current control caller until explicit release.
// They never replace the caller's output or grant access beyond that output.
static __declspec(thread) HANDLE retained_directories[8] = {};
static __declspec(thread) DWORD retained_errors[8] = {};
static __declspec(thread) TracePacket* retained_owner = nullptr;

extern "C" void memcordon_gate_trace_release_directories(TracePacket* owner) {
    if (owner != retained_owner) return;
    const DWORD error = GetLastError();
    for (size_t index = 0; index < 8; ++index) {
        if (retained_directories[index]) CloseHandle(retained_directories[index]);
        retained_directories[index] = nullptr;
        retained_errors[index] = 0;
    }
    retained_owner = nullptr;
    SetLastError(error);
}
extern "C" void memcordon_gate_trace_directories(TracePacket* owner, uint64_t* handles, uint32_t* errors) {
    for (size_t index = 0; index < 8; ++index) {
        handles[index] = owner == retained_owner ? reinterpret_cast<uintptr_t>(retained_directories[index]) : 0;
        errors[index] = owner == retained_owner ? retained_errors[index] : ERROR_INVALID_OWNER;
    }
}

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
    const DWORD original_error = GetLastError();
    if (entry && status >= 0 && entry->output_handle_readable && entry->output_handle_returned) {
        const size_t index = entry->sequence - 1;
        if (retained_owner == collector.packet) {
            LARGE_INTEGER now;
            if (!QueryPerformanceCounter(&now)) retained_errors[index] = GetLastError();
            else if (now.QuadPart < 0 || static_cast<uint64_t>(now.QuadPart) >= collector.packet->original_cutoff_qpc)
                retained_errors[index] = ERROR_TIMEOUT;
            else if (!DuplicateHandle(GetCurrentProcess(), reinterpret_cast<HANDLE>(static_cast<uintptr_t>(entry->raw_output)),
                                      GetCurrentProcess(), &retained_directories[index], 0, FALSE, DUPLICATE_SAME_ACCESS))
                retained_errors[index] = GetLastError();
        }
    }
    if (entry && (!entry->arguments_readable || !entry->name_readable || entry->name_malformed || entry->name_truncated)) collector.packet->incomplete = 1;
    SetLastError(original_error);
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
static bool same_name(const char* name, const char* expected, const Image& image) {
    for (size_t index = 0; index < 128; ++index) {
        const uintptr_t address = reinterpret_cast<uintptr_t>(name) + index;
        if (!readable(address, 1, image)) return false;
        if (name[index] != expected[index]) return false;
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
    void* directory_original;
    void* event_original;
    void** directory_slot;
    void** event_slot;
    DWORD error;
    RouteNode* node;
    LPCSTR descriptor_name;
    HMODULE descriptor_module;
    void** open_slot;
    void* open_target;
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
    ++state->packet->iat.descriptor_count;
    if (++state->packet->route.callbacks_total_descriptors > 256) { state->error = ERROR_BUFFER_OVERFLOW; state->packet->setup_reason = 6; return FALSE; }
    if (!clock_live(state->packet, state->frequency)) { state->error = state->packet->setup_error; return FALSE; }
    state->descriptor_name = name; state->descriptor_module = module;
    return TRUE;
}
static BOOL CALLBACK import_function(void* context, DWORD, LPCSTR name, void** slot) {
    auto* state = static_cast<Discovery*>(context);
    if (!slot) return state->error == ERROR_SUCCESS;
    if (state->error != ERROR_SUCCESS) return FALSE;
    ++state->packet->iat.function_count;
    if (++state->packet->route.callbacks_total_functions > 16384) { state->error = ERROR_BUFFER_OVERFLOW; state->packet->setup_reason = 6; return FALSE; }
    if (!clock_live(state->packet, state->frequency)) { state->error = state->packet->setup_error; return FALSE; }
    if (!name) return TRUE;
    if (same_name(name, "OpenEventW", state->image)) {
        ++state->node->open_event_matches;
        if (!range(reinterpret_cast<uintptr_t>(slot), sizeof(void*), state->image.iat, state->image.iat_end) ||
            reinterpret_cast<uintptr_t>(slot) % alignof(void*) || !*slot) {
            state->error = ERROR_INVALID_ADDRESS; return FALSE;
        }
        if (state->node->open_event_matches == 1) { state->open_slot = slot; state->open_target = *slot; }
    }
    const bool directory = same_name(name, "NtOpenDirectoryObject", state->image);
    const bool event = same_name(name, "NtOpenEvent", state->image);
    if (!directory && !event) return TRUE;
    const uint32_t names = directory ? ++state->node->directory_name_matches : ++state->node->event_name_matches;
    if (names != 1) { state->error = ERROR_DUP_NAME; state->packet->setup_reason = 3; return FALSE; }
    if (!range(reinterpret_cast<uintptr_t>(slot), sizeof(void*), state->image.iat, state->image.iat_end) ||
        reinterpret_cast<uintptr_t>(slot) % alignof(void*) != 0) { state->error = ERROR_INVALID_ADDRESS; state->packet->setup_reason = 5; return FALSE; }
    uint32_t& matches = directory ? state->packet->iat.directory_matches : state->packet->iat.event_matches;
    const auto expected = directory ? state->directory_original : state->event_original;
    if (*slot != expected) { state->error = ERROR_INVALID_DATA; state->packet->setup_reason = 4; return FALSE; }
    ++matches;
    auto* route = &state->packet->route;
    auto* bytes = directory ? route->directory_descriptor : route->event_descriptor;
    auto* length = directory ? &route->directory_descriptor_bytes : &route->event_descriptor_bytes;
    auto* truncated = directory ? &route->directory_descriptor_truncated : &route->event_descriptor_truncated;
    for (size_t index = 0; index < 64; ++index) {
        if (!state->descriptor_name[index]) break;
        bytes[(*length)++] = static_cast<uint8_t>(state->descriptor_name[index]);
    }
    *truncated = *length == 64 && state->descriptor_name[64] != '\0';
    if (directory) route->directory_descriptor_module = reinterpret_cast<uintptr_t>(state->descriptor_module);
    else route->event_descriptor_module = reinterpret_cast<uintptr_t>(state->descriptor_module);
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
static uint32_t machine() {
#if defined(_M_ARM64) || defined(__aarch64__)
    return IMAGE_FILE_MACHINE_ARM64;
#elif defined(_M_X64) || defined(__x86_64__)
    return IMAGE_FILE_MACHINE_AMD64;
#else
#error Unsupported native entry architecture
#endif
}
static bool entry_bytes(const Image& mapped, RouteNode* node, bool compare) {
    __try {
        MEMORY_BASIC_INFORMATION memory = {};
        const uintptr_t entry = static_cast<uintptr_t>(node->entry);
        if (!range(entry, 1, mapped.base, mapped.end) ||
            VirtualQuery(reinterpret_cast<void*>(entry), &memory, sizeof(memory)) != sizeof(memory) ||
            memory.State != MEM_COMMIT || memory.Type != MEM_IMAGE || memory.AllocationBase != reinterpret_cast<void*>(mapped.base) ||
            (memory.Protect != PAGE_EXECUTE_READ && memory.Protect != PAGE_EXECUTE_READWRITE && memory.Protect != PAGE_EXECUTE_WRITECOPY)) return false;
        const auto region = reinterpret_cast<uintptr_t>(memory.BaseAddress);
        if (memory.RegionSize > UINTPTR_MAX - region) return false;
        const auto end = region + memory.RegionSize < mapped.end ? region + memory.RegionSize : mapped.end;
        size_t length = end - entry;
        if (length > sizeof(node->entry_bytes)) length = sizeof(node->entry_bytes);
        if (length < (machine() == IMAGE_FILE_MACHINE_ARM64 ? 12u : 6u)) return false;
        if (compare && length != node->entry_byte_count) return false;
        for (size_t index = 0; index < length; ++index) {
            const auto byte = reinterpret_cast<const uint8_t*>(entry)[index];
            if (compare) { if (byte != node->entry_bytes[index]) return false; }
            else node->entry_bytes[index] = byte;
        }
        if (!compare) { node->entry_bytes_read = 1; node->entry_byte_count = static_cast<uint32_t>(length); }
        return true;
    } __except(EXCEPTION_EXECUTE_HANDLER) { return false; }
}
static bool capture_node(HMODULE owner, void* entry, RouteNode* node, Image* mapped) {
    node->owner_base = reinterpret_cast<uintptr_t>(owner); node->entry = reinterpret_cast<uintptr_t>(entry);
    if (!image(owner, mapped)) return false;
    node->owner_size = mapped->size; node->owner_timestamp = mapped->timestamp;
    WCHAR name[96] = {};
    const DWORD length = GetModuleFileNameW(owner, name, static_cast<DWORD>(sizeof(name) / sizeof(name[0])));
    node->module_name_units = length < 96 ? length : 96; node->module_name_truncated = length >= 96;
    for (size_t index = 0; index < node->module_name_units; ++index) node->module_name[index] = name[index];
    return entry_bytes(*mapped, node, false);
}
static bool route_unchanged(TracePacket* packet) {
    __try {
        packet->route.route_revalidated = 0;
        if (!packet->route.node_count || packet->route.node_count > 2) return false;
        for (uint32_t index = 0; index < packet->route.node_count; ++index) {
            auto* node = &packet->route.nodes[index];
            node->entry_revalidated = 0; node->slot_revalidated = 0;
            Image mapped = {};
            if (!image(reinterpret_cast<HMODULE>(static_cast<uintptr_t>(node->owner_base)), &mapped) ||
                mapped.size != node->owner_size || mapped.timestamp != node->owner_timestamp || !entry_bytes(mapped, node, true)) return false;
            node->entry_revalidated = 1;
            if (index + 1 < packet->route.node_count) {
                const auto slot = static_cast<uintptr_t>(node->delegation_slot);
                if (slot % alignof(void*) || !range(slot, sizeof(void*), mapped.iat, mapped.iat_end) || !readable(slot, sizeof(void*), mapped) ||
                    *reinterpret_cast<void**>(slot) != reinterpret_cast<void*>(static_cast<uintptr_t>(node->delegation_target)) ||
                    node->delegation_target != packet->route.nodes[index + 1].entry) return false;
                node->slot_revalidated = 1;
            }
        }
        if (packet->iat.published_directory && packet->iat.published_event &&
            (*reinterpret_cast<void**>(static_cast<uintptr_t>(packet->iat.directory_slot)) != reinterpret_cast<void*>(directory_hook) ||
             *reinterpret_cast<void**>(static_cast<uintptr_t>(packet->iat.event_slot)) != reinterpret_cast<void*>(event_hook))) return false;
        packet->route.route_revalidated = 1; return true;
    } __except(EXCEPTION_EXECUTE_HANDLER) { return false; }
}
static uint32_t edge_binding(const Discovery& state, uint64_t decoded) {
    if (state.node->open_event_matches > 1) return 4;
    if (state.node->open_event_matches != 1 || !state.open_slot || !state.open_target || decoded != reinterpret_cast<uintptr_t>(state.open_slot)) return 3;
    const auto slot = reinterpret_cast<uintptr_t>(state.open_slot);
    return slot % alignof(void*) || !range(slot, sizeof(void*), state.image.iat, state.image.iat_end) ? 9 : 0;
}
static bool edge_current(const Discovery& state) {
    __try { return state.open_slot && *state.open_slot == state.open_target; }
    __except(EXCEPTION_EXECUTE_HANDLER) { return false; }
}
static uint32_t target_binding(HMODULE owner, void* entry, HMODULE next, void* target, void* exported) {
    if (!next || next == owner || !target || target == entry) return 6;
    return exported != target ? 7 : 0;
}
static bool route_mock() {
    // Exercise the actual decoder and binding predicates with owned scalar
    // data only; these synthetic facts never substitute for the real route.
    const uint8_t x64[] = {0xff, 0x25, 0xfa, 0xff, 0xff, 0xff};
    const uint8_t arm64[] = {0x10, 0x00, 0x00, 0x90, 0x10, 0x06, 0x40, 0xf9, 0x00, 0x02, 0x1f, 0xd6};
    uint64_t decoded = 0;
    if (memcordon_decode_import_entry(IMAGE_FILE_MACHINE_AMD64, 0x2000, x64, sizeof(x64), &decoded) || decoded != 0x2000 ||
        memcordon_decode_import_entry(IMAGE_FILE_MACHINE_ARM64, 0x2000, arm64, sizeof(arm64), &decoded) || decoded != 0x2008 ||
        memcordon_decode_import_entry(IMAGE_FILE_MACHINE_AMD64, 0x2000, x64, 5, &decoded) != 2) return false;
    void* value = reinterpret_cast<void*>(static_cast<uintptr_t>(0x5000));
    RouteNode node = {}; node.open_event_matches = 1;
    Discovery state = {}; state.node = &node; state.open_slot = &value; state.open_target = value;
    state.image.iat = reinterpret_cast<uintptr_t>(&value); state.image.iat_end = state.image.iat + sizeof(value);
    if (edge_binding(state, state.image.iat) || !edge_current(state)) return false;
    node.open_event_matches = 0; if (edge_binding(state, state.image.iat) != 3) return false;
    node.open_event_matches = 2; if (edge_binding(state, state.image.iat) != 4) return false;
    node.open_event_matches = 1; if (edge_binding(state, state.image.iat + 8) != 3) return false;
    --state.image.iat_end; if (edge_binding(state, state.image.iat) != 9) return false;
    ++state.image.iat_end; value = nullptr; if (edge_current(state)) return false;
    const auto owner = reinterpret_cast<HMODULE>(static_cast<uintptr_t>(0x1000));
    const auto next = reinterpret_cast<HMODULE>(static_cast<uintptr_t>(0x4000));
    const auto entry = reinterpret_cast<void*>(static_cast<uintptr_t>(0x1100));
    const auto target = reinterpret_cast<void*>(static_cast<uintptr_t>(0x4100));
    return target_binding(owner, entry, next, target, target) == 0 &&
        target_binding(owner, entry, owner, target, target) == 6 &&
        target_binding(owner, entry, next, entry, entry) == 6 &&
        target_binding(owner, entry, next, target, entry) == 7;
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
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
        reinterpret_cast<LPCWSTR>(event), &pinned_ntdll)) return GetLastError();
    if (pinned_ntdll != ntdll) return ERROR_INVALID_OWNER;
    packet->setup_stage = 4;
    HMODULE kernel = GetModuleHandleW(L"kernel32.dll");
    if (!kernel) return GetLastError();
    const auto named = GetProcAddress(kernel, "OpenEventW");
    if (!named) return GetLastError();
    if (reinterpret_cast<void*>(named) != reinterpret_cast<void*>(original_win32)) { packet->setup_reason = 9; return ERROR_INVALID_ADDRESS; }
    packet->route.original_owner_export_equal = 1;
    HMODULE owner = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
        reinterpret_cast<LPCWSTR>(original_win32), &owner)) return GetLastError();
    void* selected_entry = reinterpret_cast<void*>(original_win32);
    Discovery state = {};
    Image mapped = {};
    packet->route.node_limit = 2;
    for (uint32_t index = 0; index < 2; ++index) {
        if (!clock_live(packet, frequency)) { packet->route.route_reason = 10; return packet->setup_error; }
        packet->setup_stage = 5;
        auto* node = &packet->route.nodes[index]; packet->route.node_count = index + 1;
        if (!capture_node(owner, selected_entry, node, &mapped)) { packet->route.route_reason = 8; packet->setup_reason = 5; return ERROR_BAD_EXE_FORMAT; }
        packet->iat = {};
        packet->iat.strategy = 1; packet->iat.owner_pinned = 1; packet->iat.owner_base = mapped.base;
        packet->iat.original_open_event = reinterpret_cast<uintptr_t>(original_win32);
        packet->iat.owner_size = mapped.size; packet->iat.owner_timestamp = mapped.timestamp;
        packet->iat.normal_iat_start = mapped.iat; packet->iat.normal_iat_end = mapped.iat_end;
        packet->route.directory_descriptor_module = packet->route.event_descriptor_module = 0;
        packet->route.directory_descriptor_bytes = packet->route.event_descriptor_bytes = 0;
        packet->route.directory_descriptor_truncated = packet->route.event_descriptor_truncated = 0;
        for (size_t byte = 0; byte < 64; ++byte) packet->route.directory_descriptor[byte] = packet->route.event_descriptor[byte] = 0;
        state = {}; state.image = mapped; state.packet = packet; state.frequency = frequency;
        state.directory_original = reinterpret_cast<void*>(directory); state.event_original = reinterpret_cast<void*>(event); state.node = node;
        packet->setup_stage = 6;
        if (!bounded_imports(&state)) {
            packet->iat.callback_error = state.error;
            if (state.error != ERROR_SUCCESS) return state.error;
            packet->setup_reason = 5; return ERROR_BAD_EXE_FORMAT;
        }
        const BOOL enumerated = DetourEnumerateImportsEx(owner, &state, import_file, import_function);
        const DWORD enumeration_error = GetLastError(); packet->iat.callback_error = state.error;
        if (!enumerated) return enumeration_error != ERROR_SUCCESS ? enumeration_error : ERROR_INVALID_DATA;
        if (state.error != ERROR_SUCCESS) return state.error;
        if (!packet->iat.discovery_complete) { packet->setup_reason = 10; return ERROR_INVALID_DATA; }
        if (state.directory_slot && state.event_slot) break;
        if (index != 0) { packet->route.route_reason = 1; packet->setup_reason = 2; return ERROR_PROC_NOT_FOUND; }
        uint64_t decoded_slot = 0;
        node->decode_kind = machine() == IMAGE_FILE_MACHINE_ARM64 ? 2 : 1;
        node->decode_error = memcordon_decode_import_entry(machine(), node->entry, node->entry_bytes, node->entry_byte_count, &decoded_slot);
        if (node->decode_error) { packet->route.route_reason = 2; packet->setup_reason = 2; return ERROR_NOT_SUPPORTED; }
        const auto binding = edge_binding(state, decoded_slot);
        if (binding) { packet->route.route_reason = binding; packet->setup_reason = 2; return ERROR_INVALID_ADDRESS; }
        node->delegation_slot = decoded_slot; node->delegation_target = reinterpret_cast<uintptr_t>(state.open_target);
        if (!edge_current(state)) { packet->route.route_reason = 5; return ERROR_RETRY; }
        HMODULE next = nullptr;
        if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
            reinterpret_cast<LPCWSTR>(state.open_target), &next)) return GetLastError();
        if (next == owner || state.open_target == selected_entry) { packet->route.route_reason = 6; return ERROR_INVALID_ADDRESS; }
        const auto implementation = GetProcAddress(next, "OpenEventW");
        if (!implementation) { const auto original_error = GetLastError(); packet->route.route_reason = 7; return original_error; }
        const auto target = target_binding(owner, selected_entry, next, state.open_target, reinterpret_cast<void*>(implementation));
        if (target) { packet->route.route_reason = target; return ERROR_INVALID_ADDRESS; }
        owner = next; selected_entry = state.open_target; packet->route.hop_count = 1;
    }
    if (state.directory_slot == state.event_slot) return ERROR_INVALID_ADDRESS;
    packet->iat.directory_slot = reinterpret_cast<uintptr_t>(state.directory_slot); packet->iat.event_slot = reinterpret_cast<uintptr_t>(state.event_slot);
    packet->iat.directory_original = reinterpret_cast<uintptr_t>(directory); packet->iat.event_original = reinterpret_cast<uintptr_t>(event);
    packet->setup_stage = 7;
    Page pages[2] = {};
    if (!data_page(state.directory_slot, mapped, &pages[0]) || !data_page(state.event_slot, mapped, &pages[1])) { packet->setup_reason = 5; return ERROR_INVALID_ADDRESS; }
    const size_t count = pages[0].base == pages[1].base ? 1 : 2;
    if (count == 1 && pages[0].original != pages[1].original) return ERROR_RETRY;
    if (!clock_live(packet, frequency)) return ERROR_TIMEOUT;
    if (!route_unchanged(packet)) { packet->route.route_revalidated = 0; packet->route.route_reason = 11; return ERROR_RETRY; }
    directory_open.store(directory, std::memory_order_release); event_open.store(event, std::memory_order_release);
    packet->setup_stage = 8;
    error = publish(state, pages, count);
    if (error != ERROR_SUCCESS && packet->iat.protection_error && !packet->setup_reason) packet->setup_reason = 8;
    if (error == ERROR_SUCCESS && !clock_live(packet, frequency)) return ERROR_TIMEOUT;
    if (error == ERROR_SUCCESS) packet->setup_stage = 1;
    return error;
}
extern "C" void memcordon_gate_trace_prepare(TracePacket* packet, uint64_t cutoff, uint64_t frequency) {
    packet->version = 4; packet->original_cutoff_qpc = cutoff; packet->lifetime_policy = 1;
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
            packet->route = installation_route;
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
    installation_route = packet->route;
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
    if (packet->setup_stage == 1) {
        if (!route_unchanged(packet)) {
            packet->route.route_reason = 11; packet->setup_stage = 6;
            packet->setup_reason = 10; packet->setup_error = ERROR_RETRY; packet->incomplete = 1;
        }
        if (!QueryPerformanceCounter(&now)) {
            const DWORD error = GetLastError();
            packet->clock_live = 0; packet->incomplete = 1; *called = 0; *native_error = error; return nullptr;
        }
        if (now.QuadPart < 0 || static_cast<uint64_t>(now.QuadPart) >= packet->original_cutoff_qpc) {
            packet->clock_live = 0; packet->incomplete = 1; *called = 0; *native_error = ERROR_TIMEOUT; return nullptr;
        }
    }
    if (!retained_owner) retained_owner = packet;
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
    return publication_mock() && route_mock() ? 1 : 0;
}
