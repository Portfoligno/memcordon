#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <processsnapshot.h>
#include <intrin.h>
#include "detours.h"
#include "gate_call_trace.h"

static_assert(sizeof(void*) == 8 && sizeof(WCHAR) == 2 && sizeof(NTSTATUS) == 4, "64-bit Windows ABI");
static_assert(sizeof(OBJECT_ATTRIBUTES) == 48 && offsetof(OBJECT_ATTRIBUTES, ObjectName) == 16, "object attributes ABI");
static_assert(sizeof(UNICODE_STRING) == 16 && offsetof(UNICODE_STRING, Buffer) == 8, "unicode string ABI");
using Open = NTSTATUS (NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
static Open directory_open = nullptr, event_open = nullptr;
static volatile LONG installation = 0;
static uint32_t installation_stage = 0, installation_error = 0;
static uint32_t installation_threads = 0;
static uint32_t installation_reason = 0, installation_current_thread = 0;
static SnapshotSummary installation_first = {}, installation_second = {};
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
    const NTSTATUS status = forward(directory_open, output, access, attributes, entry);
    if (entry && (!entry->arguments_readable || !entry->name_readable || entry->name_malformed || entry->name_truncated)) collector.packet->incomplete = 1;
    return status;
}
static NTSTATUS NTAPI event_hook(PHANDLE output, ACCESS_MASK access, POBJECT_ATTRIBUTES attributes) {
    TraceEntry* entry = enter(2, access);
    const NTSTATUS status = forward(event_open, output, access, attributes, entry);
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
struct SnapshotApi {
    decltype(&PssCaptureSnapshot) capture;
    decltype(&PssFreeSnapshot) free_snapshot;
    decltype(&PssWalkMarkerCreate) marker_create;
    decltype(&PssWalkMarkerFree) marker_free;
    decltype(&PssWalkSnapshot) walk;
    bool load(DWORD* error) {
        const HMODULE module = GetModuleHandleW(L"kernel32.dll");
        if (!module) { *error = GetLastError(); return false; }
        return load_export(module, "PssCaptureSnapshot", &capture, error) &&
            load_export(module, "PssFreeSnapshot", &free_snapshot, error) &&
            load_export(module, "PssWalkMarkerCreate", &marker_create, error) &&
            load_export(module, "PssWalkMarkerFree", &marker_free, error) &&
            load_export(module, "PssWalkSnapshot", &walk, error);
    }
};
struct ThreadIdentity { DWORD id; FILETIME birth; };
static uint64_t ticks(FILETIME time) {
    return (static_cast<uint64_t>(time.dwHighDateTime) << 32) | time.dwLowDateTime;
}
static DWORD threads(SnapshotApi& api, ThreadIdentity (&entries)[64], uint32_t* count, SnapshotSummary* summary) {
    HPSS snapshot = nullptr;
    summary->attempted = 1;
    DWORD error = api.capture(GetCurrentProcess(), PSS_CAPTURE_THREADS, 0, &snapshot);
    if (error != ERROR_SUCCESS) { summary->error = error; return error; }
    summary->captured = 1;
    HPSSWALK marker = nullptr;
    error = api.marker_create(nullptr, &marker);
    if (error == ERROR_SUCCESS) {
        for (;;) {
            PSS_THREAD_ENTRY entry = {};
            error = api.walk(snapshot, PSS_WALK_THREADS, marker, &entry, sizeof(entry));
            if (error == ERROR_NO_MORE_ITEMS) { summary->walk_completed = 1; error = ERROR_SUCCESS; break; }
            if (error != ERROR_SUCCESS) break;
            // Retain only fields already supplied by this same bounded walk.
            // Raw start addresses are opaque diagnostics, never dereferenced.
            if (summary->entry_count < 64) {
                ++summary->entry_count;
                const uint32_t flags = static_cast<uint32_t>(entry.Flags);
                const uint32_t terminated = static_cast<uint32_t>(PSS_THREAD_FLAGS_TERMINATED);
                if (flags & terminated) ++summary->terminated_count;
                else ++summary->without_terminated_count;
                if (flags & ~terminated) ++summary->unknown_flags_count;
                if (summary->detail_count < 8) {
                    summary->details[summary->detail_count++] = {
                        ticks(entry.CreateTime), ticks(entry.ExitTime), ticks(entry.CaptureTime),
                        reinterpret_cast<uintptr_t>(entry.Win32StartAddress),
                        entry.ProcessId, entry.ThreadId, flags, entry.ExitStatus
                    };
                } else summary->detail_truncated = 1;
            } else summary->detail_truncated = 1;
            if (entry.ProcessId != GetCurrentProcessId()) { error = ERROR_INVALID_OWNER; break; }
            if (*count >= 64) { error = ERROR_BUFFER_OVERFLOW; break; }
            entries[(*count)++] = {entry.ThreadId, entry.CreateTime};
        }
        const DWORD freed = api.marker_free(marker);
        if (error == ERROR_SUCCESS) error = freed;
    }
    const DWORD freed = api.free_snapshot(GetCurrentProcess(), snapshot);
    const DWORD original_error = error == ERROR_SUCCESS ? freed : error;
    summary->error = original_error;
    return original_error;
}
static bool equal(FILETIME a, FILETIME b) { return a.dwLowDateTime == b.dwLowDateTime && a.dwHighDateTime == b.dwHighDateTime; }

extern "C" void memcordon_gate_trace_prepare(TracePacket* packet, uint64_t cutoff, uint64_t frequency) {
    packet->version = 2; packet->original_cutoff_qpc = cutoff;
    packet->thread_limit = 64; packet->lifetime_policy = 1;
    if (!clock_live(packet, frequency)) { packet->incomplete = 1; return; }
    packet->started_qpc = packet->finished_qpc;
    const LONG previous = InterlockedCompareExchange(&installation, 1, 0);
    if (previous != 0) {
        packet->setup_stage = previous == 2 ? 1 : previous == 3 ? installation_stage : 13;
        packet->setup_error = previous == 2 ? 0 : installation_error;
        packet->attached_directory = packet->attached_event = previous == 2;
        packet->thread_count = installation_threads;
        packet->incomplete = previous != 2;
        if (previous == 2 || previous == 3) {
            packet->setup_reason = installation_reason;
            packet->original_current_thread_id = installation_current_thread;
            packet->snapshot_source = 2; // Frozen original installation evidence.
            packet->first_snapshot = installation_first;
            packet->second_snapshot = installation_second;
        } else {
            packet->setup_reason = 2; // Installation currently busy; evidence unavailable.
        }
        return;
    }
    uint32_t stage = 3;
    DWORD error = ERROR_PROC_NOT_FOUND;
    bool transaction = false;
    SnapshotApi api = {};
    ThreadIdentity first[64] = {}, second[64] = {};
    uint32_t first_count = 0, second_count = 0;
    const DWORD current = GetCurrentThreadId();
    packet->original_current_thread_id = current;
    packet->snapshot_source = 1;
    const HMODULE module = GetModuleHandleW(L"ntdll.dll");
    if (!module) { error = GetLastError(); goto done; }
    if (!load_export(module, "NtOpenDirectoryObject", &directory_open, &error) ||
        !load_export(module, "NtOpenEvent", &event_open, &error)) goto done;
    stage = 4;
    if (!api.load(&error)) goto done;
    stage = 4; error = threads(api, first, &first_count, &packet->first_snapshot);
    packet->thread_count = first_count;
    if (error != ERROR_SUCCESS) { if (error == ERROR_BUFFER_OVERFLOW) stage = 5; goto done; }
    {
        bool current_seen = false;
        for (uint32_t index = 0; index < first_count; ++index) {
            current_seen = current_seen || first[index].id == current;
            for (uint32_t previous = 0; previous < index; ++previous)
                if (first[previous].id == first[index].id) { error = ERROR_INVALID_DATA; goto done; }
        }
        if (!current_seen) { error = ERROR_INVALID_DATA; goto done; }
    }
    // Detours allocates during its transaction. Suspending an arbitrary peer
    // could strand the process heap lock, so this optional diagnostic refuses
    // multi-threaded controls instead of guessing a safe suspension point.
    if (first_count != 1) { packet->setup_reason = 1; stage = 13; error = ERROR_NOT_SUPPORTED; goto done; }
    stage = 7; error = DetourTransactionBegin();
    if (error != ERROR_SUCCESS) goto done;
    transaction = true;
    stage = 8; error = DetourUpdateThread(GetCurrentThread());
    if (error != ERROR_SUCCESS) goto done;
    stage = 9; error = DetourAttach(reinterpret_cast<PVOID*>(&directory_open), reinterpret_cast<PVOID>(directory_hook));
    if (error != ERROR_SUCCESS) goto done;
    stage = 10; error = DetourAttach(reinterpret_cast<PVOID*>(&event_open), reinterpret_cast<PVOID>(event_hook));
    if (error != ERROR_SUCCESS) goto done;
    stage = 11; error = threads(api, second, &second_count, &packet->second_snapshot);
    if (error != ERROR_SUCCESS) goto done;
    if (first_count != second_count) { error = ERROR_RETRY; goto done; }
    for (uint32_t index = 0; index < second_count; ++index) {
        bool found = false;
        for (uint32_t original = 0; original < first_count; ++original)
            if (first[original].id == second[index].id && equal(first[original].birth, second[index].birth)) found = true;
        if (!found) { error = ERROR_RETRY; goto done; }
    }
    if (!clock_live(packet, frequency)) { stage = 2; error = ERROR_TIMEOUT; goto done; }
    stage = 12; error = DetourTransactionCommit();
    transaction = false; // Detours commits or aborts its own transaction.
    if (error == ERROR_SUCCESS) stage = 1;
done:
    // Continuing after an unproved rollback could leave another original
    // thread suspended or an indeterminate patch. Fail this owned control
    // child closed; its existing parent remains the sole process wait owner.
    if (transaction && DetourTransactionAbort() != ERROR_SUCCESS) __fastfail(FAST_FAIL_FATAL_APP_EXIT);
    installation_stage = stage; installation_error = error;
    installation_threads = first_count;
    installation_reason = packet->setup_reason;
    installation_current_thread = packet->original_current_thread_id;
    installation_first = packet->first_snapshot;
    installation_second = packet->second_snapshot;
    InterlockedExchange(&installation, stage == 1 ? 2 : 3);
    packet->setup_stage = stage; packet->setup_error = error;
    packet->attached_directory = packet->attached_event = stage == 1;
    packet->incomplete = stage != 1;
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
    HANDLE event = OpenEventW(SYNCHRONIZE, FALSE, reinterpret_cast<LPCWSTR>(name));
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
    return 1;
}
