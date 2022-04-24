#include "quiccat.h"

using namespace std;

#ifndef _WIN32
bool
SetSelectableEvent(SelectableEvent Ev) {
    uint64_t Value = 1;
    auto ret = write(Ev, &Value, sizeof Value);
    CXPLAT_DBG_ASSERT(ret == sizeof Value);
    return ret != -1;
}

bool
ResetSelectableEvent(SelectableEvent Ev) {
    uint64_t Junk = 0;
    auto ret = read(Ev, &Junk, sizeof Junk);
    CXPLAT_DBG_ASSERT(ret == sizeof Junk);
    return ret != -1;
}
#endif

FileOrHandle
WaitForFileOrEvent(FileOrHandle File, FileOrHandle Event)
{
#ifdef _WIN32
    FileOrHandle Handles[] = {File, Event};
    INPUT_RECORD Record;
    while (true) {
        DWORD EventsRead = 0;
        auto Result =
            WaitForMultipleObjectsEx(
                ARRAYSIZE(Handles),
                Handles,
                FALSE,
                INFINITE,
                FALSE);
        if (Result == WAIT_FAILED) {
            cout << "Failed to wait for handles: 0x" << hex << GetLastError() << endl;
            return nullptr;
        }
        if (Result - WAIT_OBJECT_0 == 0) {
            if (PeekConsoleInput(File, &Record, 1, &EventsRead)) {
                if (EventsRead == 1 && Record.EventType != KEY_EVENT) {
                    ReadConsoleInput(File, &Record, 1, &EventsRead);
                    continue;
                }
            }
            return Handles[0];
        } else if (Result - WAIT_OBJECT_0 == 1) {
            return Handles[1];
        } else {
            cout << "Wait failed for another reason: 0x" << hex << Result << endl;
            return nullptr;
        }
    }
#else
    fd_set FileDescriptors;
    FD_ZERO(&FileDescriptors);
    FD_SET(File, &FileDescriptors);
    FD_SET(Event, &FileDescriptors);

    auto Result = select(Event + 1, &FileDescriptors, nullptr, nullptr, nullptr);
    if (Result == -1) {
        cout << "select() failed: " << strerror(errno) << endl;
        return nullptr;
    }
    if (FD_ISSET(File, &FileDescriptors)) {
        return File;
    } else if (FD_ISSET(Event, &FileDescriptors)) {
        return Event;
    } else {
        cout << "No event is ready???" << endl;
        return nullptr;
    }
#endif
}

FileOrHandle
GetStdin()
{
#ifdef _WIN32
    auto StdIn = GetStdHandle(STD_INPUT_HANDLE);
    //
    // Windows does some dumb stuff with console windows that we need
    // to ignore here.
    //
    // DWORD ConsoleMode = 0;
    // GetConsoleMode(StdIn, &ConsoleMode);
    // ConsoleMode &= ~(ENABLE_MOUSE_INPUT & ENABLE_WINDOW_INPUT);
    // SetConsoleMode(StdIn, ConsoleMode);
    FlushConsoleInputBuffer(StdIn);
    return StdIn;
#else
    return STDIN_FILENO;
#endif
}
