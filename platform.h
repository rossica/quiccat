#pragma once

#ifdef _WIN32
#else
#include <sys/eventfd.h
#include <sys/select.h>
#include <unistd.h>
#include <errno.h>
#endif

#ifdef _WIN32
typedef HANDLE FileOrHandle;
//
// SelectableEvent implementation on Windows
//
typedef CXPLAT_EVENT SelectableEvent;

#define InitializeSelectableEvent(_Ev) CxPlatEventInitialize(_Ev, true, false)
#define SetSelectableEvent(_Ev) CxPlatEventSet(_Ev)
#define ResetSelectableEvent(_Ev) CxPlatEventReset(_Ev)
#define UninitializeSelectableEvent(_Ev) CxPlatEventUninitialize(_Ev)
#else
typedef int FileOrHandle;
//
// SelectableEvent implementation on Linux
//
typedef int SelectableEvent;

#define InitializeSelectableEvent(_Ev) \
    *(_Ev) = eventfd(0, 0); \
    CXPLAT_DBG_ASSERT(*(_Ev) != -1)

bool
SetSelectableEvent(SelectableEvent Ev);

bool
ResetSelectableEvent(SelectableEvent Ev);

#define UninitializeSelectableEvent(_Ev) close(_Ev)
#endif


//
// Utility functions
//
FileOrHandle
WaitForFileOrEvent(FileOrHandle File, FileOrHandle Event);

FileOrHandle
GetStdin();
