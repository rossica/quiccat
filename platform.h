#pragma once

#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#include <errno.h>
#endif
