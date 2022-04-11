#pragma once

#define _CRT_SECURE_NO_WARNINGS 1
#include <iostream>
#include <memory>
#include <string>
#include <fstream>
#include <filesystem>
#include <chrono>

#ifndef _WIN32
#define CX_PLATFORM_LINUX 1
#endif
#include <msquichelper.h>
#include <msquic.hpp>
#include <quic_platform.h>
#include <quic_var_int.h>

#include "auth.h"
