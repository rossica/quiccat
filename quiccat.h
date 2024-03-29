﻿#pragma once

#define _CRT_NONSTDC_NO_WARNINGS 1
#define _CRT_SECURE_NO_WARNINGS 1
#include <fcntl.h>
#include <iostream>
#include <memory>
#include <string>
#include <fstream>
#include <filesystem>
#include <chrono>
#include <vector>
#include <mutex>
#include <utility>
#include <thread>
#include <condition_variable>

#ifndef _WIN32
#define CX_PLATFORM_LINUX 1
#endif
#include <msquichelper.h>
#include <msquic.hpp>
#include <quic_platform.h>
#include <quic_var_int.h>

#include "log.h"
#include "auth.h"
#include "platform.h"
