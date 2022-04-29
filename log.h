#pragma once

enum QcLogLevel : uint8_t {
    LogFatal,
    LogError,
    LogInfo
};

extern QcLogLevel CurrentLogLevel;
extern std::ofstream NullLogger;

static
inline
std::ostream&
Log(QcLogLevel Level = LogFatal) {
    if (Level <= CurrentLogLevel) {
        return std::cerr;
    } else {
        return NullLogger;
    }
}
