#pragma once

#include <cstdio>
#include <cstdarg>


// Since this file is most likely to be used outside of the project (like, in Android),
// using a namespace to avoid conflicts
namespace wfb {
enum class LogLevel {
    ALWAYS,
    ERROR,
    WARNING,
    INFO,
    DEBUG
};

class Logger
{
public:
    virtual ~Logger() = default;
    virtual void logln(LogLevel level, const char* format, ...) = 0;
};

class StdErrLogger : public Logger
{
public:
    void logln(LogLevel level, const char* format, ...) override {
        const char* level_str = "";
        switch (level) {
            case LogLevel::DEBUG:
            case LogLevel::INFO:
                return;
            case LogLevel::ALWAYS:
                break;
            case LogLevel::WARNING:
                level_str = "WARNING: ";
                break;
            case LogLevel::ERROR:
                level_str = "ERROR: ";
                break;
        }

        char buffer[1024];
        va_list args;
        va_start(args, format);
        int prefix_len = snprintf(buffer, sizeof(buffer), "%s", level_str);
        if (prefix_len < 0)
            return;

        int message_len = vsnprintf(buffer + prefix_len, sizeof(buffer) - prefix_len - 2, format, args);
        if (message_len < 0)
            return;

        va_end(args);

        buffer[prefix_len + message_len] = '\n';
        buffer[prefix_len + message_len + 1] = '\0';
    }
};
} // namespace wfb