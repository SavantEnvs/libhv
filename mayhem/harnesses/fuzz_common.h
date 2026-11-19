// Shared helpers for the libhv fuzz harnesses (mayhem/ layer, not upstream code).
#pragma once
#include <stddef.h>
#include <stdint.h>
#include "hlog.h"

// libhv's default logger writes a log file next to the binary; the harnesses keep it silent so
// no input leaves state on disk or in the logger between runs.
static inline void fuzz_quiet_logs() {
    hlog_disable();
}
