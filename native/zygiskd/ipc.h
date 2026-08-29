// Wire protocol for daemon <-> in-zygote and daemon <->
// in-target-process IPC.
//
// All messages are little-endian. Format:
//   [opcode:4][len:4][body:len]
// Reply has the same shape but with status word between op and len:
//   [opcode:4][status:4][len:4][body:len]

#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Opcodes shared between daemon and libzygisk (in-zygote)
enum BridgeOp {
    BO_PING               = 0,
    BO_REGISTER_MODULE    = 1,
    BO_GET_MODULE_LIST    = 2,
    BO_CONNECT_COMPANION  = 3,
    BO_LOG                = 4,
    BO_REQUEST_REWRITE    = 5,
    BO_SPECIALIZE_DONE   = 6,
    BO_GET_FLAGS          = 7,
};

// Opcodes for the znctl WebUI bridge
enum WebuiOp {
    WO_STATUS             = 100,
    WO_LIST_MODULES       = 101,
    WO_TOGGLE_MODULE      = 102,
    WO_VIEW_LOG           = 103,
    WO_BUGREPORT          = 104,
    WO_ENABLE_ZYGISK      = 105,
    WO_DISABLE_ZYGISK     = 106,
    WO_VERSION            = 107,
};

// Common message header
struct MsgHdr {
    uint32_t op;
    uint32_t len;
} __attribute__((packed));

struct ReplyHdr {
    uint32_t op;
    uint32_t status;
    uint32_t len;
} __attribute__((packed));

#ifdef __cplusplus
}
#endif
