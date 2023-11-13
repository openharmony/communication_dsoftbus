/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef STREAM_COMMON_INNER_H
#define STREAM_COMMON_INNER_H

#include "stream_common.h"
#include "trans_log.h"

namespace Communication {
namespace SoftBus {
enum InnerStreamOptionType {
    INNER_STREAM_OPTION_TYPE_MIN = 0,

    // for socket
    PROTOCOL,
    LOCAL_IP,
    LOCAL_PORT,
    REMOTE_IP,
    REMOTE_PORT,
    IP_TYPE,
    LOCAL_SCOPE_ID,
    REMOTE_SCOPE_ID,
    SERVER_FD,
    FD,
    SEND_BUF_SIZE,
    RECV_BUF_SIZE,
    KEEP_ALIVE_TIMEOUT,
    TOS,
    BOUND_INTERFACE_IP,
    SOFTBUS_SOCKET_ERROR,
    NON_BLOCK,
    IS_SERVER,
    REUSE_ADDR,
    NO_DELAY,

    // for RAW Stream
    SCENE,
    STREAM_HEADER_SIZE,

    // for VTP
    NACK_DELAY,
    NACK_DELAY_TIMEOUT,
    PACK_INTERVAL_ENLARGE,
    REDUNANCY_SWITCH,
    REDUNANCY_LEVEL,
    PKT_LOSS,
    PKT_STATISTICS,
    SEND_CACHE,
    RECV_CACHE,
    PACKET_SIZE,
    MAX_VTP_SOCKET_NUM,
    MAX_VTP_CONNECT_NUM,

    // for link/mac
    LINK_TYPE,
    INNER_STREAM_OPTION_TYPE_MAX = 1000,
};

enum StreamEventType {
    REPORT_NETWORK_QUALITY,
    REPORT_DROP_FRAME,
    REPORT_SCORE,
};

template<class T> struct StreamEvent {
    StreamEventType type;
    T event;
};

struct HistoryStats {
    Proto type = VTP;
    int periodFrameNum;
    int avgFrameInterval;
    int minFrameInterval;
    int maxFrameInterval;
    int interval = 1000; // ms
};

extern bool g_logOn;
} // namespace SoftBus
} // namespace Communication

#endif