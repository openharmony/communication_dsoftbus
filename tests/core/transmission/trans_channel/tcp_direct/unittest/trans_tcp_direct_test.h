/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#ifndef TRANS_TCP_DIRECT_TEST_H
#define TRANS_TCP_DIRECT_TEST_H

#include <cstdint>
#include <cstring>
#include <arpa/inet.h>
#include <unistd.h>
#include <securec.h>

#include "auth_interface.h"
#include "auth_manager.h"
#include "auth_session_fsm.h"
#include "bus_center_manager.h"
#include "cJSON.h"
#include "gtest/gtest.h"
#include "lnn_lane_interface.h"

#include "session.h"
#include "softbus_adapter_mem.h"
#include "softbus_app_info.h"
#include "softbus_base_listener.h"
#include "softbus_conn_interface.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_json_utils.h"
#include "softbus_protocol_def.h"
#include "softbus_server_frame.h"
#include "softbus_trans_def.h"
#include "softbus_proxychannel_message.h"
#include "trans_session_manager.h"
#include "trans_tcp_direct_json.h"
#include "trans_tcp_direct_p2p.h"
#include "trans_tcp_direct_message.h"
#include "trans_tcp_direct_listener.h"
#include "trans_tcp_direct_sessionconn.h"
#include "trans_tcp_direct_sessionconn.c"

#define PKG_NAME_SIZE_MAX_LEN 65
#define NETWORK_ID_BUF_MAX_LEN 65
#define SESSION_NAME_MAX_LEN 256
#define TEST_GROUP_ID_LEN 64
#define IP_LEN 46
#define ERRMOUDLE 13
#define INVALID_VALUE (-1)

int32_t g_port = 6000;

#endif // TRANS_TCP_DIRECT_MESSAGE_TEST_MOCK_H