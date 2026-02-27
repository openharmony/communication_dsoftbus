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

#ifndef CONNECTION_BR_PENDING_PACKET_MOCK_H
#define CONNECTION_BR_PENDING_PACKET_MOCK_H

#include "softbus_conn_br_connection.h"
#include "softbus_conn_br_trans.h"

#include <gmock/gmock.h>
#include "cJSON.h"

#include "softbus_adapter_bt_common.h"
#include "softbus_adapter_thread.h"
#include "softbus_config_type.h"
#include "softbus_def.h"

#include "softbus_conn_br_connection_struct.h"

namespace OHOS {
class ConnectionBrPendingPacketInterface {
public:
    ConnectionBrPendingPacketInterface() {};
    virtual ~ConnectionBrPendingPacketInterface() {};
    virtual bool GetJsonObjectSignedNumberItem(const cJSON *json, const char *key, int32_t *value) = 0;
    virtual bool GetJsonObjectNumber64Item(const cJSON *json, const char *key, int64_t *value) = 0;
    virtual int64_t ConnBrPackCtlMessage(BrCtlMessageSerializationContext ctx, uint8_t **outData, uint32_t *outLen) = 0;
    virtual int32_t ConnBrPostBytes(
        uint32_t connectionId, uint8_t *data, uint32_t len, int32_t pid, int32_t flag, int32_t module, int64_t seq) = 0;
    virtual int32_t ConnBrSetBrPendingPacket(uint32_t id, int64_t seq, void *data) = 0;
};

class ConnectionBrPendingPacketMock : public ConnectionBrPendingPacketInterface {
public:
    ConnectionBrPendingPacketMock();
    ~ConnectionBrPendingPacketMock() override;
    MOCK_METHOD3(GetJsonObjectSignedNumberItem, bool(const cJSON *, const char *, int32_t *));
    MOCK_METHOD3(GetJsonObjectNumber64Item, bool(const cJSON *, const char *, int64_t *));
    MOCK_METHOD3(ConnBrPackCtlMessage, int64_t(BrCtlMessageSerializationContext, uint8_t **, uint32_t *));
    MOCK_METHOD7(ConnBrPostBytes, int32_t(uint32_t, uint8_t *, uint32_t, int32_t, int32_t, int32_t, int64_t));
    MOCK_METHOD3(ConnBrSetBrPendingPacket, int32_t(uint32_t, int64_t, void *));
};
} // namespace OHOS
#endif // CONNECTION_BR_PENDING_PACKET_MOCK_H
