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

#include "softbus_conn_br_pending_packet_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_connectionBrPendingPacketInterface;
ConnectionBrPendingPacketMock::ConnectionBrPendingPacketMock()
{
    g_connectionBrPendingPacketInterface = reinterpret_cast<void *>(this);
}

ConnectionBrPendingPacketMock::~ConnectionBrPendingPacketMock()
{
    g_connectionBrPendingPacketInterface = nullptr;
}

static ConnectionBrPendingPacketInterface *GetConnectionBrPendingPacketInterface()
{
    return reinterpret_cast<ConnectionBrPendingPacketInterface *>(g_connectionBrPendingPacketInterface);
}

extern "C" {
bool GetJsonObjectSignedNumberItem(const cJSON *json, const char *key, int32_t *value)
{
    return GetConnectionBrPendingPacketInterface()->GetJsonObjectSignedNumberItem(json, key, value);
}

bool GetJsonObjectNumber64Item(const cJSON *json, const char *key, int64_t *value)
{
    return GetConnectionBrPendingPacketInterface()->GetJsonObjectNumber64Item(json, key, value);
}

int64_t ConnBrPackCtlMessage(BrCtlMessageSerializationContext ctx, uint8_t **outData, uint32_t *outLen)
{
    return GetConnectionBrPendingPacketInterface()->ConnBrPackCtlMessage(ctx, outData, outLen);
}

int32_t ConnBrPostBytes(
    uint32_t connectionId, uint8_t *data, uint32_t len, int32_t pid, int32_t flag, int32_t module, int64_t seq)
{
    return GetConnectionBrPendingPacketInterface()->ConnBrPostBytes(connectionId, data, len, pid, flag, module, seq);
}
}
}
