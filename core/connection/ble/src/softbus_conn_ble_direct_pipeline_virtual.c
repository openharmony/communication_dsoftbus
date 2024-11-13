/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "conn_log.h"
#include "softbus_conn_interface.h"
#include "softbus_error_code.h"

int32_t ConnBleDirectPipelineOpen(const ConnBleDirectPipelineOption *option, const ConnectResult *result)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t ConnBleDirectPipelineClose(int32_t channelId)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t ConnBleDirectPipelineInit(ConnBleDirectPipelineCallback* cb)
{
    CONN_LOGW(CONN_BLE, "do not support ble direct pipeline");
    return SOFTBUS_OK;
}

int32_t ConnBleDirectPipelineSendMessage(int32_t channelId, const uint8_t *data, uint32_t dataLen,
    PipelineMsgType type)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

void PipelineRegisterIpPortVerifyCallBack(const OnMessageReceivedFunc cb)
{
    return;
}

int32_t GetPipelineIdByPeerNetworkId(const char* peerNetworkId)
{
    return INVALID_CHANNEL_ID;
}