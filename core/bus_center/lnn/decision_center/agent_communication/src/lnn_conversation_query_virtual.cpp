/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "lnn_conversation_query.h"

#include "lnn_log.h"
#include "softbus_agent_communication.h"
#include "softbus_error_code.h"

int32_t LnnGetTrustedDevices(DeviceNodeInfo **info, int32_t *nums)
{
    (void)info;
    (void)nums;
    LNN_LOGI(LNN_INIT, "not implement");
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnRegisterConversationListener(const ConversationBusiness *info)
{
    (void)info;
    LNN_LOGI(LNN_INIT, "not implement");
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnUnregisterConversationListener(const ConversationBusiness *info)
{
    (void)info;
    LNN_LOGI(LNN_INIT, "not implement");
    return SOFTBUS_NOT_IMPLEMENT;
}

void OnRecvCloudQueryInfo(const char *udid, const char *data, uint32_t length)
{
    (void)udid;
    (void)data;
    (void)length;
    LNN_LOGI(LNN_INIT, "not implement");
    return;
}

int32_t LnnPostConversationData(const char *deviceId, const ConversationBusiness *info,
    const char *data, uint32_t len)
{
    (void)deviceId;
    (void)info;
    (void)data;
    (void)len;
    LNN_LOGI(LNN_INIT, "not implement");
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t InitConversationQuery(void)
{
    LNN_LOGI(LNN_INIT, "not implement");
    return SOFTBUS_OK;
}

void DeinitConversationQuery(void)
{
    LNN_LOGI(LNN_INIT, "not implement");
}

int32_t DestroyNearFieldChannel(const char *udid)
{
    (void)udid;
    LNN_LOGI(LNN_INIT, "not implement");
    return SOFTBUS_NOT_IMPLEMENT;
}
