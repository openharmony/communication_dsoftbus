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

#include "bus_center_event.h"

#include <stdlib.h>

#include "lnn_bus_center_ipc.h"
#include "softbus_log.h"

void LnnNotifyOnlineState(bool isOnline, NodeBasicInfo *info)
{
    if (info == NULL) {
        LOG_ERR("para : info = null!");
        return;
    }
    LOG_INFO("notify node %s", (isOnline == true) ? "online" : "offline");
    LnnIpcNotifyOnlineState(isOnline, info, sizeof(NodeBasicInfo));
}

void LnnNotifyBasicInfoChanged(NodeBasicInfo *info, NodeBasicInfoType type)
{
    if (info == NULL) {
        LOG_ERR("para : info = null!");
        return;
    }
    if (type == TYPE_DEVICE_NAME) {
        LOG_INFO("notify peer device name changed %s", info->deviceName);
    }
    LnnIpcNotifyBasicInfoChanged(info, sizeof(NodeBasicInfo), type);
}

void LnnNotifyJoinResult(ConnectionAddr *addr, const char *networkId, int32_t retCode)
{
    if (addr == NULL) {
        LOG_ERR("para : addr or networkId = null!");
        return;
    }
    LOG_INFO("notify join LNN result :%d", retCode);
    LnnIpcNotifyJoinResult(addr, sizeof(ConnectionAddr), networkId, retCode);
}

void LnnNotifyLeaveResult(const char *networkId, int32_t retCode)
{
    if (networkId == NULL) {
        LOG_ERR("para : networkId = null!");
        return;
    }
    LOG_INFO("notify leave LNN result %d", retCode);
    LnnIpcNotifyLeaveResult(networkId, retCode);
}