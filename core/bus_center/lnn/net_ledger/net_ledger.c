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

#include "bus_center_manager.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "lnn_distributed_net_ledger.h"
#include "lnn_local_net_ledger.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_utils.h"

int32_t LnnGetRemoteStrInfo(const char *networkId, InfoKey key, char *info, uint32_t len)
{
    if (!IsValidString(networkId, ID_MAX_LEN)) {
        return SOFTBUS_INVALID_PARAM;
    }
    return LnnGetDLStrInfo(networkId, key, info, len);
}

int32_t LnnGetRemoteNumInfo(const char *networkId, InfoKey key, int32_t *info)
{
    if (!IsValidString(networkId, ID_MAX_LEN)) {
        return SOFTBUS_INVALID_PARAM;
    }
    return LnnGetDLNumInfo(networkId, key, info);
}

int32_t LnnSetLocalStrInfo(InfoKey key, const char *info)
{
    return LnnSetLocalLedgerStrInfo(key, info);
}

int32_t LnnSetLocalNumInfo(InfoKey key, int32_t info)
{
    return LnnSetLocalLedgerNumInfo(key, info);
}

int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len)
{
    return LnnGetLocalLedgerStrInfo(key, info, len);
}

int32_t LnnGetLocalNumInfo(InfoKey key, int32_t *info)
{
    return LnnGetLocalLedgerNumInfo(key, info);
}

int32_t LnnGetAllOnlineNodeInfo(NodeBasicInfo **info, int32_t *infoNum)
{
    return LnnGetDistributedNodeInfo(info, infoNum);
}

int32_t LnnGetLocalDeviceInfo(NodeBasicInfo *info)
{
    int32_t rc;
    char type[DEVICE_TYPE_BUF_LEN] = {0};

    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "info is null");
        return SOFTBUS_INVALID_PARAM;
    }
    rc = LnnGetLocalLedgerStrInfo(STRING_KEY_DEV_NAME, info->deviceName, DEVICE_NAME_BUF_LEN);
    if (rc != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get local device info failed");
        return SOFTBUS_ERR;
    }
    rc = LnnGetLocalLedgerStrInfo(STRING_KEY_NETWORKID, info->networkId, NETWORK_ID_BUF_LEN);
    if (rc != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get local network id info failed");
        return SOFTBUS_ERR;
    }
    rc = LnnGetLocalLedgerStrInfo(STRING_KEY_DEV_TYPE, type, DEVICE_TYPE_BUF_LEN);
    if (rc != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get local device type failed");
        return SOFTBUS_ERR;
    }
    return LnnConvertDeviceTypeToId(type, &info->deviceTypeId);
}

int32_t LnnGetNodeKeyInfo(const char *networkId, int key, uint8_t *info, int32_t infoLen)
{
    bool isLocalNetowrkId = false;
    char localNetworkId[NETWORK_ID_BUF_LEN] = {0};
    if (networkId == NULL || info == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "params are null");
        return SOFTBUS_ERR;
    }
    if (LnnGetLocalStrInfo(STRING_KEY_NETWORKID, localNetworkId, NETWORK_ID_BUF_LEN) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get local network id fail");
        return SOFTBUS_ERR;
    }
    if (strncmp(localNetworkId, networkId, NETWORK_ID_BUF_LEN) == 0) {
        isLocalNetowrkId = true;
    }
    switch (key) {
        case NODE_KEY_UDID:
            if (isLocalNetowrkId) {
                return LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, (char *)info, infoLen);
            } else {
                return LnnGetRemoteStrInfo(networkId, STRING_KEY_DEV_UDID, (char *)info, infoLen);
            }
        case NODE_KEY_UUID:
            if (isLocalNetowrkId) {
                return LnnGetLocalStrInfo(STRING_KEY_UUID, (char *)info, infoLen);
            } else {
                return LnnGetRemoteStrInfo(networkId, STRING_KEY_UUID, (char *)info, infoLen);
            }
        default:
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid node key type: %d", key);
            return SOFTBUS_ERR;
    }
}
