/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "lnn_heartbeat_utils.h"

#include <securec.h>
#include <string.h>

#include "bus_center_manager.h"
#include "lnn_heartbeat_medium_mgr.h"
#include "p2plink_interface.h"

#include "softbus_adapter_crypto.h"
#include "softbus_errcode.h"
#include "softbus_conn_interface.h"
#include "softbus_log.h"
#include "softbus_utils.h"

LnnHeartbeatType LnnConvertConnAddrTypeToHbType(ConnectionAddrType addrType)
{
    switch (addrType) {
        case CONNECTION_ADDR_WLAN:
        case CONNECTION_ADDR_ETH:
            return HEARTBEAT_TYPE_UDP;
        case CONNECTION_ADDR_BR:
        case CONNECTION_ADDR_BLE:
            return HEARTBEAT_TYPE_BLE_V1;
        default:
            break;
    }
    return HEARTBEAT_TYPE_MAX;
}

ConnectionAddrType LnnConvertHbTypeToConnAddrType(LnnHeartbeatType type)
{
    switch (type) {
        case HEARTBEAT_TYPE_UDP:
        case HEARTBEAT_TYPE_TCP_FLUSH:
            return CONNECTION_ADDR_WLAN;
        case HEARTBEAT_TYPE_BLE_V1:
        case HEARTBEAT_TYPE_BLE_V0:
            return CONNECTION_ADDR_BLE;
        default:
            break;
    }
    return CONNECTION_ADDR_MAX;
}

int32_t LnnConvertHbTypeToId(LnnHeartbeatType type)
{
    int32_t cnt = -1;

    if (type < HEARTBEAT_TYPE_MIN || type >= HEARTBEAT_TYPE_MAX) {
        return HB_INVALID_TYPE_ID;
    }
    do {
        type >>= 1;
        ++cnt;
    } while (type >= HEARTBEAT_TYPE_MIN);
    if (cnt < 0 || cnt > HB_MAX_TYPE_COUNT) {
        return HB_INVALID_TYPE_ID;
    }
    return cnt;
}

static bool HbHasActiveBrConnection(const char *networkId)
{
    bool ret = false;
    ConnectOption option = {0};
    char brMac[BT_MAC_LEN] = {0};

    if (LnnGetRemoteStrInfo(networkId, STRING_KEY_BT_MAC, brMac, sizeof(brMac)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB get bt mac err");
        return false;
    }
    option.type = CONNECT_BR;
    if (strcpy_s(option.brOption.brMac, BT_MAC_LEN, brMac) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB strcpy_s bt mac err");
        return false;
    }
    ret = CheckActiveConnection(&option);
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_DBG, "HB has active bt connection:%s", ret ? "true" : "false");
    return ret;
}

static bool HbHasActiveBleConnection(const char *networkId)
{
    bool ret = false;
    ConnectOption option = {0};
    char udid[UDID_BUF_LEN] = {0};
    char udidHash[UDID_HASH_LEN] = {0};

    if (LnnGetRemoteStrInfo(networkId, STRING_KEY_DEV_UDID, udid, sizeof(udid)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB get udid err");
        return false;
    }
    if (SoftBusGenerateStrHash((const unsigned char *)udid, strlen(udid),
        (unsigned char *)udidHash) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB get udid hash err");
        return false;
    }
    option.type = CONNECT_BLE;
    if (memcpy_s(option.bleOption.deviceIdHash, UDID_HASH_LEN, udidHash, sizeof(udidHash)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB memcpy_s udid hash err");
        return false;
    }
    ret = CheckActiveConnection(&option);
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_DBG, "HB has active ble connection:%s", ret ? "true" : "false");
    return ret;
}

static bool HbHasActiveP2pConnection(const char *networkId)
{
    int32_t ret;
    char peerMac[P2P_MAC_LEN] = {0};

    if (LnnGetRemoteStrInfo(networkId, STRING_KEY_P2P_MAC, peerMac, sizeof(peerMac)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB get peer p2p mac err");
        return false;
    }
    ret = P2pLinkQueryDevIsOnline(peerMac);
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_DBG, "HB has active p2p connection:%s, ret=%d",
        ret == SOFTBUS_OK ? "true" : "false", ret);
    return ret == SOFTBUS_OK ? true : false;
}

bool LnnHasActiveConnection(const char *networkId, ConnectionAddrType addrType)
{
    bool ret = false;

    if (networkId == NULL || addrType >= CONNECTION_ADDR_MAX) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB check active connection get invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    switch (addrType) {
        case CONNECTION_ADDR_WLAN:
        case CONNECTION_ADDR_ETH:
        case CONNECTION_ADDR_BR:
            break;
        case CONNECTION_ADDR_BLE:
            ret = HbHasActiveBrConnection(networkId) || HbHasActiveBleConnection(networkId) ||
                HbHasActiveP2pConnection(networkId);
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "HB networkId:%s has active BT/BLE/P2P connection:%s",
                AnonymizesNetworkID(networkId), ret ? "true" : "false");
            return ret;
        default:
            break;
    }
    return false;
}

bool LnnVisitHbTypeSet(VisitHbTypeCb callback, LnnHeartbeatType *typeSet, void *data)
{
    bool isFinish = false;
    LnnHeartbeatType i;

    if (typeSet == NULL || *typeSet < HEARTBEAT_TYPE_MIN || *typeSet >= HEARTBEAT_TYPE_MAX) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB visit typeSet get invalid param");
        return false;
    }
    for (i = HEARTBEAT_TYPE_MIN; i < HEARTBEAT_TYPE_MAX; i <<= 1) {
        if ((i & *typeSet) == 0) {
            continue;
        }
        isFinish = callback(typeSet, i, data);
        if (!isFinish) {
            return false;
        }
    }
    return true;
}

static bool VisitCheckSupportedHbType(LnnHeartbeatType *typeSet, LnnHeartbeatType eachType, void *data)
{
    (void)typeSet;
    LnnHeartbeatType *dstType = (LnnHeartbeatType *)data;

    if ((eachType & *dstType) == 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB not support hbType(%d) completely", *dstType);
        return false;
    }
    return true;
}

bool LnnCheckSupportedHbType(LnnHeartbeatType *srcType, LnnHeartbeatType *dstType)
{
    if (srcType == NULL || dstType == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB check supported hbType get invalid param");
        return false;
    }
    return LnnVisitHbTypeSet(VisitCheckSupportedHbType, srcType, dstType);
}

int32_t LnnGenerateHexStringHash(const unsigned char *str, char *hashStr, uint32_t len)
{
    int32_t ret;
    uint8_t hashResult[SHA_256_HASH_LEN] = {0};

    if (str == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB generate str hash invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    ret = SoftBusGenerateStrHash(str, strlen((char *)str), hashResult);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB generate str hash fail, ret=%d", ret);
        return ret;
    }
    ret = ConvertBytesToHexString(hashStr, len + 1, hashResult, len / HEXIFY_UNIT_LEN);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB convert bytes to str hash fail ret=%d", ret);
        return ret;
    }
    return SOFTBUS_OK;
}
