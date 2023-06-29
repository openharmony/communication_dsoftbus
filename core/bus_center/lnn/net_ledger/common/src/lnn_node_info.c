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

#include "lnn_node_info.h"

#include <string.h>

#include <securec.h>

#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_adapter_mem.h"

#define PEER_DISCOVERY_INTERVAL ","
#define DISCOVERY_TYPE_JUDGE_NUM 2

static int32_t TailInsertString(char *destStr, const char *sourStr, int destLen)
{
    uint32_t len = strlen(destStr) + strlen(sourStr) + 1;
    if (len > destLen) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "para err");
        return SOFTBUS_ERR;
    }
    if (strcat_s(destStr, len, sourStr) !=0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "strcat err");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

NO_SANITIZE("cfi") int32_t LnnSetSupportDiscoveryType(char *dstId, const char *sourceId)
{
    if (dstId == NULL || sourceId == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "para error");
        return SOFTBUS_INVALID_PARAM;
    }
    if (strlen(dstId) == 0) {
        if (strcpy_s(dstId, PEER_DISCOVERY_TYPE_LEN, sourceId) != EOK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "STR COPY ERROR!");
            return SOFTBUS_MEM_ERR;
        }
    } else {
        if (TailInsertString(dstId, PEER_DISCOVERY_INTERVAL, PEER_DISCOVERY_TYPE_LEN) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "Add string err");
            return SOFTBUS_ERR;
        }
        if (TailInsertString(dstId, sourceId, PEER_DISCOVERY_TYPE_LEN) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "Add string err");
            return SOFTBUS_ERR;
        }
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "set PeerDiscoveryType=%s", dstId);
    return SOFTBUS_OK;
}

NO_SANITIZE("cfi") bool LnnHasSupportDiscoveryType(const char *destType, const char *type)
{
    if (destType == NULL || type == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "err para");
        return false;
    }
    if (strcmp(type, destType) == 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "Recv DisType = %s", type);
        return true;
    }
    char *tmp = (char *)SoftBusCalloc(PEER_DISCOVERY_TYPE_LEN * sizeof(char));
    if (tmp == NULL) {
        return false;
    }
    if (memcpy_s(tmp, PEER_DISCOVERY_TYPE_LEN, type, strlen(type)) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "memcpy_s err");
        return false;
    }
    char *tokSave = NULL;
    char *token = strtok_r(tmp, PEER_DISCOVERY_INTERVAL, &tokSave);
    uint32_t count = DISCOVERY_TYPE_JUDGE_NUM;
    for (uint32_t i = 0; i < count; i++) {
        if (token == NULL || tokSave == NULL) {
            SoftBusFree(tmp);
            return false;
        }
        if (strcmp(token, destType) == 0) {
            SoftBusFree(tmp);
            return true;
        } else if (strcmp(tokSave, destType) == 0) {
            SoftBusFree(tmp);
            return true;
        }
        token = strtok_r(NULL, PEER_DISCOVERY_INTERVAL, &tokSave);
    }
    SoftBusFree(tmp);
    return false;
}

NO_SANITIZE("cfi") bool LnnPeerHasExchangeDiscoveryType(const NodeInfo *info, DiscoveryType type)
{
    if (info == NULL || type >= DISCOVERY_TYPE_COUNT) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "para error!");
        return false;
    }
    if (((uint32_t)info->exchangeDiscoveryType & (1 << (uint32_t)type)) != 0) {
        return true;
    }
    return false;
}

NO_SANITIZE("cfi") bool LnnHasDiscoveryType(const NodeInfo *info, DiscoveryType type)
{
    if (info == NULL || type >= DISCOVERY_TYPE_COUNT) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "para error!");
        return false;
    }
    if (((uint32_t)info->discoveryType & (1 << (uint32_t)type)) != 0) {
        return true;
    }
    return false;
}

NO_SANITIZE("cfi") const char *LnnGetDeviceUdid(const NodeInfo *info)
{
    if (info == NULL) {
        return NULL;
    }
    return info->deviceInfo.deviceUdid;
}

NO_SANITIZE("cfi") int32_t LnnSetDeviceUdid(NodeInfo *info, const char *udid)
{
    if (info == NULL || udid == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (strncpy_s(info->deviceInfo.deviceUdid, UDID_BUF_LEN, udid, strlen(udid)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "STR COPY ERROR!");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

NO_SANITIZE("cfi") int32_t LnnSetDiscoveryType(NodeInfo *info, DiscoveryType type)
{
    if (info == NULL || type >= DISCOVERY_TYPE_COUNT) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "para error!");
        return SOFTBUS_INVALID_PARAM;
    }
    info->discoveryType = (uint32_t)info->discoveryType | (1 << (uint32_t)type);
    return SOFTBUS_OK;
}

NO_SANITIZE("cfi") int32_t LnnClearDiscoveryType(NodeInfo *info, DiscoveryType type)
{
    if (info == NULL || type >= DISCOVERY_TYPE_COUNT) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "para error!");
        return SOFTBUS_INVALID_PARAM;
    }
    info->discoveryType = (uint32_t)info->discoveryType & ~(1 << (uint32_t)type);
    return SOFTBUS_OK;
}

NO_SANITIZE("cfi") bool LnnIsNodeOnline(const NodeInfo *info)
{
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "para error!");
        return false;
    }
    return (info->status == STATUS_ONLINE);
}

NO_SANITIZE("cfi") void LnnSetNodeConnStatus(NodeInfo *info, ConnectStatus status)
{
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "para error!!!");
        return;
    }
    info->status = status;
}

NO_SANITIZE("cfi") const char *LnnGetBtMac(const NodeInfo *info)
{
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "para error!");
        return DEFAULT_MAC;
    }
    return info->connectInfo.macAddr;
}

NO_SANITIZE("cfi") void LnnSetBtMac(NodeInfo *info, const char *mac)
{
    if (info == NULL || mac == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "PARA ERROR!");
        return;
    }
    if (strncpy_s(info->connectInfo.macAddr, MAC_LEN, mac, strlen(mac)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "str copy error!");
    }
    return;
}

NO_SANITIZE("cfi") const char *LnnGetNetIfName(const NodeInfo *info)
{
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "para error!");
        return DEFAULT_MAC;
    }
    return info->connectInfo.netIfName;
}

NO_SANITIZE("cfi") void LnnSetNetIfName(NodeInfo *info, const char *netIfName)
{
    if (info == NULL || netIfName == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "PARA ERROR!");
        return;
    }
    if (strncpy_s(info->connectInfo.netIfName, NET_IF_NAME_LEN, netIfName, strlen(netIfName)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "str copy error!");
    }
    return;
}

NO_SANITIZE("cfi") const char *LnnGetWiFiIp(const NodeInfo *info)
{
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "PARA error!");
        return DEFAULT_IP;
    }
    return info->connectInfo.deviceIp;
}

NO_SANITIZE("cfi") void LnnSetWiFiIp(NodeInfo *info, const char *ip)
{
    if (info == NULL || ip == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "PARA ERROR!");
        return;
    }
    if (strncpy_s(info->connectInfo.deviceIp, sizeof(info->connectInfo.deviceIp), ip, strlen(ip)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "STR COPY ERROR!");
    }
    return;
}

NO_SANITIZE("cfi") const char *LnnGetMasterUdid(const NodeInfo *info)
{
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "PARA ERROR!");
        return NULL;
    }
    return info->masterUdid;
}

NO_SANITIZE("cfi") int32_t LnnSetMasterUdid(NodeInfo *info, const char *udid)
{
    if (info == NULL || udid == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "PARA ERROR!");
        return SOFTBUS_INVALID_PARAM;
    }
    if (strncpy_s(info->masterUdid, UDID_BUF_LEN, udid, strlen(udid)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "STR COPY ERROR!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

NO_SANITIZE("cfi") int32_t LnnGetAuthPort(const NodeInfo *info)
{
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "para error");
        return SOFTBUS_INVALID_PARAM;
    }
    return info->connectInfo.authPort;
}

NO_SANITIZE("cfi") int32_t LnnSetAuthPort(NodeInfo *info, int32_t port)
{
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "para error.");
        return SOFTBUS_INVALID_PARAM;
    }
    info->connectInfo.authPort = port;
    return SOFTBUS_OK;
}

NO_SANITIZE("cfi") int32_t LnnGetSessionPort(const NodeInfo *info)
{
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "para error!");
        return SOFTBUS_INVALID_PARAM;
    }
    return info->connectInfo.sessionPort;
}

NO_SANITIZE("cfi") int32_t LnnSetSessionPort(NodeInfo *info, int32_t port)
{
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "para error!");
        return SOFTBUS_INVALID_PARAM;
    }
    info->connectInfo.sessionPort = port;
    return SOFTBUS_OK;
}

NO_SANITIZE("cfi") int32_t LnnGetProxyPort(const NodeInfo *info)
{
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "para error!");
        return SOFTBUS_INVALID_PARAM;
    }
    return info->connectInfo.proxyPort;
}

NO_SANITIZE("cfi") int32_t LnnSetProxyPort(NodeInfo *info, int32_t port)
{
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "para error!");
        return SOFTBUS_OK;
    }
    info->connectInfo.proxyPort = port;
    return SOFTBUS_OK;
}

NO_SANITIZE("cfi") int32_t LnnSetP2pRole(NodeInfo *info, int32_t p2pRole)
{
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "%s:invalid param.", __func__);
        return SOFTBUS_INVALID_PARAM;
    }
    info->p2pInfo.p2pRole = p2pRole;
    return SOFTBUS_OK;
}

NO_SANITIZE("cfi") int32_t LnnGetP2pRole(const NodeInfo *info)
{
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "%s:invalid param.", __func__);
        return 0;
    }
    return info->p2pInfo.p2pRole;
}

NO_SANITIZE("cfi") int32_t LnnSetP2pMac(NodeInfo *info, const char *p2pMac)
{
    if (info == NULL || p2pMac == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "%s:invalid param.", __func__);
        return SOFTBUS_INVALID_PARAM;
    }
    if (strcpy_s(info->p2pInfo.p2pMac, sizeof(info->p2pInfo.p2pMac), p2pMac) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "strcpy_s p2p mac err.");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

NO_SANITIZE("cfi") const char *LnnGetP2pMac(const NodeInfo *info)
{
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "%s:invalid param.", __func__);
        return NULL;
    }
    return info->p2pInfo.p2pMac;
}

NO_SANITIZE("cfi") int32_t LnnSetDataChangeFlag(NodeInfo *info, uint16_t dataChangeFlag)
{
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "%s:invalid param.", __func__);
        return SOFTBUS_INVALID_PARAM;
    }
    info->dataChangeFlag = dataChangeFlag;
    return SOFTBUS_OK;
}

NO_SANITIZE("cfi") uint16_t LnnGetDataChangeFlag(const NodeInfo *info)
{
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "%s:invalid param.", __func__);
        return 0;
    }
    return info->dataChangeFlag;
}

NO_SANITIZE("cfi") int32_t LnnSetP2pGoMac(NodeInfo *info, const char *goMac)
{
    if (info == NULL || goMac == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "%s:invalid param.", __func__);
        return SOFTBUS_INVALID_PARAM;
    }

    if (strcpy_s(info->p2pInfo.goMac, sizeof(info->p2pInfo.goMac), goMac) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "strcpy_s go mac err.");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

NO_SANITIZE("cfi") const char *LnnGetP2pGoMac(const NodeInfo *info)
{
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "%s:invalid param.", __func__);
        return NULL;
    }
    return info->p2pInfo.goMac;
}

NO_SANITIZE("cfi") uint64_t LnnGetSupportedProtocols(const NodeInfo *info)
{
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "%s:invalid param.", __func__);
        return 0;
    }
    return info->supportedProtocols;
}

NO_SANITIZE("cfi") int32_t LnnSetSupportedProtocols(NodeInfo *info, uint64_t protocols)
{
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "para error!");
        return SOFTBUS_OK;
    }
    info->supportedProtocols = protocols;
    return SOFTBUS_OK;
}
