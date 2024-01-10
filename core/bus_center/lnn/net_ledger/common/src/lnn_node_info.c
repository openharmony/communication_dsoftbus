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

#include "lnn_log.h"
#include "softbus_errcode.h"

bool LnnHasDiscoveryType(const NodeInfo *info, DiscoveryType type)
{
    if (info == NULL || type >= DISCOVERY_TYPE_COUNT) {
        LNN_LOGE(LNN_LEDGER, "para error");
        return false;
    }
    if (((uint32_t)info->discoveryType & (1 << (uint32_t)type)) != 0) {
        return true;
    }
    return false;
}

const char *LnnGetDeviceUdid(const NodeInfo *info)
{
    if (info == NULL) {
        return NULL;
    }
    return info->deviceInfo.deviceUdid;
}

int32_t LnnSetDeviceUdid(NodeInfo *info, const char *udid)
{
    if (info == NULL || udid == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (strncpy_s(info->deviceInfo.deviceUdid, UDID_BUF_LEN, udid, strlen(udid)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "STR COPY ERROR");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

const char *LnnGetDeviceUuid(const NodeInfo *info)
{
    if (info == NULL) {
        return NULL;
    }
    return info->uuid;
}

int32_t LnnSetDiscoveryType(NodeInfo *info, DiscoveryType type)
{
    if (info == NULL || type >= DISCOVERY_TYPE_COUNT) {
        LNN_LOGE(LNN_LEDGER, "para error");
        return SOFTBUS_INVALID_PARAM;
    }
    info->discoveryType = (uint32_t)info->discoveryType | (1 << (uint32_t)type);
    return SOFTBUS_OK;
}

int32_t LnnClearDiscoveryType(NodeInfo *info, DiscoveryType type)
{
    if (info == NULL || type >= DISCOVERY_TYPE_COUNT) {
        LNN_LOGE(LNN_LEDGER, "para error");
        return SOFTBUS_INVALID_PARAM;
    }
    info->discoveryType = (uint32_t)info->discoveryType & ~(1 << (uint32_t)type);
    return SOFTBUS_OK;
}

bool LnnIsNodeOnline(const NodeInfo *info)
{
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "para error");
        return false;
    }
    return (info->status == STATUS_ONLINE);
}

void LnnSetNodeConnStatus(NodeInfo *info, ConnectStatus status)
{
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "para error");
        return;
    }
    info->status = status;
}

const char *LnnGetBtMac(const NodeInfo *info)
{
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "para error");
        return DEFAULT_MAC;
    }
    return info->connectInfo.macAddr;
}

void LnnSetBtMac(NodeInfo *info, const char *mac)
{
    if (info == NULL || mac == NULL) {
        LNN_LOGE(LNN_LEDGER, "PARA ERROR");
        return;
    }
    if (strncpy_s(info->connectInfo.macAddr, MAC_LEN, mac, strlen(mac)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "str copy error");
    }
}

const char *LnnGetBleMac(const NodeInfo *info)
{
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "PARA ERROR");
        return DEFAULT_MAC;
    }
    return info->connectInfo.bleMacAddr;
}

void LnnSetBleMac(NodeInfo *info, const char *mac)
{
    if (info == NULL || mac == NULL) {
        LNN_LOGE(LNN_LEDGER, "PARA ERROR");
        return;
    }
    if (strcpy_s(info->connectInfo.bleMacAddr, MAC_LEN, mac) != EOK) {
        LNN_LOGE(LNN_LEDGER, "str copy error");
    }
}

const char *LnnGetNetIfName(const NodeInfo *info)
{
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "para error");
        return DEFAULT_IFNAME;
    }
    return info->connectInfo.netIfName;
}

void LnnSetNetIfName(NodeInfo *info, const char *netIfName)
{
    if (info == NULL || netIfName == NULL) {
        LNN_LOGE(LNN_LEDGER, "PARA ERROR");
        return;
    }
    if (strncpy_s(info->connectInfo.netIfName, NET_IF_NAME_LEN, netIfName, strlen(netIfName)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "str copy error");
    }
}

const char *LnnGetWiFiIp(const NodeInfo *info)
{
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "PARA error");
        return DEFAULT_IP;
    }
    return info->connectInfo.deviceIp;
}

void LnnSetWiFiIp(NodeInfo *info, const char *ip)
{
    if (info == NULL || ip == NULL) {
        LNN_LOGE(LNN_LEDGER, "PARA ERROR");
        return;
    }
    if (strncpy_s(info->connectInfo.deviceIp, sizeof(info->connectInfo.deviceIp), ip, strlen(ip)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "STR COPY ERROR");
    }
}

const char *LnnGetMasterUdid(const NodeInfo *info)
{
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "PARA ERROR");
        return NULL;
    }
    return info->masterUdid;
}

int32_t LnnSetMasterUdid(NodeInfo *info, const char *udid)
{
    if (info == NULL || udid == NULL) {
        LNN_LOGE(LNN_LEDGER, "PARA ERROR");
        return SOFTBUS_INVALID_PARAM;
    }
    if (strncpy_s(info->masterUdid, UDID_BUF_LEN, udid, strlen(udid)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "STR COPY ERROR");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnGetAuthPort(const NodeInfo *info)
{
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "para error");
        return SOFTBUS_INVALID_PARAM;
    }
    return info->connectInfo.authPort;
}

int32_t LnnSetAuthPort(NodeInfo *info, int32_t port)
{
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "para error");
        return SOFTBUS_INVALID_PARAM;
    }
    info->connectInfo.authPort = port;
    return SOFTBUS_OK;
}

int32_t LnnGetSessionPort(const NodeInfo *info)
{
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "para error");
        return SOFTBUS_INVALID_PARAM;
    }
    return info->connectInfo.sessionPort;
}

int32_t LnnSetSessionPort(NodeInfo *info, int32_t port)
{
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "para error");
        return SOFTBUS_INVALID_PARAM;
    }
    info->connectInfo.sessionPort = port;
    return SOFTBUS_OK;
}

int32_t LnnGetProxyPort(const NodeInfo *info)
{
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "para error");
        return SOFTBUS_INVALID_PARAM;
    }
    return info->connectInfo.proxyPort;
}

int32_t LnnSetProxyPort(NodeInfo *info, int32_t port)
{
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "para error");
        return SOFTBUS_OK;
    }
    info->connectInfo.proxyPort = port;
    return SOFTBUS_OK;
}

int32_t LnnSetP2pRole(NodeInfo *info, int32_t p2pRole)
{
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    info->p2pInfo.p2pRole = p2pRole;
    return SOFTBUS_OK;
}

int32_t LnnGetP2pRole(const NodeInfo *info)
{
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return 0;
    }
    return info->p2pInfo.p2pRole;
}

int32_t LnnSetWifiCfg(NodeInfo *info, const char *wifiCfg)
{
    if (info == NULL || wifiCfg == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (strcpy_s(info->p2pInfo.wifiCfg, sizeof(info->p2pInfo.wifiCfg), wifiCfg) != EOK) {
        LNN_LOGE(LNN_LEDGER, "strcpy_s wifi cfg err");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

const char *LnnGetWifiCfg(const NodeInfo *info)
{
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return 0;
    }
    return info->p2pInfo.wifiCfg;
}

int32_t LnnSetChanList5g(NodeInfo *info, const char *chanList5g)
{
    if (info == NULL || chanList5g == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (strcpy_s(info->p2pInfo.chanList5g, sizeof(info->p2pInfo.chanList5g), chanList5g) != EOK) {
        LNN_LOGE(LNN_LEDGER, "strcpy_s chan list 5g err");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

const char *LnnGetChanList5g(const NodeInfo *info)
{
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return 0;
    }
    return info->p2pInfo.chanList5g;
}

int32_t LnnSetStaFrequency(NodeInfo *info, int32_t staFrequency)
{
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    info->p2pInfo.staFrequency = staFrequency;
    return SOFTBUS_OK;
}

int32_t LnnGetStaFrequency(const NodeInfo *info)
{
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return 0;
    }
    return info->p2pInfo.staFrequency;
}

int32_t LnnSetP2pMac(NodeInfo *info, const char *p2pMac)
{
    if (info == NULL || p2pMac == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (strcpy_s(info->p2pInfo.p2pMac, sizeof(info->p2pInfo.p2pMac), p2pMac) != EOK) {
        LNN_LOGE(LNN_LEDGER, "strcpy_s p2p mac err");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

const char *LnnGetP2pMac(const NodeInfo *info)
{
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return NULL;
    }
    return info->p2pInfo.p2pMac;
}

const char *LnnGetWifiDirectAddr(const NodeInfo *info)
{
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return NULL;
    }
    return info->wifiDirectAddr;
}

int32_t LnnSetDataChangeFlag(NodeInfo *info, uint16_t dataChangeFlag)
{
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    info->dataChangeFlag = dataChangeFlag;
    return SOFTBUS_OK;
}

uint16_t LnnGetDataChangeFlag(const NodeInfo *info)
{
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return 0;
    }
    return info->dataChangeFlag;
}

int32_t LnnSetP2pGoMac(NodeInfo *info, const char *goMac)
{
    if (info == NULL || goMac == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (strcpy_s(info->p2pInfo.goMac, sizeof(info->p2pInfo.goMac), goMac) != EOK) {
        LNN_LOGE(LNN_LEDGER, "strcpy_s go mac err");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

const char *LnnGetP2pGoMac(const NodeInfo *info)
{
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return NULL;
    }
    return info->p2pInfo.goMac;
}

uint64_t LnnGetSupportedProtocols(const NodeInfo *info)
{
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "para error");
        return 0;
    }
    return info->supportedProtocols;
}

int32_t LnnSetSupportedProtocols(NodeInfo *info, uint64_t protocols)
{
    if (info == NULL) {
        LNN_LOGE(LNN_LEDGER, "para error");
        return SOFTBUS_OK;
    }
    info->supportedProtocols = protocols;
    return SOFTBUS_OK;
}

int32_t LnnSetStaticCapability(NodeInfo *info, uint8_t *cap, uint32_t len)
{
    if (info == NULL || cap == NULL) {
        LNN_LOGE(LNN_LEDGER, "param is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (len <= 0 || len > STATIC_CAP_LEN) {
        LNN_LOGE(LNN_LEDGER, "length error");
        return SOFTBUS_INVALID_PARAM;
    }
    if (memcpy_s(info->staticCapability, STATIC_CAP_LEN, cap, len) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memcpy static cap err");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnGetStaticCapability(NodeInfo *info, uint8_t *cap, uint32_t len)
{
    if (info == NULL || cap == NULL) {
        LNN_LOGE(LNN_LEDGER, "param err");
        return SOFTBUS_INVALID_PARAM;
    }
    if (len < 0 || len > STATIC_CAP_LEN) {
        LNN_LOGE(LNN_LEDGER, "param err");
        return SOFTBUS_INVALID_PARAM;
    }
    if (memcpy_s(cap, len, info->staticCapability, info->staticCapLen) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memcpy static cap err");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnSetPtk(NodeInfo *info, const char *remotePtk)
{
    if (info == NULL || remotePtk == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (memcpy_s(info->remotePtk, PTK_DEFAULT_LEN, remotePtk, PTK_DEFAULT_LEN) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memcpy ptk err");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnSetWifiDirectAddr(NodeInfo *info, const char *wifiDirectAddr)
{
    if (info == NULL || wifiDirectAddr == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (strcpy_s(info->wifiDirectAddr, sizeof(info->wifiDirectAddr), wifiDirectAddr) != EOK) {
        LNN_LOGE(LNN_LEDGER, "strcpy_s wifidirect addr err");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}