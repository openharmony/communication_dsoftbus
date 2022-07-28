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

#include "lnn_network_manager.h"

#include <securec.h>

#include "auth_interface.h"
#include "bus_center_manager.h"
#include "disc_interface.h"
#include "lnn_discovery_manager.h"
#include "lnn_ohos_account.h"
#include "lnn_physical_subnet_manager.h"
#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"
#include "softbus_feature_config.h"
#include "softbus_log.h"

#define LNN_MAX_IF_NAME_LEN   256
#define LNN_DELIMITER_OUTSIDE ","
#define LNN_DELIMITER_INSIDE  ":"

#define LNN_DEFAULT_IF_NAME_WLAN "wlan0"
#define LNN_DEFAULT_IF_NAME_ETH  "eth0"

typedef enum {
    LNN_ETH_TYPE = 0,
    LNN_WLAN_TYPE,
    LNN_MAX_NUM_TYPE,
} LnnNetIfNameType;

static ListNode g_netIfNameList = {
    .prev = &g_netIfNameList,
    .next = &g_netIfNameList,
};

int32_t RegistIPProtocolManager(void);
int32_t RegistNewIPProtocolManager(void);

int32_t __attribute__((weak)) RegistNewIPProtocolManager(void)
{
    return SOFTBUS_OK;
}

static LnnNetIfManagerBuilder g_netifBuilders[LNN_MAX_NUM_TYPE] = {0};

static LnnProtocolManager *g_networkProtocols[LNN_NETWORK_MAX_PROTOCOL_COUNT] = {0};

static LnnNetIfMgr *CreateEthNetifMgr(const char *netIfName)
{
    if (netIfName == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "parameters invalid!");
        return NULL;
    }
    LnnNetIfMgr *netIfMgr = (LnnNetIfMgr *)SoftBusCalloc(sizeof(LnnNetIfMgr));
    if (netIfMgr == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: malloc LnnNetIfMgr");
        return NULL;
    }
    do {
        ListInit(&netIfMgr->node);
        if (strncpy_s(netIfMgr->ifName, NET_IF_NAME_LEN, netIfName, strlen(netIfName)) != EOK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy netIfName fail");
            break;
        }
        return netIfMgr;
    } while (false);

    SoftBusFree(netIfMgr);
    return NULL;
}

static int32_t RegistNetIfMgr(LnnNetIfNameType type, LnnNetIfManagerBuilder builder)
{
    if (type >= LNN_MAX_NUM_TYPE) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "%s:type too big!", __func__);
        return SOFTBUS_ERR;
    }

    if (g_netifBuilders[type] != NULL && g_netifBuilders[type] != builder) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "%s:type already registed!", __func__);
        return SOFTBUS_ERR;
    }
    g_netifBuilders[type] = builder;
    return SOFTBUS_OK;
}

static LnnNetIfType ConvertToNetIfType(LnnNetIfNameType nameType)
{
    return nameType >= LNN_MAX_NUM_TYPE ? 0 : (0x1 << nameType);
}

static LnnNetIfMgr *NetifMgrFactory(LnnNetIfNameType type, const char *ifName)
{
    if (type >= LNN_MAX_NUM_TYPE) {
        return NULL;
    }
    if (g_netifBuilders[type] == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "netif type %d not supportted!", type);
        return NULL;
    }
    LnnNetIfMgr *netifMgr = g_netifBuilders[type](ifName);
    if (netifMgr != NULL) {
        netifMgr->type = ConvertToNetIfType(type);
    }
    return netifMgr;
}

static int32_t ParseIfNameConfig(char *buf, uint32_t bufLen)
{
    char *outerPtr = NULL;
    char *innerPtr = NULL;
    char *value1 = NULL;
    char *value2 = NULL;
    if (buf == NULL || bufLen <= 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "parameters invaild!");
        return SOFTBUS_ERR;
    }
    char *key = strtok_r(buf, LNN_DELIMITER_OUTSIDE, &outerPtr);
    while (key != NULL) {
        value1 = strtok_r(key, LNN_DELIMITER_INSIDE, &innerPtr);
        value2 = strtok_r(NULL, LNN_DELIMITER_INSIDE, &innerPtr);

        LnnNetIfMgr *netIfMgr = NetifMgrFactory(atoi(value1), value2);
        if (netIfMgr != NULL) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_WARN, "Create netif mgr [%s],[%s]", value1, value2);
            ListTailInsert(&g_netIfNameList, &netIfMgr->node);
        } else {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "Create netif mgr failed!,[%s],[%s]", value1, value2);
        }
        key = strtok_r(NULL, LNN_DELIMITER_OUTSIDE, &outerPtr);
    }
    return SOFTBUS_OK;
}

static int32_t SetIfNameDefaultVal(void)
{
    LnnNetIfMgr *netIfMgr = NetifMgrFactory(LNN_ETH_TYPE, LNN_DEFAULT_IF_NAME_ETH);
    if (netIfMgr == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "add default ETH port failed!");
        return SOFTBUS_ERR;
    }
    ListTailInsert(&g_netIfNameList, &netIfMgr->node);

    netIfMgr = NetifMgrFactory(LNN_WLAN_TYPE, LNN_DEFAULT_IF_NAME_WLAN);
    if (netIfMgr == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "add default ETH port failed!");
        return SOFTBUS_ERR;
    }
    ListTailInsert(&g_netIfNameList, &netIfMgr->node);
    return SOFTBUS_OK;
}

static int32_t LnnInitManagerByConfig(void)
{
    char netIfName[LNN_MAX_IF_NAME_LEN] = {0};
    if (SoftbusGetConfig(SOFTBUS_STR_LNN_NET_IF_NAME, (unsigned char *)netIfName, sizeof(netIfName)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get lnn net ifName fail, use default value");
        if (SetIfNameDefaultVal() != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "default value set fail");
            return SOFTBUS_ERR;
        }
        return SOFTBUS_OK;
    }
    if (ParseIfNameConfig(netIfName, strlen(netIfName)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ifName str parse fail!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnClearNetConfigList(void)
{
    LnnNetIfMgr *item = NULL;
    LnnNetIfMgr *next = NULL;

    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_netIfNameList, LnnNetIfMgr, node)
    {
        ListDelete(&item->node);
        SoftBusFree(item);
    }
    return SOFTBUS_OK;
}

int32_t LnnRegistProtocol(LnnProtocolManager *protocolMgr)
{
    int32_t ret = SOFTBUS_OK;

    if (protocolMgr == NULL || protocolMgr->GetListenerModule == NULL || protocolMgr->Init == NULL ||
        protocolMgr->Enable == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "%s:bad input protocol!", __func__);
        return SOFTBUS_ERR;
    }

    for (uint8_t i = 0; i < LNN_NETWORK_MAX_PROTOCOL_COUNT; i++) {
        if (g_networkProtocols[i] != NULL) {
            continue;
        }
        if (protocolMgr->Init != NULL) {
            ret = protocolMgr->Init(protocolMgr);
            if (ret != SOFTBUS_OK) {
                SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "init network protocol failed!ret=%d\n", ret);
                break;
            }
        } else {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_WARN, "network protocol have no init\n");
        }
        g_networkProtocols[i] = protocolMgr;
        break;
    }
    return ret;
}

int32_t UnregistProtocol(LnnProtocolManager *protocolMgr)
{
    uint8_t i;
    if (protocolMgr == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "%s:null ptr!\n", __func__);
        return SOFTBUS_ERR;
    }

    for (i = 0; i < LNN_NETWORK_MAX_PROTOCOL_COUNT; i++) {
        if (g_networkProtocols[i] == protocolMgr) {
            g_networkProtocols[i] = NULL;
            if (protocolMgr->Deinit != NULL) {
                protocolMgr->Deinit(protocolMgr);
            }
            return SOFTBUS_OK;
        }
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "%s:no such protocol!\n", __func__);
    return SOFTBUS_ERR;
}

bool LnnVisitNetif(VisitNetifCallback callback, void *data)
{
    LnnNetIfMgr *item = NULL;
    VisitNextChoice result = CHOICE_VISIT_NEXT;
    LIST_FOR_EACH_ENTRY(item, &g_netIfNameList, LnnNetIfMgr, node)
    {
        result = callback(item, data);
        if (result == CHOICE_FINISH_VISITING) {
            return false;
        }
    }
    return true;
}

bool LnnVisitProtocol(VisitProtocolCallback callback, void *data)
{
    VisitNextChoice result = CHOICE_VISIT_NEXT;
    for (uint8_t i = 0; i < LNN_NETWORK_MAX_PROTOCOL_COUNT; i++) {
        if (g_networkProtocols[i] == NULL) {
            continue;
        }
        result = callback(g_networkProtocols[i], data);
        if (result == CHOICE_FINISH_VISITING) {
            return false;
        }
    }
    return true;
}

static void RestartCoapDiscovery(void)
{
    char ifName[NET_IF_NAME_LEN] = {0};
    int32_t authPort = 0;
    if (LnnGetLocalStrInfo(STRING_KEY_NET_IF_NAME, ifName, NET_IF_NAME_LEN) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get local ifName error!\n");
        return;
    }
    if (strncmp(ifName, LNN_LOOPBACK_IFNAME, strlen(LNN_LOOPBACK_IFNAME)) == 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "ip invalid now, stop group create");
        return;
    }
    if (LnnGetLocalNumInfo(NUM_KEY_AUTH_PORT, &authPort) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get local auth port failed.");
        return;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "open previous discovery again");
    LnnStopDiscovery();
    if (LnnStartDiscovery() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "start discovery failed\n");
    }
    SetCallLnnStatus(true);
}

static void OnAccountChanged(void)
{
    uint8_t accountHash[SHA_256_HASH_LEN] = {0};
    uint8_t localAccountHash[SHA_256_HASH_LEN] = {0};
    if (LnnGetLocalByteInfo(BYTE_KEY_USERID_HASH, localAccountHash, SHA_256_HASH_LEN) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "OnAccountChanged get local user id fail");
        return;
    }
    if (LnnGetOhosAccountInfo(accountHash, SHA_256_HASH_LEN) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "OnAccountChanged get account user id fail");
        return;
    }
    if (memcmp(accountHash, localAccountHash, SHA_256_HASH_LEN) == EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "OnAccountChanged account not change");
        return;
    }

    LnnSetLocalByteInfo(BYTE_KEY_USERID_HASH, accountHash, SHA_256_HASH_LEN);
    DiscDeviceInfoChanged(TYPE_ACCOUNT);
}

static void OnGroupCreated(const char *groupId)
{
    (void)groupId;
    RestartCoapDiscovery();
    OnAccountChanged();
}

static void OnGroupDeleted(const char *groupId)
{
    (void)groupId;
    OnAccountChanged();
}

static VerifyCallback g_verifyCb = {
    .onGroupCreated = OnGroupCreated,
    .onGroupDeleted = OnGroupDeleted,
};

static VisitNextChoice GetAllProtocols(const LnnProtocolManager *manager, void *data)
{
    if (manager == NULL || data == NULL) {
        return CHOICE_FINISH_VISITING;
    }

    ProtocolType *type = (ProtocolType *)data;
    *type |= manager->id;
    return CHOICE_VISIT_NEXT;
}

int32_t LnnInitNetworkManager(void)
{
    RegistNetIfMgr(LNN_ETH_TYPE, CreateEthNetifMgr);
    RegistNetIfMgr(LNN_WLAN_TYPE, CreateEthNetifMgr);

    int32_t ret = LnnInitManagerByConfig();
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "Read net config failed!ret=%d\n", ret);
        return ret;
    }

    // Regist default protocols
    ret = RegistIPProtocolManager();
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "regist ip protocol manager failed,ret=%d\n", ret);
        return ret;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "IP protocol registed.\n");

    ret = RegistNewIPProtocolManager();
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "regist newip protocol manager failed,ret=%d\n", ret);
        return ret;
    }

    ret = AuthRegCallback(BUSCENTER_MONITOR, &g_verifyCb);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "register auth callback fail");
        return ret;
    }

    ret = LnnInitPhysicalSubnetManager();
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "init subnet manager failed!,ret=%d\n", ret);
        return ret;
    }

    ProtocolType type = 0;
    if (!LnnVisitProtocol(GetAllProtocols, &type)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "Get all protocol failed!");
        return SOFTBUS_ERR;
    }

    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "set supported protocol to %lld.", type);
    ret = LnnSetLocalNum64Info(NUM_KEY_TRANS_PROTOCOLS, (int64_t)type);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "set supported protocol failed!,ret=%d\n", ret);
        return ret;
    }

    return SOFTBUS_OK;
}

int32_t LnnInitNetworkManagerDelay(void)
{
    uint32_t i;

    char udid[UDID_BUF_LEN] = {0};
    if (LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, udid, UDID_BUF_LEN) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get local udid error!\n");
        return SOFTBUS_ERR;
    }

    LnnNetIfMgr *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_netIfNameList, LnnNetIfMgr, node)
    {
        for (i = 0; i < LNN_NETWORK_MAX_PROTOCOL_COUNT; ++i) {
            if (g_networkProtocols[i] == NULL) {
                continue;
            }
            if ((g_networkProtocols[i]->supportedNetif & item->type) != 0) {
                int32_t ret = g_networkProtocols[i]->Enable(g_networkProtocols[i], item);
                if (ret != SOFTBUS_OK) {
                    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "enable protocol (%d) for netif %s failed\n", i,
                        item->ifName);
                }
                SoftBusLog(
                    SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "enable protocol (%d) for netif %s success\n", i, item->ifName);
            }
        }
    }
    return SOFTBUS_OK;
}

bool LnnIsAutoNetWorkingEnabled(void)
{
    bool isEnabled = false;
    if (SoftbusGetConfig(SOFTBUS_INT_AUTO_NETWORKING_SWITCH, (unsigned char *)&isEnabled,
        sizeof(LnnIsAutoNetWorkingEnabled())) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "Cannot get autoNetworkingSwitch from config file");
        return true;
    }
    return isEnabled;
}

void LnnDeinitNetworkManager(void)
{
    uint32_t i;
    if (LnnClearNetConfigList() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "deinit network manager failed\n");
    }

    LnnDeinitPhysicalSubnetManager();

    for (i = 0; i < LNN_NETWORK_MAX_PROTOCOL_COUNT; ++i) {
        if (g_networkProtocols[i] == NULL || g_networkProtocols[i]->Deinit == NULL) {
            continue;
        }
        g_networkProtocols[i]->Deinit(g_networkProtocols[i]);
        g_networkProtocols[i] = NULL;
    }
}

int32_t LnnGetNetIfTypeByName(const char *ifName, LnnNetIfType *type)
{
    if (ifName == NULL || type == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "parameters are NULL!");
        return SOFTBUS_ERR;
    }
    LnnNetIfMgr *netif = NULL;
    LIST_FOR_EACH_ENTRY(netif, &g_netIfNameList, LnnNetIfMgr, node)
    {
        if (strncmp(ifName, netif->ifName, sizeof(netif->ifName)) == 0) {
            *type = netif->type;
            return SOFTBUS_OK;
        }
    }
    return SOFTBUS_ERR;
}
int32_t LnnGetAddrTypeByIfName(const char *ifName, ConnectionAddrType *type)
{
    if (type == NULL || ifName == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "parameters are NULL!");
        return SOFTBUS_ERR;
    }
    LnnNetIfType netifType;
    int32_t ret = LnnGetNetIfTypeByName(ifName, &netifType);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    switch (netifType) {
        case LNN_NETIF_TYPE_ETH:
            *type = CONNECTION_ADDR_ETH;
            break;
        case LNN_NETIF_TYPE_WLAN:
            *type = CONNECTION_ADDR_WLAN;
            break;
        default:
            ret = SOFTBUS_ERR;
    }
    return ret;
}

struct FindProtocolByTypeRequest {
    ProtocolType protocol;
    LnnProtocolManager *manager;
};

static VisitNextChoice FindProtocolByType(const LnnProtocolManager *manager, void *data)
{
    struct FindProtocolByTypeRequest *request = (struct FindProtocolByTypeRequest *)data;
    if (manager->id == request->protocol) {
        request->manager = manager;
        return CHOICE_FINISH_VISITING;
    } else {
        return CHOICE_VISIT_NEXT;
    }
}

ListenerModule LnnGetProtocolListenerModule(ProtocolType protocol, ListenerMode mode)
{
    struct FindProtocolByTypeRequest request = {.protocol = protocol, .manager = NULL};
    if (LnnVisitProtocol(FindProtocolByType, &request)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "%s: not such protocol! protocolId=%d", __func__, protocol);
        return UNUSE_BUTT;
    }
    if (request.manager == NULL) {
        SoftBusLog(
            SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "%s: protocol manager is null! protocolId=%d", __func__, protocol);
        return UNUSE_BUTT;
    }
    return request.manager->GetListenerModule(mode);
}
