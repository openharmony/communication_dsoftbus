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
#include "lnn_async_callback_utils.h"
#include "lnn_common_utils.h"
#include "lnn_discovery_manager.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_heartbeat_ctrl.h"
#include "lnn_net_builder.h"
#include "lnn_ohos_account.h"
#include "lnn_physical_subnet_manager.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_feature_config.h"
#include "softbus_log_old.h"

#define LNN_MAX_IF_NAME_LEN   256
#define LNN_DELIMITER_OUTSIDE ","
#define LNN_DELIMITER_INSIDE  ":"

#define LNN_DEFAULT_IF_NAME_WLAN "wlan0"
#define LNN_DEFAULT_IF_NAME_ETH  "eth0"
#define LNN_DEFAULT_IF_NAME_BR   "br0"
#define LNN_DEFAULT_IF_NAME_BLE  "ble0"

#define LNN_CHECK_OOBE_DELAY_LEN (5 * 60 * 1000LL)

typedef enum {
    LNN_ETH_TYPE = 0,
    LNN_WLAN_TYPE,
    LNN_BR_TYPE,
    LNN_BLE_TYPE,
    LNN_MAX_NUM_TYPE,
} LnnNetIfNameType;

static ListNode g_netIfNameList = {
    .prev = &g_netIfNameList,
    .next = &g_netIfNameList,
};

static ListNode *g_nightOnCache = NULL;

typedef struct {
    ListNode node;
    ConnectionAddr addrs;
} DeviceNightMode;

static bool g_isNightMode = false;
static bool g_isOOBEEnd = false;
static bool g_isUnLock = false;
static SoftBusUserState g_backgroundState = SOFTBUS_USER_FOREGROUND;

int32_t RegistIPProtocolManager(void);
int32_t RegistNewIPProtocolManager(void);

int32_t __attribute__((weak)) RegistNewIPProtocolManager(void)
{
    return SOFTBUS_OK;
}

int32_t __attribute__((weak)) RegistBtProtocolManager(void)
{
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_WARN, "regist virtual bt protocol manager");
    return SOFTBUS_OK;
}

static LnnNetIfManagerBuilder g_netifBuilders[LNN_MAX_NUM_TYPE] = {0};

static LnnProtocolManager *g_networkProtocols[LNN_NETWORK_MAX_PROTOCOL_COUNT] = {0};

static LnnNetIfMgr *CreateNetifMgr(const char *netIfName)
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
    if (buf == NULL || bufLen == 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "parameters invaild!");
        return SOFTBUS_ERR;
    }
    char *key = strtok_s(buf, LNN_DELIMITER_OUTSIDE, &outerPtr);
    while (key != NULL) {
        value1 = strtok_s(key, LNN_DELIMITER_INSIDE, &innerPtr);
        value2 = strtok_s(NULL, LNN_DELIMITER_INSIDE, &innerPtr);

        LnnNetIfMgr *netIfMgr = NetifMgrFactory((LnnNetIfNameType)atoi(value1), value2);
        if (netIfMgr != NULL) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_WARN, "Create netif mgr [%s],[%s]", value1, value2);
            ListTailInsert(&g_netIfNameList, &netIfMgr->node);
        } else {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "Create netif mgr failed!,[%s],[%s]", value1, value2);
        }
        key = strtok_s(NULL, LNN_DELIMITER_OUTSIDE, &outerPtr);
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
    netIfMgr = NetifMgrFactory(LNN_BR_TYPE, LNN_DEFAULT_IF_NAME_BR);
    if (netIfMgr == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "add default BR netIfMgr failed!");
        return SOFTBUS_ERR;
    }
    ListTailInsert(&g_netIfNameList, &netIfMgr->node);
    netIfMgr = NetifMgrFactory(LNN_BLE_TYPE, LNN_DEFAULT_IF_NAME_BLE);
    if (netIfMgr == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "add default BLE netIfMgr failed!");
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

static void NetUserStateEventHandler(const LnnEventBasicInfo *info)
{
    if (info == NULL || info->event != LNN_EVENT_USER_STATE_CHANGED) {
        LLOGE("wifi user background state change evt handler get invalid param");
        return;
    }
    bool addrType[CONNECTION_ADDR_MAX] = {0};
    const LnnMonitorHbStateChangedEvent *event = (const LnnMonitorHbStateChangedEvent *)info;
    SoftBusUserState userState = (SoftBusUserState)event->status;
    switch (userState) {
        case SOFTBUS_USER_FOREGROUND:
            g_backgroundState = userState;
            LLOGI("wifi handle SOFTBUS_USER_FOREGROUND");
            RestartCoapDiscovery();
            break;
        case SOFTBUS_USER_BACKGROUND:
            g_backgroundState = userState;
            LLOGI("wifi handle SOFTBUS_USER_BACKGROUND");
            for (int32_t i = 0; i < CONNECTION_ADDR_MAX; i++) {
                addrType[i] = true;
            }
            if (LnnRequestLeaveByAddrType(addrType, CONNECTION_ADDR_MAX) != SOFTBUS_OK) {
                LLOGE("LNN leave network fail");
            }
            break;
        default:
            return;
    }
}

static void NetLockStateEventHandler(const LnnEventBasicInfo *info)
{
    if (info == NULL || info->event != LNN_EVENT_SCREEN_LOCK_CHANGED) {
        LLOGE("wifi user background state change evt handler get invalid param");
        return;
    }
    if (g_isUnLock) {
        LLOGI("ignore wifi SOFTBUS_SCREEN_UNLOCK");
        return;
    }
    const LnnMonitorHbStateChangedEvent *event = (const LnnMonitorHbStateChangedEvent *)info;
    SoftBusUserState userState = (SoftBusUserState)event->status;
    switch (userState) {
        case SOFTBUS_SCREEN_UNLOCK:
            g_isUnLock = true;
            LLOGI("wifi handle SOFTBUS_SCREEN_UNLOCK");
            RestartCoapDiscovery();
            break;
        case SOFTBUS_SCREEN_LOCK:
            LLOGI("ignore wifi SOFTBUS_SCREEN_LOCK");
            break;
        default:
            return;
    }
}

static void NetOOBEStateEventHandler(const LnnEventBasicInfo *info)
{
    if (info == NULL || info->event != LNN_EVENT_OOBE_STATE_CHANGED) {
        LLOGE("OOBE state change evt handler get invalid param");
        return;
    }
    const LnnMonitorHbStateChangedEvent *event = (const LnnMonitorHbStateChangedEvent *)info;
    SoftBusOOBEState state = (SoftBusOOBEState)event->status;
    switch (state) {
        case SOFTBUS_OOBE_RUNNING:
            LLOGI("wifi handle SOFTBUS_OOBE_RUNNING");
            break;
        case SOFTBUS_OOBE_END:
            LLOGI("wifi handle SOFTBUS_OOBE_END");
            g_isOOBEEnd = true;
            RestartCoapDiscovery();
            break;
        default:
            return;
    }
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

    if (protocolMgr == NULL || protocolMgr->getListenerModule == NULL || protocolMgr->init == NULL ||
        protocolMgr->enable == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "%s:bad input protocol!", __func__);
        return SOFTBUS_ERR;
    }
    for (uint8_t i = 0; i < LNN_NETWORK_MAX_PROTOCOL_COUNT; i++) {
        if (g_networkProtocols[i] != NULL) {
            continue;
        }
        if (protocolMgr->init != NULL) {
            ret = protocolMgr->init(protocolMgr);
            if (ret != SOFTBUS_OK) {
                SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "init network protocol failed! ret=%d", ret);
                break;
            }
        } else {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_WARN, "network protocol (supportedNetif=%u) have no init",
                protocolMgr->supportedNetif);
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
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "%s:null ptr!", __func__);
        return SOFTBUS_ERR;
    }
    for (i = 0; i < LNN_NETWORK_MAX_PROTOCOL_COUNT; i++) {
        if (g_networkProtocols[i] == protocolMgr) {
            g_networkProtocols[i] = NULL;
            if (protocolMgr->deinit != NULL) {
                protocolMgr->deinit(protocolMgr);
            }
            return SOFTBUS_OK;
        }
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "%s:no such protocol!", __func__);
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

void RestartCoapDiscovery(void)
{
    char ifName[NET_IF_NAME_LEN] = {0};
    int32_t authPort = 0;
    if (!LnnIsAutoNetWorkingEnabled()) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_WARN, "network is disabled yet, dont restart coap discovery");
        return;
    }
    if (LnnGetLocalStrInfo(STRING_KEY_NET_IF_NAME, ifName, NET_IF_NAME_LEN) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get local ifName error!");
        return;
    }
    if (strncmp(ifName, LNN_LOOPBACK_IFNAME, strlen(LNN_LOOPBACK_IFNAME)) == 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "ip invalid now, stop restart coap discovery");
        return;
    }
    if (LnnGetLocalNumInfo(NUM_KEY_AUTH_PORT, &authPort) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get local auth port failed.");
        return;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "open previous discovery again");
    DiscLinkStatusChanged(LINK_STATUS_UP, COAP);
    LnnStopPublish();
    if (LnnStartPublish() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "start publish failed");
    }
    LnnStopDiscovery();
    if (LnnStartDiscovery() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "start discovery failed");
    }
}

static void OnGroupCreated(const char *groupId, int32_t groupType)
{
    (void)groupId;
    LLOGD("wifi handle OnGroupCreated");
    LnnUpdateOhosAccount();
    LnnHbOnTrustedRelationIncreased(groupType);
    RestartCoapDiscovery();
}

static void OnGroupDeleted(const char *groupId)
{
    (void)groupId;
    LLOGD("wifi handle OnGroupDeleted");
    LnnOnOhosAccountLogout();
    LnnHbOnTrustedRelationReduced();
}

static void OnDeviceBound(const char *udid, const char *groupInfo)
{
    (void)groupInfo;
    if (LnnGetOnlineStateById(udid, CATEGORY_UDID)) {
        LLOGD("device is online, no need to start discovery");
        return;
    }
    LnnHbOnTrustedRelationIncreased(AUTH_PEER_TO_PEER_GROUP);
    LLOGD("wifi handle OnDeviceBound");
    RestartCoapDiscovery();
}

static GroupChangeListener g_groupChangeListener = {
    .onGroupCreated = OnGroupCreated,
    .onGroupDeleted = OnGroupDeleted,
    .onDeviceBound = OnDeviceBound,
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

static void RestoreBrNetworkDevices(void)
{
    DeviceNightMode *item = NULL;
    DeviceNightMode *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, g_nightOnCache, DeviceNightMode, node) {
        if (LnnNotifyDiscoveryDevice(&(item->addrs), true) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "notify device found failed\n");
        }
        ListDelete(&item->node);
        SoftBusFree(item);
    }
    SoftBusFree(g_nightOnCache);
    g_nightOnCache = NULL;
}

static void SaveBrNetworkDevices(void)
{
    int32_t infoNum = 0;
    NodeBasicInfo *netInfo = NULL;
    if (LnnGetAllOnlineNodeInfo(&netInfo, &infoNum) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "night mode on: get all online node info fail.");
    }

    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    for (int32_t i = 0; i < infoNum; i++) {
        if (LnnGetRemoteNodeInfoById(netInfo[i].networkId, CATEGORY_NETWORK_ID, &nodeInfo) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "night mode on: GetRemoteNodeInfo fail.");
            continue;
        }
        if (!LnnHasDiscoveryType(&nodeInfo, DISCOVERY_TYPE_BR)) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_DBG, "night mode on: ignore no br network device.");
            continue;
        }
        DeviceNightMode *modeInfo = (DeviceNightMode *)SoftBusMalloc(sizeof(DeviceNightMode));
        if (strcpy_s(modeInfo->addrs.info.br.brMac, BT_MAC_LEN, nodeInfo.connectInfo.macAddr) != EOK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "night mode on: str copy fail.");
            SoftBusFree(modeInfo);
            continue;
        }
        modeInfo->addrs.type = CONNECTION_ADDR_BR;
        ListNodeInsert(g_nightOnCache, &modeInfo->node);
    }
    SoftBusFree(netInfo);
}

static void NightModeChangeEventHandler(const LnnEventBasicInfo *info)
{
    bool addrType[CONNECTION_ADDR_MAX] = {0};
    if (info == NULL || info->event != LNN_EVENT_NIGHT_MODE_CHANGED) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "not interest event");
        return;
    }
    if (g_nightOnCache == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_DBG, "init g_nightOnCache");
        g_nightOnCache = (ListNode *)SoftBusMalloc(sizeof(ListNode));
        ListInit(g_nightOnCache);
    }
    const LnnMonitorHbStateChangedEvent *event = (const LnnMonitorHbStateChangedEvent *)info;
    if (event->status == SOFTBUS_NIGHT_MODE_OFF) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "wifi handle SOFTBUS_NIGHT_MODE_OFF");
        g_isNightMode = false;
        RestartCoapDiscovery();
        RestoreBrNetworkDevices();
        return;
    }
    if (event->status == SOFTBUS_NIGHT_MODE_ON) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "wifi handle SOFTBUS_NIGHT_MODE_ON");
        g_isNightMode = true;
        SaveBrNetworkDevices();
        for (int32_t i = 0; i < CONNECTION_ADDR_MAX; i++) {
            addrType[i] = true;
        }
        if (LnnRequestLeaveByAddrType(addrType, CONNECTION_ADDR_MAX) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LNN leave network fail");
        }
    }
}

static void NetAccountStateChangeEventHandler(const LnnEventBasicInfo *info)
{
    if (info == NULL || info->event != LNN_EVENT_ACCOUNT_CHANGED) {
        LLOGE("account state change evt handler get invalid param");
        return;
    }
    const LnnMonitorHbStateChangedEvent *event = (const LnnMonitorHbStateChangedEvent*)info;
    SoftBusAccountState accountState = (SoftBusAccountState)event->status;
    switch (accountState) {
        case SOFTBUS_ACCOUNT_LOG_IN:
            LLOGI("wifi handle SOFTBUS_ACCOUNT_LOG_IN");
            LnnUpdateOhosAccount();
            LnnHbOnTrustedRelationIncreased(AUTH_IDENTICAL_ACCOUNT_GROUP);
            RestartCoapDiscovery();
            break;
        case SOFTBUS_ACCOUNT_LOG_OUT:
            LLOGI("wifi handle SOFTBUS_ACCOUNT_LOG_OUT");
            LnnOnOhosAccountLogout();
            LnnHbOnTrustedRelationReduced();
            break;
        default:
            return;
    }
}

int32_t LnnInitNetworkManager(void)
{
    RegistNetIfMgr(LNN_ETH_TYPE, CreateNetifMgr);
    RegistNetIfMgr(LNN_WLAN_TYPE, CreateNetifMgr);
    RegistNetIfMgr(LNN_BR_TYPE, CreateNetifMgr);
    RegistNetIfMgr(LNN_BLE_TYPE, CreateNetifMgr);

    int32_t ret = LnnInitManagerByConfig();
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "Read net config failed!ret=%d", ret);
        return ret;
    }
    // Regist default protocols
    ret = RegistIPProtocolManager();
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "regist ip protocol manager failed,ret=%d", ret);
        return ret;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "IP protocol registed.");
    ret = RegistBtProtocolManager();
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "regist bt protocol manager failed,ret=%d", ret);
        return ret;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "BT protocol registed.");
    ret = RegistNewIPProtocolManager();
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "regist newip protocol manager failed,ret=%d\n", ret);
        return ret;
    }
    ret = RegGroupChangeListener(&g_groupChangeListener);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "register group change listener fail");
        return ret;
    }
    ret = LnnInitPhysicalSubnetManager();
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "init subnet manager failed!,ret=%d", ret);
        return ret;
    }
    ProtocolType type = 0;
    if (!LnnVisitProtocol(GetAllProtocols, &type)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "Get all protocol failed!");
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "set supported protocol to %" PRIu64 ".", type);
    ret = LnnSetLocalNum64Info(NUM_KEY_TRANS_PROTOCOLS, (int64_t)type);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "set supported protocol failed!,ret=%d\n", ret);
        return ret;
    }
    if (LnnRegisterEventHandler(LNN_EVENT_NIGHT_MODE_CHANGED, NightModeChangeEventHandler) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "register night mode change event handler failed");
        return SOFTBUS_ERR;
    }
    if (LnnRegisterEventHandler(LNN_EVENT_USER_STATE_CHANGED, NetUserStateEventHandler) != SOFTBUS_OK) {
        LLOGE("Net regist user background evt handler fail!");
        return SOFTBUS_ERR;
    }
    if (LnnRegisterEventHandler(LNN_EVENT_SCREEN_LOCK_CHANGED, NetLockStateEventHandler) != SOFTBUS_OK) {
        LLOGE("Net regist user unlock evt handler fail!");
        return SOFTBUS_ERR;
    }
    if (LnnRegisterEventHandler(LNN_EVENT_OOBE_STATE_CHANGED, NetOOBEStateEventHandler) != SOFTBUS_OK) {
        LLOGE("Net regist OOBE state evt handler fail!");
        return SOFTBUS_ERR;
    }
    if (LnnRegisterEventHandler(LNN_EVENT_ACCOUNT_CHANGED, NetAccountStateChangeEventHandler) != SOFTBUS_OK) {
        LLOGE("Net regist account change evt handler fail!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static void RetryCheckOOBEState(void *para)
{
    (void)para;

    if (!IsOOBEState()) {
        LLOGI("wifi handle SOFTBUS_OOBE_END");
        LnnNotifyOOBEStateChangeEvent(SOFTBUS_OOBE_END);
    } else {
        LLOGD("check OOBE again after a delay of %" PRIu64 " ms", LNN_CHECK_OOBE_DELAY_LEN);
        LnnAsyncCallbackDelayHelper(GetLooper(LOOP_TYPE_DEFAULT), RetryCheckOOBEState, NULL, LNN_CHECK_OOBE_DELAY_LEN);
    }
}

int32_t LnnInitNetworkManagerDelay(void)
{
    uint32_t i;

    char udid[UDID_BUF_LEN] = {0};
    if (LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, udid, UDID_BUF_LEN) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get local udid error!");
        return SOFTBUS_ERR;
    }
    LnnNetIfMgr *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_netIfNameList, LnnNetIfMgr, node) {
        for (i = 0; i < LNN_NETWORK_MAX_PROTOCOL_COUNT; ++i) {
            if (g_networkProtocols[i] == NULL) {
                continue;
            }
            if ((g_networkProtocols[i]->supportedNetif & item->type) != 0) {
                int32_t ret = g_networkProtocols[i]->enable(g_networkProtocols[i], item);
                if (ret != SOFTBUS_OK) {
                    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "enable protocol (%d) for netif %s failed", i,
                        item->ifName);
                }
                SoftBusLog(
                    SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "enable protocol (%d) for netif %s success", i, item->ifName);
            }
        }
    }
    if (IsScreenUnlock()) {
        g_isUnLock = true;
    }
    RetryCheckOOBEState(NULL);
    return SOFTBUS_OK;
}

bool LnnIsAutoNetWorkingEnabled(void)
{
    bool isConfigEnabled = false;
    if (SoftbusGetConfig(SOFTBUS_INT_AUTO_NETWORKING_SWITCH, (unsigned char *)&isConfigEnabled,
        sizeof(isConfigEnabled)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "Cannot get autoNetworkingSwitch from config file");
        return true;
    }
    LLOGI("wifi condition state: config=%d, background=%d, nightMode=%d, OOBEEnd=%d, unlock=%d",
        isConfigEnabled, g_backgroundState == SOFTBUS_USER_BACKGROUND, g_isNightMode, g_isOOBEEnd, g_isUnLock);
    return isConfigEnabled && (g_backgroundState == SOFTBUS_USER_FOREGROUND) && !g_isNightMode &&
        g_isOOBEEnd && g_isUnLock;
}

void LnnDeinitNetworkManager(void)
{
    if (g_nightOnCache != NULL) {
        DeviceNightMode *item = NULL;
        DeviceNightMode *next = NULL;
        LIST_FOR_EACH_ENTRY_SAFE(item, next, g_nightOnCache, DeviceNightMode, node) {
            ListDelete(&item->node);
            SoftBusFree(item);
        }
        SoftBusFree(g_nightOnCache);
        g_nightOnCache = NULL;
    }
    uint32_t i;
    if (LnnClearNetConfigList() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "deinit network manager failed");
    }
    LnnDeinitPhysicalSubnetManager();
    for (i = 0; i < LNN_NETWORK_MAX_PROTOCOL_COUNT; ++i) {
        if (g_networkProtocols[i] == NULL || g_networkProtocols[i]->deinit == NULL) {
            continue;
        }
        g_networkProtocols[i]->deinit(g_networkProtocols[i]);
        g_networkProtocols[i] = NULL;
    }
    LnnUnregisterEventHandler(LNN_EVENT_NIGHT_MODE_CHANGED, NightModeChangeEventHandler);
    LnnUnregisterEventHandler(LNN_EVENT_USER_STATE_CHANGED, NetUserStateEventHandler);
    LnnUnregisterEventHandler(LNN_EVENT_SCREEN_LOCK_CHANGED, NetLockStateEventHandler);
    LnnUnregisterEventHandler(LNN_EVENT_OOBE_STATE_CHANGED, NetOOBEStateEventHandler);
    LnnUnregisterEventHandler(LNN_EVENT_ACCOUNT_CHANGED, NetAccountStateChangeEventHandler);
}

int32_t LnnGetNetIfTypeByName(const char *ifName, LnnNetIfType *type)
{
    if (ifName == NULL || type == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "parameters are NULL!");
        return SOFTBUS_ERR;
    }
    LnnNetIfMgr *netif = NULL;
    LIST_FOR_EACH_ENTRY(netif, &g_netIfNameList, LnnNetIfMgr, node) {
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
        case LNN_NETIF_TYPE_BR:
            *type = CONNECTION_ADDR_BR;
            break;
        case LNN_NETIF_TYPE_BLE:
            *type = CONNECTION_ADDR_BLE;
            break;
        default:
            ret = SOFTBUS_ERR;
    }
    return ret;
}

struct FindProtocolByTypeRequest {
    ProtocolType protocol;
    const LnnProtocolManager *manager;
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
    if (request.manager == NULL || request.manager->getListenerModule == NULL) {
        SoftBusLog(
            SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "%s: protocol manager is null! protocolId=%d", __func__, protocol);
        return UNUSE_BUTT;
    }
    return request.manager->getListenerModule(mode);
}
