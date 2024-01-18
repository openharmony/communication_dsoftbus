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
#include "lnn_fast_offline.h"
#include "lnn_heartbeat_ctrl.h"
#include "lnn_log.h"
#include "lnn_net_builder.h"
#include "lnn_ohos_account.h"
#include "lnn_physical_subnet_manager.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_feature_config.h"

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
    LNN_LOGW(LNN_BUILDER, "regist virtual bt protocol manager");
    return SOFTBUS_OK;
}

static LnnNetIfManagerBuilder g_netifBuilders[LNN_MAX_NUM_TYPE] = {0};

static LnnProtocolManager *g_networkProtocols[LNN_NETWORK_MAX_PROTOCOL_COUNT] = {0};

static LnnNetIfMgr *CreateNetifMgr(const char *netIfName)
{
    if (netIfName == NULL) {
        LNN_LOGE(LNN_BUILDER, "parameters invalid");
        return NULL;
    }
    LnnNetIfMgr *netIfMgr = (LnnNetIfMgr *)SoftBusCalloc(sizeof(LnnNetIfMgr));
    if (netIfMgr == NULL) {
        LNN_LOGE(LNN_BUILDER, "malloc LnnNetIfMgr fail");
        return NULL;
    }
    do {
        ListInit(&netIfMgr->node);
        if (strncpy_s(netIfMgr->ifName, NET_IF_NAME_LEN, netIfName, strlen(netIfName)) != EOK) {
            LNN_LOGE(LNN_BUILDER, "copy netIfName fail");
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
        LNN_LOGE(LNN_BUILDER, "type too big");
        return SOFTBUS_ERR;
    }
    if (g_netifBuilders[type] != NULL && g_netifBuilders[type] != builder) {
        LNN_LOGE(LNN_BUILDER, "type already registed");
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
        LNN_LOGE(LNN_BUILDER, "netif type not supported. type=%{public}d", type);
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
        LNN_LOGE(LNN_BUILDER, "parameters invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    char *key = strtok_s(buf, LNN_DELIMITER_OUTSIDE, &outerPtr);
    while (key != NULL) {
        value1 = strtok_s(key, LNN_DELIMITER_INSIDE, &innerPtr);
        value2 = strtok_s(NULL, LNN_DELIMITER_INSIDE, &innerPtr);

        LnnNetIfMgr *netIfMgr = NetifMgrFactory((LnnNetIfNameType)atoi(value1), value2);
        if (netIfMgr != NULL) {
            LNN_LOGW(LNN_BUILDER, "Create netif mgr. value1=%{public}s, value2=%{public}s", value1, value2);
            ListTailInsert(&g_netIfNameList, &netIfMgr->node);
        } else {
            LNN_LOGE(LNN_BUILDER, "Create netif mgr failed, value1=%{public}s, value2=%{public}s", value1, value2);
        }
        key = strtok_s(NULL, LNN_DELIMITER_OUTSIDE, &outerPtr);
    }
    return SOFTBUS_OK;
}

static int32_t SetIfNameDefaultVal(void)
{
    LnnNetIfMgr *netIfMgr = NetifMgrFactory(LNN_ETH_TYPE, LNN_DEFAULT_IF_NAME_ETH);
    if (netIfMgr == NULL) {
        LNN_LOGE(LNN_BUILDER, "add default ETH port failed");
        return SOFTBUS_ERR;
    }
    ListTailInsert(&g_netIfNameList, &netIfMgr->node);
    netIfMgr = NetifMgrFactory(LNN_WLAN_TYPE, LNN_DEFAULT_IF_NAME_WLAN);
    if (netIfMgr == NULL) {
        LNN_LOGE(LNN_BUILDER, "add default ETH port failed");
        return SOFTBUS_ERR;
    }
    ListTailInsert(&g_netIfNameList, &netIfMgr->node);
    netIfMgr = NetifMgrFactory(LNN_BR_TYPE, LNN_DEFAULT_IF_NAME_BR);
    if (netIfMgr == NULL) {
        LNN_LOGE(LNN_BUILDER, "add default BR netIfMgr failed");
        return SOFTBUS_ERR;
    }
    ListTailInsert(&g_netIfNameList, &netIfMgr->node);
    netIfMgr = NetifMgrFactory(LNN_BLE_TYPE, LNN_DEFAULT_IF_NAME_BLE);
    if (netIfMgr == NULL) {
        LNN_LOGE(LNN_BUILDER, "add default BLE netIfMgr failed");
        return SOFTBUS_ERR;
    }
    ListTailInsert(&g_netIfNameList, &netIfMgr->node);
    return SOFTBUS_OK;
}

static int32_t LnnInitManagerByConfig(void)
{
    char netIfName[LNN_MAX_IF_NAME_LEN] = {0};
    if (SoftbusGetConfig(SOFTBUS_STR_LNN_NET_IF_NAME, (unsigned char *)netIfName, sizeof(netIfName)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get lnn net ifName fail, use default value");
        if (SetIfNameDefaultVal() != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "default value set fail");
            return SOFTBUS_ERR;
        }
        return SOFTBUS_OK;
    }
    int32_t ret = ParseIfNameConfig(netIfName, strlen(netIfName));
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "ifName str parse fail!");
        return ret;
    }
    return SOFTBUS_OK;
}

static void NetUserStateEventHandler(const LnnEventBasicInfo *info)
{
    if (info == NULL || info->event != LNN_EVENT_USER_STATE_CHANGED) {
        LNN_LOGE(LNN_BUILDER, "wifi user background state change evt handler get invalid param");
        return;
    }
    bool addrType[CONNECTION_ADDR_MAX] = {false};
    const LnnMonitorHbStateChangedEvent *event = (const LnnMonitorHbStateChangedEvent *)info;
    SoftBusUserState userState = (SoftBusUserState)event->status;
    switch (userState) {
        case SOFTBUS_USER_FOREGROUND:
            g_backgroundState = userState;
            LNN_LOGI(LNN_BUILDER, "wifi handle SOFTBUS_USER_FOREGROUND");
            RestartCoapDiscovery();
            break;
        case SOFTBUS_USER_BACKGROUND:
            g_backgroundState = userState;
            LNN_LOGI(LNN_BUILDER, "wifi handle SOFTBUS_USER_BACKGROUND");
            for (int32_t i = 0; i < CONNECTION_ADDR_MAX; i++) {
                addrType[i] = true;
            }
            if (LnnRequestLeaveByAddrType(addrType, CONNECTION_ADDR_MAX) != SOFTBUS_OK) {
                LNN_LOGE(LNN_BUILDER, "LNN leave network fail");
            }
            break;
        default:
            return;
    }
}

static void NetLockStateEventHandler(const LnnEventBasicInfo *info)
{
    if (info == NULL || info->event != LNN_EVENT_SCREEN_LOCK_CHANGED) {
        LNN_LOGE(LNN_BUILDER, "wifi user background state change evt handler get invalid param");
        return;
    }
    if (g_isUnLock) {
        LNN_LOGI(LNN_BUILDER, "ignore wifi SOFTBUS_SCREEN_UNLOCK");
        return;
    }
    const LnnMonitorHbStateChangedEvent *event = (const LnnMonitorHbStateChangedEvent *)info;
    SoftBusUserState userState = (SoftBusUserState)event->status;
    switch (userState) {
        case SOFTBUS_SCREEN_UNLOCK:
            g_isUnLock = true;
            LNN_LOGI(LNN_BUILDER, "wifi handle SOFTBUS_SCREEN_UNLOCK");
            RestartCoapDiscovery();
            break;
        case SOFTBUS_SCREEN_LOCK:
            LNN_LOGI(LNN_BUILDER, "ignore wifi SOFTBUS_SCREEN_LOCK");
            break;
        default:
            return;
    }
}

static void NetOOBEStateEventHandler(const LnnEventBasicInfo *info)
{
    if (info == NULL || info->event != LNN_EVENT_OOBE_STATE_CHANGED) {
        LNN_LOGE(LNN_BUILDER, "OOBE state change evt handler get invalid param");
        return;
    }
    const LnnMonitorHbStateChangedEvent *event = (const LnnMonitorHbStateChangedEvent *)info;
    SoftBusOOBEState state = (SoftBusOOBEState)event->status;
    switch (state) {
        case SOFTBUS_OOBE_RUNNING:
            LNN_LOGI(LNN_BUILDER, "wifi handle SOFTBUS_OOBE_RUNNING");
            break;
        case SOFTBUS_OOBE_END:
            LNN_LOGI(LNN_BUILDER, "wifi handle SOFTBUS_OOBE_END");
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
        LNN_LOGE(LNN_BUILDER, "bad input protocol");
        return SOFTBUS_INVALID_PARAM;
    }
    for (uint8_t i = 0; i < LNN_NETWORK_MAX_PROTOCOL_COUNT; i++) {
        if (g_networkProtocols[i] != NULL) {
            continue;
        }
        if (protocolMgr->init != NULL) {
            ret = protocolMgr->init(protocolMgr);
            if (ret != SOFTBUS_OK) {
                LNN_LOGE(LNN_BUILDER, "init network protocol failed! ret=%{public}d", ret);
                break;
            }
        } else {
            LNN_LOGW(LNN_BUILDER, "network protocol have no init. supportedNetif=%{public}u",
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
        LNN_LOGE(LNN_BUILDER, "protocoMgr is null");
        return SOFTBUS_INVALID_PARAM;
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
    LNN_LOGE(LNN_BUILDER, "no such protocol!");
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
        LNN_LOGW(LNN_BUILDER, "network is disabled yet, dont restart coap discovery");
        return;
    }
    if (LnnGetLocalStrInfo(STRING_KEY_NET_IF_NAME, ifName, NET_IF_NAME_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get local ifName error!");
        return;
    }
    if (strncmp(ifName, LNN_LOOPBACK_IFNAME, strlen(LNN_LOOPBACK_IFNAME)) == 0) {
        LNN_LOGI(LNN_BUILDER, "ip invalid now, stop restart coap discovery");
        return;
    }
    if (LnnGetLocalNumInfo(NUM_KEY_AUTH_PORT, &authPort) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get local auth port failed.");
        return;
    }
    LNN_LOGI(LNN_BUILDER, "open previous discovery again");
    DiscLinkStatusChanged(LINK_STATUS_UP, COAP);
    LnnStopPublish();
    if (LnnStartPublish() != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "start publish failed");
    }
    LnnStopDiscovery();
    if (LnnStartDiscovery() != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "start discovery failed");
    }
}

static void OnGroupCreated(const char *groupId, int32_t groupType)
{
    (void)groupId;
    LNN_LOGD(LNN_BUILDER, "wifi handle OnGroupCreated");
    LnnUpdateOhosAccount();
    LnnHbOnTrustedRelationIncreased(groupType);
    RestartCoapDiscovery();
    EhLoginEventHandler();
}

static void OnGroupDeleted(const char *groupId)
{
    (void)groupId;
    LNN_LOGD(LNN_BUILDER, "wifi handle OnGroupDeleted");
    LnnOnOhosAccountLogout();
    LnnHbOnTrustedRelationReduced();
}

static void OnDeviceBound(const char *udid, const char *groupInfo)
{
    (void)groupInfo;
    if (LnnGetOnlineStateById(udid, CATEGORY_UDID)) {
        LNN_LOGD(LNN_BUILDER, "device is online, no need to start discovery");
        return;
    }
    LnnHbOnTrustedRelationChanged(AUTH_PEER_TO_PEER_GROUP);
    LNN_LOGD(LNN_BUILDER, "wifi handle OnDeviceBound");
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
            LNN_LOGE(LNN_BUILDER, "notify device found failed\n");
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
        LNN_LOGE(LNN_BUILDER, "night mode on: get all online node info fail.");
    }

    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    for (int32_t i = 0; i < infoNum; i++) {
        if (LnnGetRemoteNodeInfoById(netInfo[i].networkId, CATEGORY_NETWORK_ID, &nodeInfo) != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "night mode on: GetRemoteNodeInfo fail.");
            continue;
        }
        if (!LnnHasDiscoveryType(&nodeInfo, DISCOVERY_TYPE_BR)) {
            LNN_LOGE(LNN_BUILDER, "night mode on: ignore no br network device.");
            continue;
        }
        DeviceNightMode *modeInfo = (DeviceNightMode *)SoftBusMalloc(sizeof(DeviceNightMode));
        if (modeInfo == NULL) {
            LNN_LOGE(LNN_BUILDER, "mode info malloc fail.");
            continue;
        }
        if (strcpy_s(modeInfo->addrs.info.br.brMac, BT_MAC_LEN, nodeInfo.connectInfo.macAddr) != EOK) {
            LNN_LOGE(LNN_BUILDER, "night mode on: str copy fail.");
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
        LNN_LOGE(LNN_BUILDER, "not interest event");
        return;
    }
    if (g_nightOnCache == NULL) {
        LNN_LOGD(LNN_BUILDER, "init g_nightOnCache");
        g_nightOnCache = (ListNode *)SoftBusMalloc(sizeof(ListNode));
        if (g_nightOnCache == NULL) {
            LNN_LOGE(LNN_BUILDER, "malloc g_nightOnCache fail");
            return;
        }
        ListInit(g_nightOnCache);
    }
    const LnnMonitorHbStateChangedEvent *event = (const LnnMonitorHbStateChangedEvent *)info;
    if (event->status == SOFTBUS_NIGHT_MODE_OFF) {
        LNN_LOGI(LNN_BUILDER, "wifi handle SOFTBUS_NIGHT_MODE_OFF");
        g_isNightMode = false;
        RestartCoapDiscovery();
        RestoreBrNetworkDevices();
        return;
    }
    if (event->status == SOFTBUS_NIGHT_MODE_ON) {
        LNN_LOGI(LNN_BUILDER, "wifi handle SOFTBUS_NIGHT_MODE_ON");
        g_isNightMode = true;
        SaveBrNetworkDevices();
        for (int32_t i = 0; i < CONNECTION_ADDR_MAX; i++) {
            addrType[i] = true;
        }
        if (LnnRequestLeaveByAddrType(addrType, CONNECTION_ADDR_MAX) != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "LNN leave network fail");
        }
    }
}

static void NetAccountStateChangeEventHandler(const LnnEventBasicInfo *info)
{
    if (info == NULL || info->event != LNN_EVENT_ACCOUNT_CHANGED) {
        LNN_LOGE(LNN_BUILDER, "account state change evt handler get invalid param");
        return;
    }
    const LnnMonitorHbStateChangedEvent *event = (const LnnMonitorHbStateChangedEvent*)info;
    SoftBusAccountState accountState = (SoftBusAccountState)event->status;
    switch (accountState) {
        case SOFTBUS_ACCOUNT_LOG_IN:
            LNN_LOGI(LNN_BUILDER, "wifi handle SOFTBUS_ACCOUNT_LOG_IN");
            LnnUpdateOhosAccount();
            LnnHbOnTrustedRelationIncreased(AUTH_IDENTICAL_ACCOUNT_GROUP);
            RestartCoapDiscovery();
            break;
        case SOFTBUS_ACCOUNT_LOG_OUT:
            LNN_LOGI(LNN_BUILDER, "wifi handle SOFTBUS_ACCOUNT_LOG_OUT");
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
        LNN_LOGE(LNN_BUILDER, "Read net config failed, ret=%{public}d", ret);
        return ret;
    }
    // Regist default protocols
    ret = RegistIPProtocolManager();
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "regist ip protocol manager failed, ret=%{public}d", ret);
        return ret;
    }
    LNN_LOGI(LNN_BUILDER, "IP protocol registed.");
    ret = RegistBtProtocolManager();
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "regist bt protocol manager failed, ret=%{public}d", ret);
        return ret;
    }
    LNN_LOGI(LNN_BUILDER, "BT protocol registed.");
    ret = RegistNewIPProtocolManager();
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "regist newip protocol manager failed, ret=%{public}d", ret);
        return ret;
    }
    ret = RegGroupChangeListener(&g_groupChangeListener);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "register group change listener fail");
        return ret;
    }
    ret = LnnInitPhysicalSubnetManager();
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "init subnet manager failed, ret=%{public}d", ret);
        return ret;
    }
    ProtocolType type = 0;
    if (!LnnVisitProtocol(GetAllProtocols, &type)) {
        LNN_LOGE(LNN_BUILDER, "Get all protocol failed");
        return SOFTBUS_ERR;
    }
    LNN_LOGI(LNN_BUILDER, "set supported protocol type. type=%{public}u", type);
    ret = LnnSetLocalNum64Info(NUM_KEY_TRANS_PROTOCOLS, (int64_t)type);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "set supported protocol failed, ret=%{public}d", ret);
        return ret;
    }
    if (LnnRegisterEventHandler(LNN_EVENT_NIGHT_MODE_CHANGED, NightModeChangeEventHandler) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "register night mode change event handler fail");
        return SOFTBUS_NETWORK_REG_EVENT_HANDLER_ERR;
    }
    if (LnnRegisterEventHandler(LNN_EVENT_USER_STATE_CHANGED, NetUserStateEventHandler) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "Net regist user background evt handler fail");
        return SOFTBUS_NETWORK_REG_EVENT_HANDLER_ERR;
    }
    if (LnnRegisterEventHandler(LNN_EVENT_SCREEN_LOCK_CHANGED, NetLockStateEventHandler) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "Net regist user unlock evt handler fail");
        return SOFTBUS_NETWORK_REG_EVENT_HANDLER_ERR;
    }
    if (LnnRegisterEventHandler(LNN_EVENT_OOBE_STATE_CHANGED, NetOOBEStateEventHandler) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "Net regist OOBE state evt handler fail");
        return SOFTBUS_NETWORK_REG_EVENT_HANDLER_ERR;
    }
    if (LnnRegisterEventHandler(LNN_EVENT_ACCOUNT_CHANGED, NetAccountStateChangeEventHandler) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "Net regist account change evt handler fail");
        return SOFTBUS_NETWORK_REG_EVENT_HANDLER_ERR;
    }
    return SOFTBUS_OK;
}

static void RetryCheckOOBEState(void *para)
{
    (void)para;

    if (!IsOOBEState()) {
        LNN_LOGI(LNN_BUILDER, "wifi handle SOFTBUS_OOBE_END");
        LnnNotifyOOBEStateChangeEvent(SOFTBUS_OOBE_END);
    } else {
        LNN_LOGD(LNN_BUILDER, "check OOBE again after a delay. delay=%{public}" PRIu64 "ms",
            (uint64_t)LNN_CHECK_OOBE_DELAY_LEN);
        LnnAsyncCallbackDelayHelper(GetLooper(LOOP_TYPE_DEFAULT), RetryCheckOOBEState, NULL, LNN_CHECK_OOBE_DELAY_LEN);
    }
}

int32_t LnnInitNetworkManagerDelay(void)
{
    uint32_t i;

    char udid[UDID_BUF_LEN] = {0};
    if (LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, udid, UDID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "get local udid error");
        return SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR;
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
                    LNN_LOGE(LNN_INIT, "enable for netif failed. protocol=%{public}d, ifName=%{public}s", i,
                        item->ifName);
                }
                LNN_LOGI(LNN_INIT, "enable for netif success. protocol=%{public}d, ifName=%{public}s", i, item->ifName);
            }
        }
    }
    if (IsActiveOsAccountUnlocked()) {
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
        LNN_LOGE(LNN_BUILDER, "Cannot get autoNetworkingSwitch from config file");
        return true;
    }
    LNN_LOGI(LNN_BUILDER,
        "wifi condition state:config=%{public}d, background=%{public}d, nightMode=%{public}d, OOBEEnd=%{public}d, "
        "unlock=%{public}d",
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
        LNN_LOGE(LNN_INIT, "deinit network manager failed");
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
        LNN_LOGE(LNN_BUILDER, "parameters is NULL");
        return SOFTBUS_INVALID_PARAM;
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
        LNN_LOGE(LNN_BUILDER, "parameters is NULL");
        return SOFTBUS_INVALID_PARAM;
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
        LNN_LOGE(LNN_BUILDER, "not such protocol! protocolId=%{public}d", protocol);
        return UNUSE_BUTT;
    }
    if (request.manager == NULL || request.manager->getListenerModule == NULL) {
        LNN_LOGE(LNN_BUILDER, "protocol manager is null, protocolId=%{public}d", protocol);
        return UNUSE_BUTT;
    }
    return request.manager->getListenerModule(mode);
}
