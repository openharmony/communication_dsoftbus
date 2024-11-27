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

#include <securec.h>
#include <string.h>

#include "anonymizer.h"
#include "bus_center_event.h"
#include "bus_center_manager.h"
#include "lnn_log.h"
#include "lnn_net_builder.h"
#include "lnn_network_manager.h"
#include "lnn_physical_subnet_manager.h"
#include "softbus_adapter_bt_common.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_timer.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"

#define LNN_BT_PROTOCOL_PRI 10
#define TIME_FACTOR (1000LL)

typedef enum {
    BT_SUBNET_MANAGER_EVENT_IF_READY,   // bluetooth on
    BT_SUBNET_MANAGER_EVENT_IF_DOWN,    // bluetooth off
    BT_SUBNET_MANAGER_EVENT_MAX
} BtSubnetManagerEvent;

typedef enum {
    BT_EVENT_RESULT_ACCEPTED = 0,
    BT_EVENT_RESULT_REJECTED,
    BT_EVENT_RESULT_OPTION_COUNT
} BtSubnetManagerEventResultOptions;

static void TransactBtSubnetState(LnnPhysicalSubnet *subnet, BtSubnetManagerEvent event, bool isAccepted)
{
    LnnPhysicalSubnetStatus lastStatus = subnet->status;
    LnnPhysicalSubnetStatus transactMap[][BT_EVENT_RESULT_OPTION_COUNT] = {
        [BT_SUBNET_MANAGER_EVENT_IF_READY] = {LNN_SUBNET_RUNNING, LNN_SUBNET_IDLE},
        [BT_SUBNET_MANAGER_EVENT_IF_DOWN] = {LNN_SUBNET_SHUTDOWN, subnet->status},
    };
    if (event == BT_SUBNET_MANAGER_EVENT_MAX) {
        LNN_LOGE(LNN_BUILDER, "event error");
        return;
    }
    subnet->status = transactMap[event][isAccepted ? BT_EVENT_RESULT_ACCEPTED : BT_EVENT_RESULT_REJECTED];
    LNN_LOGD(LNN_BUILDER,
        "subnet ifName status trans. ifName=%{public}s, status:%{public}d->%{public}d", subnet->ifName,
        lastStatus, subnet->status);
}

static int32_t GetAvailableBtMac(char *macStr, uint32_t len)
{
    int32_t ret;
    SoftBusBtAddr mac = {0};

    if (len != BT_MAC_LEN) {
        return SOFTBUS_INVALID_PARAM;
    }
    ret = SoftBusGetBtMacAddr(&mac);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get bt mac addr fail");
        return ret;
    }
    ret = ConvertBtMacToStr(macStr, len, mac.addr, sizeof(mac.addr));
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "convert bt mac to str fail");
        return ret;
    }
    LnnSetLocalByteInfo(BYTE_KEY_PUB_MAC, mac.addr, sizeof(mac.addr));
    return SOFTBUS_OK;
}

static int32_t EnableBtSubnet(LnnPhysicalSubnet *subnet)
{
    char macStr[BT_MAC_LEN] = {0};

    if (subnet->status == LNN_SUBNET_RUNNING) {
        LNN_LOGI(LNN_BUILDER, "bt running return ok");
        return SOFTBUS_OK;
    }
    int32_t ret = GetAvailableBtMac(macStr, sizeof(macStr));
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get available bt mac fail");
        return ret;
    }
    char *anonyMac = NULL;
    Anonymize(macStr, &anonyMac);
    LNN_LOGI(LNN_BUILDER, "btmac=%{public}s", AnonymizeWrapper(anonyMac));
    AnonymizeFree(anonyMac);
    return LnnSetLocalStrInfo(STRING_KEY_BT_MAC, macStr);
}

static int32_t DisableBrSubnet(LnnPhysicalSubnet *subnet)
{
    bool addrType[CONNECTION_ADDR_MAX] = {
        [CONNECTION_ADDR_BR] = true,
    };

    if (subnet->status != LNN_SUBNET_RUNNING) {
        return SOFTBUS_NETWORK_SUBNET_STATUS_ERR;
    }
    LNN_LOGI(LNN_BUILDER, "br subnet is disable, start leave br network");
    int32_t ret = LnnRequestLeaveByAddrType(addrType, CONNECTION_ADDR_MAX);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "leave br network fail, ret=%{public}d", ret);
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t DisableBleSubnet(LnnPhysicalSubnet *subnet)
{
    int32_t ret;
    bool addrType[CONNECTION_ADDR_MAX] = {
        [CONNECTION_ADDR_BLE] = true,
    };

    if (subnet->status != LNN_SUBNET_RUNNING) {
        return SOFTBUS_NETWORK_SUBNET_STATUS_ERR;
    }
    LNN_LOGI(LNN_BUILDER, "ble subnet is disable, start leave ble network");
    ret = LnnRequestLeaveByAddrType(addrType, CONNECTION_ADDR_MAX);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "leave ble network fail, ret=%{public}d", ret);
        return ret;
    }
    return SOFTBUS_OK;
}

static void DestroyBtSubnetManager(LnnPhysicalSubnet *subnet)
{
    int32_t ret;
    LnnNetIfType type;

    LnnGetNetIfTypeByName(subnet->ifName, &type);
    if (subnet->status == LNN_SUBNET_RUNNING) {
        ret = (type == LNN_NETIF_TYPE_BR) ? DisableBrSubnet(subnet) : DisableBleSubnet(subnet);
        TransactBtSubnetState(subnet, BT_SUBNET_MANAGER_EVENT_IF_DOWN, (ret == SOFTBUS_OK));
    }
    SoftBusFree(subnet);
}

static BtSubnetManagerEvent GetBtRegistEvent(void)
{
    char macStr[BT_MAC_LEN] = {0};

    if (!SoftBusGetBtState()) {
        LNN_LOGD(LNN_BUILDER, "bluetooth is not enabled yet");
        return BT_SUBNET_MANAGER_EVENT_IF_DOWN;
    }
    return GetAvailableBtMac(macStr, sizeof(macStr)) == SOFTBUS_OK ?
        BT_SUBNET_MANAGER_EVENT_IF_READY : BT_SUBNET_MANAGER_EVENT_IF_DOWN;
}

static BtSubnetManagerEvent GetBtStatusChangedEvent(SoftBusBtState btState)
{
    if (btState == SOFTBUS_BR_TURN_ON || btState == SOFTBUS_BLE_TURN_ON) {
        return BT_SUBNET_MANAGER_EVENT_IF_READY;
    }
    if (btState == SOFTBUS_BR_TURN_OFF || btState == SOFTBUS_BLE_TURN_OFF) {
        return BT_SUBNET_MANAGER_EVENT_IF_DOWN;
    }
    return BT_SUBNET_MANAGER_EVENT_MAX;
}

static void OnBtNetifStatusChanged(LnnPhysicalSubnet *subnet, void *status)
{
    BtSubnetManagerEvent event = BT_SUBNET_MANAGER_EVENT_MAX;

    if (status == NULL) {
        event = GetBtRegistEvent();
        /* Only used for initialization process to obtain bt subnet status */
        if (event != BT_SUBNET_MANAGER_EVENT_IF_READY) {
            return;
        }
    } else {
        SoftBusBtState btState = (SoftBusBtState)(*(uint8_t *)status);
        event = GetBtStatusChangedEvent(btState);
    }

    int32_t ret = SOFTBUS_NETWORK_NETIF_STATUS_CHANGED;
    LnnNetIfType type;
    LnnGetNetIfTypeByName(subnet->ifName, &type);
    switch (event) {
        case BT_SUBNET_MANAGER_EVENT_IF_READY:
            if (type == LNN_NETIF_TYPE_BR || type == LNN_NETIF_TYPE_BLE) {
                ret = EnableBtSubnet(subnet);
            }
            break;
        case BT_SUBNET_MANAGER_EVENT_IF_DOWN:
            if (type == LNN_NETIF_TYPE_BR) {
                ret = DisableBrSubnet(subnet);
            }
            if (type == LNN_NETIF_TYPE_BLE) {
                ret = DisableBleSubnet(subnet);
            }
            break;
        default:
            LNN_LOGW(LNN_BUILDER, "discard unexpected event. event=%{public}d", event);
            return;
    }
    TransactBtSubnetState(subnet, event, (ret == SOFTBUS_OK));
}

static LnnPhysicalSubnet *CreateBtSubnetManager(struct LnnProtocolManager *self, const char *ifName)
{
    LnnNetIfType type;
    LnnGetNetIfTypeByName(ifName, &type);
    LnnPhysicalSubnet *subnet = (LnnPhysicalSubnet *)SoftBusCalloc(sizeof(LnnPhysicalSubnet));
    if (subnet == NULL) {
        LNN_LOGE(LNN_BUILDER, "calloc bt subnet fail");
        return NULL;
    }

    do {
        subnet->destroy = DestroyBtSubnetManager;
        subnet->protocol = self;
        subnet->status = LNN_SUBNET_IDLE;
        subnet->onNetifStatusChanged = OnBtNetifStatusChanged;
        subnet->onSoftbusNetworkDisconnected = NULL;

        int32_t ret = strcpy_s(subnet->ifName, sizeof(subnet->ifName), ifName);
        if (ret != EOK) {
            LNN_LOGE(LNN_BUILDER, "copy ifName failed! ret=%{public}d", ret);
            break;
        }
        return subnet;
    } while (false);

    subnet->destroy(subnet);
    return NULL;
}

static VisitNextChoice NotifyBtStatusChanged(const LnnNetIfMgr *netifManager, void *data)
{
    SoftBusBtState btState = (SoftBusBtState)(*(uint8_t *)data);
    if (netifManager->type == LNN_NETIF_TYPE_BR &&
        (btState == SOFTBUS_BR_TURN_ON || btState == SOFTBUS_BR_TURN_OFF)) {
        LnnNotifyPhysicalSubnetStatusChanged(netifManager->ifName, LNN_PROTOCOL_BR | LNN_PROTOCOL_BLE, data);
    }
    if (netifManager->type == LNN_NETIF_TYPE_BLE &&
        (btState == SOFTBUS_BLE_TURN_ON || btState == SOFTBUS_BLE_TURN_OFF)) {
        LnnNotifyPhysicalSubnetStatusChanged(netifManager->ifName, LNN_PROTOCOL_BR | LNN_PROTOCOL_BLE, data);
    }
    return CHOICE_VISIT_NEXT;
}

static void BtNetworkInfoUpdate(SoftBusBtState btState)
{
    if (btState == SOFTBUS_BLE_TURN_ON) {
        LnnSetLocalNum64Info(NUM_KEY_BLE_START_TIME, 0);
    }
    if (btState == SOFTBUS_BLE_TURN_OFF) {
        LnnSetLocalNum64Info(NUM_KEY_BLE_START_TIME, 0);
    }
}

static void BtStateChangedEvtHandler(const LnnEventBasicInfo *info)
{
    if (info == NULL || info->event != LNN_EVENT_BT_STATE_CHANGED) {
        LNN_LOGE(LNN_BUILDER, "not interest event");
        return;
    }

    LnnMonitorHbStateChangedEvent *event = (LnnMonitorHbStateChangedEvent *)info;
    (void)LnnVisitNetif(NotifyBtStatusChanged, (void *)&event->status);
    BtNetworkInfoUpdate((SoftBusBtState)event->status);
}

static void LeaveSpecificBrNetwork(const char *btMac)
{
    char networkId[NETWORK_ID_BUF_LEN] = {0};
    if (LnnGetNetworkIdByBtMac(btMac, networkId, sizeof(networkId)) != SOFTBUS_OK) {
        LNN_LOGW(LNN_BUILDER, "networkId not found by btMac");
        return;
    }
    char *anonyNetworkId = NULL;
    Anonymize(networkId, &anonyNetworkId);
    LNN_LOGI(LNN_BUILDER, "start leave specific br networkId=%{public}s", AnonymizeWrapper(anonyNetworkId));
    AnonymizeFree(anonyNetworkId);
    int32_t ret = LnnRequestLeaveSpecific(networkId, CONNECTION_ADDR_BR);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "leave br network fail=%{public}d", ret);
    }
}

static void BtAclStateChangedEvtHandler(const LnnEventBasicInfo *info)
{
    if (info == NULL || info->event != LNN_EVENT_BT_ACL_STATE_CHANGED) {
        LNN_LOGE(LNN_BUILDER, "bt acl state event handler get invalid param");
        return;
    }

    const LnnMonitorBtAclStateChangedEvent *event = (const LnnMonitorBtAclStateChangedEvent *)info;
    LNN_LOGI(LNN_BUILDER, "BtAclStateChange=%{public}d", event->status);
    switch (event->status) {
        case SOFTBUS_BR_ACL_CONNECTED:
            /* do nothing */
            break;
        case SOFTBUS_BR_ACL_DISCONNECTED:
            LeaveSpecificBrNetwork(event->btMac);
            break;
        default:
            break;
    }
}

int32_t LnnInitBtProtocol(struct LnnProtocolManager *self)
{
    (void)self;
    if (LnnRegisterEventHandler(LNN_EVENT_BT_STATE_CHANGED, BtStateChangedEvtHandler) != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "register bt state change event handler failed");
        return SOFTBUS_NETWORK_REG_EVENT_HANDLER_ERR;
    }
    if (LnnRegisterEventHandler(LNN_EVENT_BT_ACL_STATE_CHANGED, BtAclStateChangedEvtHandler) != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "register bt acl state change event handler failed");
        return SOFTBUS_NETWORK_REG_EVENT_HANDLER_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnEnableBtProtocol(struct LnnProtocolManager *self, LnnNetIfMgr *netifMgr)
{
    (void)self;

    if (netifMgr == NULL) {
        LNN_LOGE(LNN_BUILDER, "netifMgr is nullptr");
        return SOFTBUS_INVALID_PARAM;
    }
    LnnPhysicalSubnet *manager = CreateBtSubnetManager(self, netifMgr->ifName);
    if (manager == NULL) {
        LNN_LOGE(LNN_BUILDER, "create bt subnet mgr fail");
        return SOFTBUS_NETWORK_CREATE_SUBNET_MANAGER_FAILED;
    }

    int ret = LnnRegistPhysicalSubnet(manager);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "regist subnet manager failed! ret=%{public}d", ret);
        manager->destroy(manager);
        return ret;
    }
    return SOFTBUS_OK;
}

static ListenerModule LnnGetBtListenerModule(ListenerMode mode)
{
    return UNUSE_BUTT;
}

void LnnDeinitBtNetwork(struct LnnProtocolManager *self)
{
    (void)self;
    LnnUnregisterEventHandler(LNN_EVENT_BT_STATE_CHANGED, BtStateChangedEvtHandler);
    LnnUnregisterEventHandler(LNN_EVENT_BT_ACL_STATE_CHANGED, BtAclStateChangedEvtHandler);
    LnnUnregistPhysicalSubnetByType(LNN_PROTOCOL_BR | LNN_PROTOCOL_BLE);
    LNN_LOGW(LNN_INIT, "bt network deinited");
}

static LnnProtocolManager g_btProtocol = {
    .init = LnnInitBtProtocol,
    .deinit = LnnDeinitBtNetwork,
    .enable = LnnEnableBtProtocol,
    .disable = NULL,
    .getListenerModule = LnnGetBtListenerModule,
    .id = LNN_PROTOCOL_BR | LNN_PROTOCOL_BLE,
    .supportedNetif = LNN_NETIF_TYPE_BR | LNN_NETIF_TYPE_BLE,
    .pri = LNN_BT_PROTOCOL_PRI,
};

int32_t RegistBtProtocolManager(void)
{
    return LnnRegistProtocol(&g_btProtocol);
}