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

#include "bus_center_event.h"
#include "bus_center_manager.h"
#include "lnn_net_builder.h"
#include "lnn_network_manager.h"
#include "lnn_physical_subnet_manager.h"
#include "softbus_adapter_bt_common.h"
#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_utils.h"

#define LNN_BT_PROTOCOL_PRI 10

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
    subnet->status = transactMap[event][isAccepted ? BT_EVENT_RESULT_ACCEPTED : BT_EVENT_RESULT_REJECTED];
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_DBG, "subnet %s trans state from %d to %d", subnet->ifName,
        lastStatus, subnet->status);
}

static int32_t GetAvailableBtMac(char *macStr, uint32_t len)
{
    int32_t ret;
    SoftBusBtAddr mac;

    if (len != BT_MAC_LEN) {
        return SOFTBUS_INVALID_PARAM;
    }
    ret = SoftBusGetBtMacAddr(&mac);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get bt mac addr fail");
        return ret;
    }
    ret = ConvertBtMacToStr(macStr, len, mac.addr, sizeof(mac.addr));
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "convert bt mac to str fail");
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t EnableBrSubnet(LnnPhysicalSubnet *subnet)
{
    char macStr[BT_MAC_LEN] = {0};

    if (subnet->status == LNN_SUBNET_RUNNING) {
        return SOFTBUS_OK;
    }
    if (GetAvailableBtMac(macStr, sizeof(macStr)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get available bt mac fail");
        return SOFTBUS_ERR;
    }
    return LnnSetLocalStrInfo(STRING_KEY_BT_MAC, macStr);
}

static int32_t EnableBleSubnet(LnnPhysicalSubnet *subnet)
{
    (void)subnet;
    return SOFTBUS_OK;
}

static int32_t DisableBrSubnet(LnnPhysicalSubnet *subnet)
{
    int32_t ret;
    bool addrType[CONNECTION_ADDR_MAX] = {
        [CONNECTION_ADDR_BR] = true,
    };

    if (subnet->status != LNN_SUBNET_RUNNING) {
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "LNN br subnet is disable, start leave br network");
    ret = LnnRequestLeaveByAddrType(addrType, CONNECTION_ADDR_MAX);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LNN leave br network fail, ret=%d", ret);
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
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "LNN ble subnet is disable, start leave ble network");
    ret = LnnRequestLeaveByAddrType(addrType, CONNECTION_ADDR_MAX);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LNN leave ble network fail, ret=%d", ret);
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
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_DBG, "bluetooth is not enabled yet");
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

    int32_t ret = SOFTBUS_ERR;
    LnnNetIfType type;
    LnnGetNetIfTypeByName(subnet->ifName, &type);
    switch (event) {
        case BT_SUBNET_MANAGER_EVENT_IF_READY:
            if (type == LNN_NETIF_TYPE_BR) {
                ret = EnableBrSubnet(subnet);
            }
            if (type == LNN_NETIF_TYPE_BLE) {
                ret = EnableBleSubnet(subnet);
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
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_WARN, "discard unexpected event %d", event);
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
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "%s:calloc bt subnet fail", __func__);
        return NULL;
    }

    do {
        subnet->Destroy = DestroyBtSubnetManager;
        subnet->protocol = self;
        subnet->status = LNN_SUBNET_IDLE;
        subnet->OnNetifStatusChanged = OnBtNetifStatusChanged;
        subnet->OnSoftbusNetworkDisconnected = NULL;

        int32_t ret = strcpy_s(subnet->ifName, sizeof(subnet->ifName), ifName);
        if (ret != EOK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "%s:copy ifName failed! ret=%d", __func__, ret);
            break;
        }
        return subnet;
    } while (false);

    subnet->Destroy(subnet);
    return NULL;
}

static VisitNextChoice NotifyBtStatusChanged(const LnnNetIfMgr *netifManager, void *data)
{
    SoftBusBtState btState = (SoftBusBtState)(*(uint8_t *)data);
    if (netifManager->type == LNN_NETIF_TYPE_BR &&
        (btState == SOFTBUS_BR_TURN_ON || btState == SOFTBUS_BR_TURN_OFF)) {
        LnnNotifyPhysicalSubnetAddressChanged(netifManager->ifName, LNN_PROTOCOL_BR | LNN_PROTOCOL_BLE, data);
    }
    if (netifManager->type == LNN_NETIF_TYPE_BLE &&
        (btState == SOFTBUS_BLE_TURN_ON || btState == SOFTBUS_BLE_TURN_OFF)) {
        LnnNotifyPhysicalSubnetAddressChanged(netifManager->ifName, LNN_PROTOCOL_BR | LNN_PROTOCOL_BLE, data);
    }
    return CHOICE_VISIT_NEXT;
}

static void LnnBtStateChangeEventHandler(const LnnEventBasicInfo *info)
{
    if (info == NULL || info->event != LNN_EVENT_BT_STATE_CHANGED) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB bt state event handler get invalid param");
        return;
    }

    LnnMonitorBtStateChangedEvent *event = (LnnMonitorBtStateChangedEvent *)info;
    (void)LnnVisitNetif(NotifyBtStatusChanged, &event->status);
}

static void LnnLeaveSpecificBrNetwork(const char *btMac)
{
    char networkId[NETWORK_ID_BUF_LEN] = {0};
    if (LnnGetNetworkIdByBtMac(btMac, networkId, sizeof(networkId)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_WARN, "networkId not found by btMac.");
        return;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO,
        "LNN start leave specific br network: %s.", AnonymizesNetworkID(networkId));
    int32_t ret = LnnRequestLeaveSpecific(networkId, CONNECTION_ADDR_BR);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LNN leave br network fail(=%d).", ret);
    }
}

static void LnnBtAclStateChangeEventHandler(const LnnEventBasicInfo *info)
{
    if (info == NULL || info->event != LNN_EVENT_BT_ACL_STATE_CHANGED) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "bt acl state event handler get invalid param");
        return;
    }

    const LnnMonitorBtAclStateChangedEvent *event = (const LnnMonitorBtAclStateChangedEvent *)info;
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "BtAclStateChange: %d", event->status);
    switch (event->status) {
        case SOFTBUS_BR_ACL_CONNECTED:
            /* do nothing */
            break;
        case SOFTBUS_BR_ACL_DISCONNECTED:
            LnnLeaveSpecificBrNetwork(event->btMac);
            break;
        default:
            break;
    }
}

int32_t LnnInitBtProtocol(struct LnnProtocolManager *self)
{
    (void)self;
    if (LnnRegisterEventHandler(LNN_EVENT_BT_STATE_CHANGED, LnnBtStateChangeEventHandler) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "register bt state change event handler failed");
        return SOFTBUS_ERR;
    }
    if (LnnRegisterEventHandler(LNN_EVENT_BT_ACL_STATE_CHANGED, LnnBtAclStateChangeEventHandler) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "register bt acl state change event handler failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnEnableBtProtocol(struct LnnProtocolManager *self, LnnNetIfMgr *netifMgr)
{
    (void)self;

    if (netifMgr == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "%s:netifMgr null ptr!", __func__);
        return SOFTBUS_INVALID_PARAM;
    }
    LnnPhysicalSubnet *manager = CreateBtSubnetManager(self, netifMgr->ifName);
    if (manager == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "%s:create bt subnet mgr fail", __func__);
        return SOFTBUS_ERR;
    }

    int ret = LnnRegistPhysicalSubnet(manager);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "%s:regist subnet manager failed! ret=%d", __func__, ret);
        manager->Destroy(manager);
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
    LnnUnregisterEventHandler(LNN_EVENT_BT_STATE_CHANGED, LnnBtStateChangeEventHandler);
    LnnUnregisterEventHandler(LNN_EVENT_BT_ACL_STATE_CHANGED, LnnBtAclStateChangeEventHandler);
    LnnUnregistPhysicalSubnetByType(LNN_PROTOCOL_BR | LNN_PROTOCOL_BLE);
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_WARN, "%s:bt network deinited", __func__);
}

static LnnProtocolManager g_btProtocol = {
    .id = LNN_PROTOCOL_BR | LNN_PROTOCOL_BLE,
    .pri = LNN_BT_PROTOCOL_PRI,
    .supportedNetif = LNN_NETIF_TYPE_BR | LNN_NETIF_TYPE_BLE,
    .Init = LnnInitBtProtocol,
    .Deinit = LnnDeinitBtNetwork,
    .Enable = LnnEnableBtProtocol,
    .Disable = NULL,
    .GetListenerModule = LnnGetBtListenerModule,
};

int32_t RegistBtProtocolManager(void)
{
    return LnnRegistProtocol(&g_btProtocol);
}