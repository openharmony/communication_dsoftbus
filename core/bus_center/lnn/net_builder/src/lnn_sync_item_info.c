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

#include "lnn_sync_item_info.h"

#include <securec.h>

#include "lnn_connection_addr_utils.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_local_net_ledger.h"
#include "lnn_log.h"
#include "lnn_net_builder.h"
#include "lnn_sync_info_manager.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_socket.h"
#include "softbus_error_code.h"
#include "softbus_wifi_api_adapter.h"

#define CONN_CODE_SHIFT 16
#define DISCOVERY_TYPE_MASK 0x7FFF

static int32_t FillTargetWifiConfig(const unsigned char *targetBssid, const char *ssid,
                                    const SoftBusWifiDevConf *conWifiConf, SoftBusWifiDevConf *targetWifiConf)
{
    if (strcpy_s(targetWifiConf->ssid, sizeof(targetWifiConf->ssid), ssid) != EOK) {
        LNN_LOGE(LNN_BUILDER, "str copy ssid fail");
        return SOFTBUS_STRCPY_ERR;
    }

    if (memcpy_s(targetWifiConf->bssid, sizeof(targetWifiConf->bssid),
        targetBssid, sizeof(targetWifiConf->bssid)) != EOK) {
        LNN_LOGE(LNN_BUILDER, "mem copy bssid fail");
        return SOFTBUS_MEM_ERR;
    }

    if (strcpy_s(targetWifiConf->preSharedKey, sizeof(targetWifiConf->preSharedKey),
        conWifiConf->preSharedKey) != EOK) {
        LNN_LOGE(LNN_BUILDER, "str copy ssid fail");
        return SOFTBUS_STRCPY_ERR;
    }

    targetWifiConf->securityType = conWifiConf->securityType;
    targetWifiConf->isHiddenSsid = conWifiConf->isHiddenSsid;
    return SOFTBUS_OK;
}

static void ResultClean(SoftBusWifiDevConf *result)
{
    (void)memset_s(result, sizeof(SoftBusWifiDevConf) * WIFI_MAX_CONFIG_SIZE, 0,
                   sizeof(SoftBusWifiDevConf) * WIFI_MAX_CONFIG_SIZE);
    SoftBusFree(result);
}

static int32_t WifiConnectToTargetAp(const unsigned char *targetBssid, const char *ssid)
{
    SoftBusWifiDevConf *result = NULL;
    uint32_t wifiConfigSize;
    SoftBusWifiDevConf targetDeviceConf;
    uint32_t i;

    result = (SoftBusWifiDevConf *)SoftBusMalloc(sizeof(SoftBusWifiDevConf) * WIFI_MAX_CONFIG_SIZE);
    if (result == NULL) {
        LNN_LOGE(LNN_BUILDER, "malloc wifi device config fail");
        return SOFTBUS_MALLOC_ERR;
    }
    (void)memset_s(&targetDeviceConf, sizeof(SoftBusWifiDevConf), 0, sizeof(SoftBusWifiDevConf));
    (void)memset_s(result, sizeof(SoftBusWifiDevConf) * WIFI_MAX_CONFIG_SIZE, 0,
                   sizeof(SoftBusWifiDevConf) * WIFI_MAX_CONFIG_SIZE);
    int32_t retVal = SoftBusGetWifiDeviceConfig(result, &wifiConfigSize);
    if (retVal != SOFTBUS_OK || wifiConfigSize > WIFI_MAX_CONFIG_SIZE) {
        LNN_LOGE(LNN_BUILDER, "git config fail, retVal=%{public}d, wifiConfigSize=%{public}d", retVal, wifiConfigSize);
        ResultClean(result);
        return SOFTBUS_GET_WIFI_DEVICE_CONFIG_FAIL;
    }

    for (i = 0; i < wifiConfigSize; i++) {
        if (strcmp(ssid, (result + i)->ssid) != 0) {
            continue;
        }
        if (FillTargetWifiConfig(targetBssid, ssid, result + i, &targetDeviceConf) != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "fill device config fail");
            (void)memset_s(&targetDeviceConf, sizeof(SoftBusWifiDevConf), 0, sizeof(SoftBusWifiDevConf));
            ResultClean(result);
            return SOFTBUS_MEM_ERR;
        }
        break;
    }
    retVal = SoftBusDisconnectDevice();
    if (retVal != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "dis connect device fail");
        (void)memset_s(&targetDeviceConf, sizeof(SoftBusWifiDevConf), 0, sizeof(SoftBusWifiDevConf));
        ResultClean(result);
        return retVal;
    }
    retVal = SoftBusConnectToDevice(&targetDeviceConf);
    if (retVal != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "connect to target ap fail");
        (void)memset_s(&targetDeviceConf, sizeof(SoftBusWifiDevConf), 0, sizeof(SoftBusWifiDevConf));
        ResultClean(result);
        return retVal;
    }
    (void)memset_s(&targetDeviceConf, sizeof(SoftBusWifiDevConf), 0, sizeof(SoftBusWifiDevConf));
    ResultClean(result);
    return SOFTBUS_OK;
}

void OnReceiveDeviceName(LnnSyncInfoType type, const char *networkId, const uint8_t *msg, uint32_t len)
{
    char udid[UDID_BUF_LEN];
    BssTransInfo *bssTranInfo = NULL;
    if (msg == NULL) {
        LNN_LOGE(LNN_BUILDER, "msg is null");
        return;
    }
    if (type != LNN_INFO_TYPE_DEVICE_NAME) {
        return;
    }
    if (LnnConvertDlId(networkId, CATEGORY_NETWORK_ID, CATEGORY_UDID, udid, UDID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "convert networkId to udid fail");
        return;
    }
    bssTranInfo = (BssTransInfo *)msg;
    if (WifiConnectToTargetAp(bssTranInfo->targetBssid, bssTranInfo->ssid) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "wifi connect to target ap failed");
    }
}

void OnReceiveTransReqMsg(LnnSyncInfoType type, const char *networkId, const uint8_t *msg, uint32_t len)
{
    char udid[UDID_BUF_LEN];

    LNN_LOGI(LNN_BUILDER, "recv trans req msg infoType=%{public}d, len=%{public}d", type, len);
    if (type != LNN_INFO_TYPE_BSS_TRANS) {
        return;
    }
    if (LnnConvertDlId(networkId, CATEGORY_NETWORK_ID, CATEGORY_UDID, udid, UDID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "convert networkId to udid fail");
        return;
    }
    if (!LnnSetDLDeviceInfoName(udid, (char *)msg)) {
        LNN_LOGI(LNN_BUILDER, "set peer device name fail");
    }
}

static void OnReceiveBrOffline(LnnSyncInfoType type, const char *networkId, const uint8_t *msg, uint32_t len)
{
    uint32_t combinedInt;
    char uuid[UUID_BUF_LEN];
    int16_t peerCode, code;
    DiscoveryType discType;

    LNN_LOGI(LNN_BUILDER, "Recv offline info, infoType=%{public}d, len=%{public}d", type, len);
    if (type != LNN_INFO_TYPE_OFFLINE) {
        return;
    }
    if (msg == NULL || len != sizeof(int32_t)) {
        return;
    }
    combinedInt = *(uint32_t *)msg;
    combinedInt = SoftBusNtoHl(combinedInt);
    peerCode = (int16_t)(combinedInt >> CONN_CODE_SHIFT);
    discType = (DiscoveryType)(combinedInt & DISCOVERY_TYPE_MASK);
    if (LnnConvertDlId(networkId, CATEGORY_NETWORK_ID, CATEGORY_UUID, uuid, UUID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "covert networkId to uuid fail");
        return;
    }
    code = LnnGetCnnCode(uuid, DISCOVERY_TYPE_BR);
    if (code == INVALID_CONNECTION_CODE_VALUE) {
        LNN_LOGE(LNN_BUILDER, "uuid not exist");
        return;
    }
    if (discType != DISCOVERY_TYPE_BR || code != peerCode) {
        LNN_LOGE(LNN_BUILDER, "info error discType=%{public}d, code=%{public}d, peerCode=%{public}d",
            discType, code, peerCode);
        return;
    }
    if (LnnRequestLeaveSpecific(networkId, LnnDiscTypeToConnAddrType(discType)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "request leave specific fail");
    }
}

int32_t LnnSendTransReq(const char *peerNetWorkId, const BssTransInfo *transInfo)
{
    if (peerNetWorkId == NULL || transInfo == NULL) {
        LNN_LOGE(LNN_BUILDER, "para peerNetWorkId or tansInfo is null");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret = LnnSetDLBssTransInfo(peerNetWorkId, transInfo);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "save bssTransinfo fail");
        return ret;
    }

    ret = LnnSendSyncInfoMsg(
        LNN_INFO_TYPE_BSS_TRANS, peerNetWorkId, (const uint8_t *)transInfo, sizeof(BssTransInfo), NULL);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "send bss info fail");
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t LnnInitOffline(void)
{
    return LnnRegSyncInfoHandler(LNN_INFO_TYPE_OFFLINE, OnReceiveBrOffline);
}

void LnnDeinitOffline(void)
{
    (void)LnnUnregSyncInfoHandler(LNN_INFO_TYPE_OFFLINE, OnReceiveBrOffline);
}
