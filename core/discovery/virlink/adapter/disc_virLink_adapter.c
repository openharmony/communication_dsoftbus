/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "disc_virLink_adapter.h"

#include <securec.h>

#include "anonymizer.h"
#include "auth_interface.h"
#include "auth_manager.h"
#include "lnn_distributed_net_ledger.h"
#include "bus_center_manager.h"
#include "disc_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"
#include "wifi_direct_manager.h"

static DiscVirlinkLinklessRecvCb g_discVirLinkLinklessCb = NULL;
static struct DiscVirlinkConnStatusListener g_discVirlinkConnStatusListener = {NULL};

static int32_t VirLinkLinklessGetWifiDirectAuthByNetworkId(const char *networkId, AuthHandle *authHandle)
{
    char uuid[UUID_BUF_LEN] = {0};
    int32_t ret = LnnConvertDlId(networkId, CATEGORY_NETWORK_ID, CATEGORY_UUID, uuid, UUID_BUF_LEN);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BROADCAST, "convert dlId fail");
    AuthDeviceGetLatestIdByUuid(uuid, AUTH_LINK_TYPE_ENHANCED_P2P, authHandle);

    if (authHandle->authId != AUTH_INVALID_ID) {
        char *anonyNetworkId = NULL;
        Anonymize(networkId, &anonyNetworkId);
        DISC_LOGI(DISC_BROADCAST, "find wifidirect authHandle, networkId=%{public}s",
            AnonymizeWrapper(anonyNetworkId));
        AnonymizeFree(anonyNetworkId);
        return SOFTBUS_OK;
    }
    return SOFTBUS_INVALID_PARAM;
}

int DiscVirlinkLinklessVirtualSend(const char *networkId, const uint8_t *data, uint32_t dataLen)
{
    if (networkId == NULL || data == NULL || dataLen == 0) {
        DISC_LOGE(DISC_BROADCAST, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    AuthHandle authHandle = { .authId = AUTH_INVALID_ID };
    if (VirLinkLinklessGetWifiDirectAuthByNetworkId(networkId, &authHandle) != SOFTBUS_OK) {
        char *anonyNetworkId = NULL;
        Anonymize(networkId, &anonyNetworkId);
        DISC_LOGE(DISC_BROADCAST, "get authHandle fail, networkId=%{public}s", AnonymizeWrapper(anonyNetworkId));
        AnonymizeFree(anonyNetworkId);
        return SOFTBUS_INVALID_PARAM;
    }

    DISC_LOGI(DISC_BROADCAST, "send virtual msg, authId=%{public}" PRId64 ", datalen=%{public}u", authHandle.authId,
              dataLen);
    AuthTransData dataInfo = {
        .module = MODULE_VIRTUAL_LINK,
        .flag = 0,
        .seq = 0,
        .len = dataLen,
        .data = data,
    };
    int32_t ret = AuthPostTransData(authHandle, &dataInfo);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BROADCAST, "auth post data fail");
    return SOFTBUS_OK;
}

static void OnVirlinkLinklessMsgRecv(AuthHandle authHandle, const AuthTransData *data)
{
    char networkId[NETWORK_ID_BUF_LEN] = {0};
    DISC_CHECK_AND_RETURN_LOGE(data != NULL, DISC_BROADCAST, "recv null data, authId=%{public}" PRId64,
                               authHandle.authId);

    DISC_LOGI(DISC_BROADCAST, "recv linkless msg. authId=%{public}" PRId64 ", len=%{public}u", authHandle.authId,
              data->len);

    AuthManager *auth = GetAuthManagerByAuthId(authHandle.authId);
    DISC_CHECK_AND_RETURN_LOGE(auth != NULL, DISC_BROADCAST, "auth is null");

    char *anonyUdid = NULL;
    Anonymize(auth->udid, &anonyUdid);
    DISC_LOGI(DISC_BROADCAST, "udid=%{public}s", AnonymizeWrapper(anonyUdid));
    AnonymizeFree(anonyUdid);
    if (LnnGetNetworkIdByUdid(auth->udid, networkId, sizeof(networkId)) != SOFTBUS_OK) {
        DISC_LOGE(DISC_BROADCAST, "LnnGetNetworkIdByUdid fail");
        DelDupAuthManager(auth);
        return;
    }
    DelDupAuthManager(auth);

    DiscVirlinkLinklessRecvCb recvCb = g_discVirLinkLinklessCb;
    if (recvCb != NULL) {
        recvCb(networkId, data->data, data->len);
    }
}

static void OnVirlinkLinklessAuthClose(AuthHandle authHandle)
{
    DISC_LOGW(DISC_BROADCAST, "authId=%{public}" PRId64, authHandle.authId);
}

static void VirlinkLinklessOnDeviceOnline(const char *remoteMac, const char *remoteIp,
    const char *remoteUuid, bool isSource)
{
    if (remoteMac == NULL || remoteIp == NULL || remoteUuid == NULL) {
        DISC_LOGE(DISC_BROADCAST, "invalid param");
        return;
    }

    char networkId[NETWORK_ID_BUF_LEN] = {0};
    if (LnnGetNetworkIdByUuid(remoteUuid, networkId, sizeof(networkId)) != SOFTBUS_OK) {
        DISC_LOGE(DISC_BROADCAST, "LnnGetNetworkIdByUuid fail");
        return;
    }

    char *anonyNetworkId = NULL;
    Anonymize(networkId, &anonyNetworkId);
    DISC_LOGI(DISC_BROADCAST, "device online, network=%{public}s", AnonymizeWrapper(anonyNetworkId));
    AnonymizeFree(anonyNetworkId);
    struct DiscVirlinkConnStatusListener listener = g_discVirlinkConnStatusListener;
    if (listener.onDeviceOnline != NULL) {
        listener.onDeviceOnline(remoteMac, remoteIp, networkId, isSource);
    }
}

static void VirlinkLinklessOnDeviceOffline(const char *remoteMac, const char *remoteIp,
    const char *remoteUuid, const char *localIp)
{
    if (remoteMac == NULL || remoteIp == NULL || remoteUuid == NULL || localIp == NULL) {
        DISC_LOGE(DISC_BROADCAST, "invalid param");
        return;
    }

    char networkId[NETWORK_ID_BUF_LEN] = {0};
    if (LnnGetNetworkIdByUuid(remoteUuid, networkId, sizeof(networkId)) != SOFTBUS_OK) {
        DISC_LOGE(DISC_BROADCAST, "LnnGetNetworkIdByUuid fail");
        return;
    }

    char *anonyNetworkId = NULL;
    Anonymize(networkId, &anonyNetworkId);
    DISC_LOGI(DISC_BROADCAST, "device offline, network=%{public}s", AnonymizeWrapper(anonyNetworkId));
    AnonymizeFree(anonyNetworkId);
    struct DiscVirlinkConnStatusListener listener = g_discVirlinkConnStatusListener;
    if (listener.onDeviceOffline != NULL) {
        listener.onDeviceOffline(remoteMac, remoteIp, networkId, localIp);
    }
}

static struct WifiDirectStatusListener g_virlinkWifiDirectStatusListener = {
    NULL,
    VirlinkLinklessOnDeviceOnline,
    VirlinkLinklessOnDeviceOffline,
    NULL,
    NULL,
};

void DiscVirlinkLinklessRegisterListener(const struct DiscVirlinkConnStatusListener *listener)
{
    if (listener != NULL && listener->onDeviceOnline != NULL && listener->onDeviceOffline != NULL) {
        g_discVirlinkConnStatusListener.onDeviceOnline = listener->onDeviceOnline;
        g_discVirlinkConnStatusListener.onDeviceOffline = listener->onDeviceOffline;
        GetWifiDirectManager()->registerStatusListener(&g_virlinkWifiDirectStatusListener);
    }
}

int DiscVirlinkLinklessRegisterRecvCallback(DiscVirlinkLinklessRecvCb recvCb)
{
    AuthTransListener linklessCb = {
        .onDataReceived = OnVirlinkLinklessMsgRecv,
        .onDisconnected = OnVirlinkLinklessAuthClose,
        .onException = NULL,
    };
    int32_t ret = RegAuthTransListener(MODULE_VIRTUAL_LINK, &linklessCb);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BROADCAST, "reg auth listener fail");

    g_discVirLinkLinklessCb = recvCb;
    return SOFTBUS_OK;
}