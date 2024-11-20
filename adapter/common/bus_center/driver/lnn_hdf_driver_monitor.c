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

#include "lnn_event_monitor_impl.h"

#include <hdf_io_service.h>
#include <hdf_sbuf.h>
#include <securec.h>

#include "lnn_async_callback_utils.h"
#include "lnn_driver_request.h"
#include "lnn_log.h"
#include "lnn_network_manager.h"
#include "message_handler.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"

#define DRIVER_SERVICE_NAME      "hdf_dsoftbus"
#define NETIF_NAME_LENGTH        16
#define BIND_HDF_DELAY           1000
#define MAX_BIND_HDF_RETRY_COUNT 10

typedef struct {
    struct HdfIoService *softbusService;
    struct HdfDevEventlistener eventListener;
} HdfDriverEventCtrl;

typedef struct {
    char ifName[NETIF_NAME_LENGTH];
    uint32_t event;
    union ExtInfo {
        int32_t status;
    } extInfo;
} LwipMonitorReportInfo;

static HdfDriverEventCtrl g_driverCtrl;

static void ProcessLwipEvent(struct HdfSBuf *data)
{
    LnnNetIfType type = LNN_NETIF_TYPE_ETH;
    uint32_t eventDataSize = 0;
    uint8_t *eventData = NULL;

    if (!HdfSbufReadBuffer(data, (const void **)&eventData, &eventDataSize)) {
        LNN_LOGE(LNN_EVENT, "read data from sbuff failed");
        return;
    }

    if (eventData == NULL || eventDataSize != sizeof(LwipMonitorReportInfo)) {
        LNN_LOGE(LNN_EVENT,
            "receive lwip monitor not correct size: eventDataSize=%{public}d, LwipMonitorReportInfo=%{public}zu",
            eventDataSize, sizeof(LwipMonitorReportInfo));
        return;
    }
    const LwipMonitorReportInfo *info = (const LwipMonitorReportInfo *)eventData;

    LNN_LOGI(LNN_EVENT, "receive lwip monitor event=%{public}d, ifName=%{public}s", info->event, info->ifName);
    if (LnnGetNetIfTypeByName(info->ifName, &type) != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "LnnGetNetIfTypeByName error");
        return;
    }
    if (type == LNN_NETIF_TYPE_ETH || type == LNN_NETIF_TYPE_WLAN) {
        LNN_LOGI(LNN_EVENT, "network addr changed, netifType=%{public}d", type);
        LnnNotifyAddressChangedEvent(info->ifName);
    }
}

static void ProcessWlanEvent(struct HdfSBuf *data)
{
    SoftBusWifiState *notifyState = (SoftBusWifiState *)SoftBusMalloc(sizeof(SoftBusWifiState));
    if (notifyState == NULL) {
        LNN_LOGE(LNN_EVENT, "notifyState malloc err");
        return;
    }
    *notifyState = SOFTBUS_WIFI_UNKNOWN;
    int32_t ret = LnnAsyncCallbackHelper(GetLooper(LOOP_TYPE_DEFAULT), LnnNotifyWlanStateChangeEvent,
        (void *)notifyState);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "async notify wifi state err, ret=%{public}d", ret);
        SoftBusFree(notifyState);
    }
}

static int32_t OnReceiveDriverEvent(
    struct HdfDevEventlistener *listener, struct HdfIoService *service, uint32_t moduleId, struct HdfSBuf *data)
{
    (void)listener;
    (void)service;
    if (data == NULL) {
        LNN_LOGI(LNN_EVENT, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    LNN_LOGI(LNN_EVENT, "receive hdf event, moudle=%{public}d", moduleId);
    if (moduleId >= LNN_DRIVER_MODULE_MAX_INDEX) {
        return SOFTBUS_OK;
    }
    switch (moduleId) {
        case LNN_DRIVER_MODULE_WLAN_PARAM:
            ProcessWlanEvent(data);
            break;
        case LNN_DRIVER_MODULE_LWIP_MONITOR:
            ProcessLwipEvent(data);
            break;
        default:
            break;
    }
    return SOFTBUS_OK;
}

static void DelayInitFunction(void *para)
{
    int32_t rc;
    static int32_t retry = 0;

    (void)para;
    if (retry >= MAX_BIND_HDF_RETRY_COUNT) {
        return;
    }
    g_driverCtrl.softbusService = HdfIoServiceBind(DRIVER_SERVICE_NAME);
    if (g_driverCtrl.softbusService == NULL) {
        LNN_LOGE(LNN_INIT, "get hdf dsoftbus service fail=%{public}d", retry);
        LnnAsyncCallbackDelayHelper(GetLooper(LOOP_TYPE_DEFAULT), DelayInitFunction, NULL, BIND_HDF_DELAY);
        ++retry;
        return;
    }
    rc = HdfDeviceRegisterEventListener(g_driverCtrl.softbusService, &g_driverCtrl.eventListener);
    LNN_LOGI(LNN_INIT, "init hdf driver monitor=%{public}d, result=%{public}d", retry, rc);
    if (rc != SOFTBUS_OK) {
        HdfIoServiceRecycle(g_driverCtrl.softbusService);
        g_driverCtrl.softbusService = NULL;
        LnnAsyncCallbackDelayHelper(GetLooper(LOOP_TYPE_DEFAULT), DelayInitFunction, NULL, BIND_HDF_DELAY);
    }
    ++retry;
}

int32_t LnnInitDriverMonitorImpl(void)
{
    LNN_LOGI(LNN_INIT, "hdf driver monitor init enter");
    g_driverCtrl.eventListener.onReceive = OnReceiveDriverEvent;
    return LnnAsyncCallbackDelayHelper(GetLooper(LOOP_TYPE_DEFAULT), DelayInitFunction, NULL, BIND_HDF_DELAY);
}

void LnnDeinitDriverMonitorImpl(void)
{
    if (g_driverCtrl.softbusService == NULL) {
        return;
    }
    LNN_LOGI(LNN_INIT, "hdf driver deinit enter");
    HdfIoServiceRecycle(g_driverCtrl.softbusService);
    g_driverCtrl.softbusService = NULL;
}