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
#include "lnn_network_manager.h"
#include "message_handler.h"
#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"
#include "softbus_log.h"

#define DRIVER_SERVICE_NAME "hdf_dsoftbus"

#define NETIF_NAME_LENGTH 16

#define BIND_HDF_DELAY           1000
#define MAX_BIND_HDF_RETRY_COUNT 10

typedef struct {
    struct HdfIoService *softbusService;
    struct HdfDevEventlistener eventListener;
} HdfDriverEventCtrl;

typedef struct {
    uint32_t event;
    char ifName[NETIF_NAME_LENGTH];
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
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "read data from sbuff failed!");
        return;
    }

    if (eventData == NULL || eventDataSize != sizeof(LwipMonitorReportInfo)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "receive lwip monitor not correct size: %d<->%d", eventDataSize,
            sizeof(LwipMonitorReportInfo));
        return;
    }
    const LwipMonitorReportInfo *info = (const LwipMonitorReportInfo *)eventData;

    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "receive lwip monitor event(%d) for %s", info->event, info->ifName);
    if (LnnGetNetIfTypeByName(info->ifName, &type) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ProcessLwipEvent LnnGetNetIfTypeByName error");
        return;
    }
    if (type == LNN_NETIF_TYPE_ETH || type == LNN_NETIF_TYPE_WLAN) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "network addr changed, type:%d", type);
        LnnNotifyAddressChangedEvent(info->ifName);
    }
}

static void ProcessWlanEvent(struct HdfSBuf *data)
{
    LnnNotifyWlanStateChangeEvent(SOFTBUS_WIFI_UNKNOWN);
}

static int32_t OnReceiveDriverEvent(
    struct HdfDevEventlistener *listener, struct HdfIoService *service, uint32_t moduleId, struct HdfSBuf *data)
{
    (void)listener;
    (void)service;
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "receive hdf moudle(%d) event", moduleId);
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
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get hdf dsoftbus service fail(%d)", retry);
        LnnAsyncCallbackDelayHelper(GetLooper(LOOP_TYPE_DEFAULT), DelayInitFunction, NULL, BIND_HDF_DELAY);
        ++retry;
        return;
    }
    rc = HdfDeviceRegisterEventListener(g_driverCtrl.softbusService, &g_driverCtrl.eventListener);
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "init hdf driver monitor(%d) result: %d", retry, rc);
    if (rc != SOFTBUS_OK) {
        HdfIoServiceRecycle(g_driverCtrl.softbusService);
        g_driverCtrl.softbusService = NULL;
        LnnAsyncCallbackDelayHelper(GetLooper(LOOP_TYPE_DEFAULT), DelayInitFunction, NULL, BIND_HDF_DELAY);
    }
    ++retry;
}

int32_t LnnInitDriverMonitorImpl(void)
{
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "hdf driver monitor init enter");
    g_driverCtrl.eventListener.onReceive = OnReceiveDriverEvent;
    return LnnAsyncCallbackDelayHelper(GetLooper(LOOP_TYPE_DEFAULT), DelayInitFunction, NULL, BIND_HDF_DELAY);
}