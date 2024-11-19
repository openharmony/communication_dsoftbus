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

#include "bus_center_event.h"
#include "lnn_log.h"
#include "softbus_error_code.h"
#include "hdf_io_service_if.h"

#define HISYSLINK_SERVICE_NAME "hisyslink_service"
#define IP_READY 124

static struct HdfIoService *g_serv = NULL;

static int OnDevEventReceived(void* priv, unsigned int id, struct HdfSBuf* data)
{
    (void)data;
    if (id == IP_READY) {
        if (priv != NULL) {
            LNN_LOGI(LNN_STATE, "dev event received, event=%{public}s, id=%{public}u", (char*)priv, id);
        }
        LnnNotifyAddressChangedEvent(NULL);
    }
    return HDF_SUCCESS;
}

static struct HdfDevEventlistener g_listener = {
    .callBack = OnDevEventReceived,
    .priv = "Service0",
};

int32_t LnnInitProductMonitorImpl(void)
{
    g_serv = HdfIoServiceBind(HISYSLINK_SERVICE_NAME);
    if (g_serv == NULL) {
        LNN_LOGI(LNN_STATE, "fail to get service. HISYSLINK_SERVICE_NAME=%{public}s", HISYSLINK_SERVICE_NAME);
        return SOFTBUS_BIND_DRIVER_FAIL;
    }

    int32_t ret = HdfDeviceRegisterEventListener(g_serv, &g_listener);
    if (ret != HDF_SUCCESS) {
        LNN_LOGI(LNN_STATE, "fail to register event listener");
        HdfIoServiceRecycle(g_serv);
        g_serv = NULL;
        return ret;
    }
    LNN_LOGI(LNN_STATE, "start success");
    return SOFTBUS_OK;
}

void LnnDeinitProductMonitorImpl(void)
{
    if (g_serv == NULL) {
        return;
    }
    LNN_LOGI(LNN_INIT, "deinit g_serv enter");
    HdfIoServiceRecycle(g_serv);
    g_serv = NULL;
}
