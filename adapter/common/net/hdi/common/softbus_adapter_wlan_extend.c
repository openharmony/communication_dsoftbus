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

#include "softbus_adapter_wlan_extend.h"

#include <stdlib.h>
#include <string.h>

#include "lnn_log.h"
#include "lnn_async_callback_utils.h"
#include "securec.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "v1_1/iwlan_interface.h"

#define WLAN_SERVICE_NAME "wlan_interface_service"
#define WLAN_IFNAME "wlan0"
#define MEAS_TIME_PER_CHAN_MS (15)
#define GET_MEAS_RESULT_DELAY_MS (1000)
static struct IWlanInterface *g_wlanObj = NULL;
static WlanChannelInfoCb *g_wlanChannelInfoCb = NULL;
static ChannelInfoList g_channelInfoList;
static ChannelList g_channelList;
static void GetOneChannelMeasResult(void *para);

int32_t SoftBusRegWlanChannelInfoCb(WlanChannelInfoCb *cb)
{
    if (cb == NULL) {
        LNN_LOGE(LNN_STATE, "invalid parameter");
        return SOFTBUS_INVALID_PARAM;
    }
    g_wlanChannelInfoCb = cb;
    return SOFTBUS_OK;
}

static int32_t GetHdiInstance(void)
{
    if (g_wlanObj != NULL) {
        LNN_LOGE(LNN_STATE, "hdi instance already exists");
        return SOFTBUS_OK;
    }
    g_wlanObj = IWlanInterfaceGetInstance(WLAN_SERVICE_NAME, false);
    if (g_wlanObj == NULL) {
        LNN_LOGE(LNN_STATE, "wlan interface get instance fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static void ReleaseMeasResources(void)
{
    IWlanInterfaceReleaseInstance(WLAN_SERVICE_NAME, g_wlanObj, false);
    g_wlanObj = NULL;
    SoftBusFree(g_channelList.buff);
    (void)memset_s(&g_channelList, sizeof(ChannelList), 0, sizeof(ChannelList));
    g_channelList.buff = NULL;
    SoftBusFree(g_channelInfoList.buff);
    (void)memset_s(&g_channelInfoList, sizeof(ChannelInfoList), 0, sizeof(ChannelInfoList));
    g_channelInfoList.buff = NULL;
}

static void ExcuteChannelMeas(void)
{
    if (g_channelList.measNum >= g_channelList.num) {
        WlanChannelInfo *info = g_channelInfoList.buff;
        uint32_t num = g_channelInfoList.num;
        if (g_wlanChannelInfoCb->onChannelInfoAvailable != NULL) {
            g_wlanChannelInfoCb->onChannelInfoAvailable(info, num);
        }
        ReleaseMeasResources();
        return;
    }
    int32_t channelId = *(g_channelList.buff + g_channelList.measNum);
    struct MeasChannelParam measChannelParam;
    measChannelParam.channelId = channelId;
    measChannelParam.measTime = MEAS_TIME_PER_CHAN_MS;
    int32_t rc = g_wlanObj->StartChannelMeas(g_wlanObj, WLAN_IFNAME, &measChannelParam);
    if (rc != HDF_SUCCESS) {
        if (g_wlanChannelInfoCb->onFail != NULL) {
            g_wlanChannelInfoCb->onFail(rc);
        }
        ReleaseMeasResources();
        LNN_LOGE(LNN_STATE, "softbus StartChannelMeas fail ret=%{public}d", rc);
        return;
    }
    g_channelList.measNum++;
    if (LnnAsyncCallbackDelayHelper(GetLooper(LOOP_TYPE_DEFAULT), GetOneChannelMeasResult, NULL,
        GET_MEAS_RESULT_DELAY_MS) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "LnnAsyncCallbackDelayHelper get result delay fail");
        return;
    }
}

int32_t SoftBusRequestWlanChannelInfo(int32_t *channelId, uint32_t num)
{
    if (channelId == NULL || num == 0) {
        LNN_LOGE(LNN_STATE, "invalid parameter");
        return SOFTBUS_INVALID_PARAM;
    }
    if (GetHdiInstance() != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "softbus get hdi instance fail");
        return SOFTBUS_ERR;
    }
    if (g_channelList.buff != NULL || g_channelInfoList.buff != NULL) {
        LNN_LOGI(LNN_STATE, "measuring channel");
        return SOFTBUS_OK;
    }

    g_channelList.buff = (int32_t *)SoftBusCalloc(sizeof(int32_t) * num);
    if (g_channelList.buff == NULL) {
        LNN_LOGE(LNN_STATE, " SoftBusCalloc channelId fail");
        return SOFTBUS_ERR;
    }
    g_channelList.num = num;
    g_channelList.measNum = 0;
    if (memcpy_s(g_channelList.buff, sizeof(int32_t) * num, channelId, sizeof(int32_t) * num) != EOK) {
        LNN_LOGE(LNN_STATE, "net hdi memcpy fail");
        SoftBusFree(g_channelList.buff);
        g_channelList.buff = NULL;
        return SOFTBUS_ERR;
    }

    g_channelInfoList.buff = (WlanChannelInfo *)SoftBusCalloc(sizeof(WlanChannelInfo) * num);
    if (g_channelInfoList.buff == NULL) {
        LNN_LOGE(LNN_STATE, "SoftBusCalloc WlanChannelInfo fail");
        SoftBusFree(g_channelList.buff);
        g_channelList.buff = NULL;
        return SOFTBUS_ERR;
    }
    g_channelInfoList.num = num;
    WlanChannelInfo *temp = g_channelInfoList.buff;
    for (uint32_t i = 0; i < num; i++) {
        temp->channelId = *channelId;
        temp++;
        channelId++;
    }
    /* start measuring */
    ExcuteChannelMeas();
    return SOFTBUS_OK;
}

static void GetOneChannelMeasResult(void *para)
{
    (void)para;
    struct MeasChannelResult measChannelResult = {0};
    int32_t rc = g_wlanObj->GetChannelMeasResult(g_wlanObj, WLAN_IFNAME, &measChannelResult);
    if (rc != HDF_SUCCESS) {
        if (g_wlanChannelInfoCb->onFail != NULL) {
            g_wlanChannelInfoCb->onFail(rc);
        }
        ReleaseMeasResources();
        LNN_LOGE(LNN_STATE, "softbus GetChannelMeasResult failed ret=%{public}d", rc);
        return;
    }
    (g_channelInfoList.buff + g_channelList.measNum-1)->channelId = measChannelResult.channelId;
    (g_channelInfoList.buff + g_channelList.measNum-1)->chload = measChannelResult.chload;
    (g_channelInfoList.buff + g_channelList.measNum-1)->noise = measChannelResult.noise;
    ExcuteChannelMeas();
}
