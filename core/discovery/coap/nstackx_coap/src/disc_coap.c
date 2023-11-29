/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "disc_coap.h"

#include <stdio.h>
#include "disc_event.h"
#include "disc_log.h"
#include "disc_nstackx_adapter.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_utils.h"
#include "softbus_hidumper_disc.h"
#include "softbus_hisysevt_discreporter.h"

#define INT32_MAX_BIT_NUM 32
#define MAX_CAP_NUM (CAPABILITY_NUM * INT32_MAX_BIT_NUM)

#define COAP_PUBLISH_INFO "coapPublishInfo"
#define COAP_SUBSCRIBE_INFO "coapSubscribeInfo"

typedef struct {
    uint32_t allCap[CAPABILITY_NUM];
    int16_t capCount[MAX_CAP_NUM];
    bool isUpdate;
    bool isEmpty;
    SoftBusMutex lock;
} DiscCoapInfo;

static DiscCoapInfo *g_publishMgr = NULL;
static DiscCoapInfo *g_subscribeMgr = NULL;
static int CoapPubInfoDump(int fd);
static int CoapSubInfoDump(int fd);

static int32_t RegisterAllCapBitmap(uint32_t capBitmapNum, const uint32_t inCapBitmap[], DiscCoapInfo *info,
    uint32_t count)
{
    if (info == NULL || capBitmapNum == 0 || capBitmapNum > CAPABILITY_NUM || count > MAX_CAP_NUM) {
        DISC_LOGW(DISC_COAP, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    DISC_CHECK_AND_RETURN_RET_LOGW((inCapBitmap[0] >> APPROACH_CAPABILITY_BITMAP) == 0, SOFTBUS_INVALID_PARAM,
        DISC_COAP, "CoAP not support approach capability");

    info->isUpdate = false;
    for (uint32_t i = 0; i < capBitmapNum; i++) {
        DISC_LOGI(DISC_COAP, "register input bitmap = [%u].", inCapBitmap[i]);
        for (uint32_t pos = 0; pos < count; pos++) {
            if (((inCapBitmap[i] >> (pos % INT32_MAX_BIT_NUM)) & 0x1) == 0) {
                continue;
            }
            if ((info->capCount)[pos] == 0) {
                (info->allCap)[i] |= (0x1 << (pos % INT32_MAX_BIT_NUM));
                info->isUpdate = true;
            }
            (info->capCount)[pos]++;
        }
        DISC_LOGI(DISC_COAP, "register all cap bitmap = [%u].", (info->allCap)[i]);
    }
    return SOFTBUS_OK;
}

static int32_t  UnregisterAllCapBitmap(uint32_t capBitmapNum, const uint32_t inCapBitmap[], DiscCoapInfo *info,
    uint32_t count)
{
    if (info == NULL || capBitmapNum == 0 || capBitmapNum > CAPABILITY_NUM || count > MAX_CAP_NUM) {
        DISC_LOGW(DISC_COAP, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    DISC_CHECK_AND_RETURN_RET_LOGW((inCapBitmap[0] >> APPROACH_CAPABILITY_BITMAP) == 0, SOFTBUS_INVALID_PARAM,
        DISC_COAP, "CoAP not support approach capability");

    info->isEmpty = true;
    info->isUpdate = false;
    for (uint32_t i = 0; i < capBitmapNum; i++) {
        DISC_LOGI(DISC_COAP, "unregister input bitmap = [%u].", inCapBitmap[i]);
        for (uint32_t pos = 0; pos < count; pos++) {
            if (((inCapBitmap[i] >> (pos % INT32_MAX_BIT_NUM)) & 0x1) == 0) {
                continue;
            }
            (info->capCount)[pos]--;
            if ((info->capCount)[pos] <= 0) {
                (info->allCap)[i] &= (~(0x1 << (pos % INT32_MAX_BIT_NUM)));
                (info->capCount)[pos] = 0;
                info->isUpdate = true;
            }
        }
        if ((info->allCap)[i] != 0) {
            info->isEmpty = false;
        }
        DISC_LOGI(DISC_COAP, "register all cap bitmap = [%u].", (info->allCap)[i]);
    }
    return SOFTBUS_OK;
}

static void SetDiscCoapOption(DiscCoapOption *discCoapOption, DiscOption *option, uint32_t allCap)
{
    if (option->isPublish) {
        discCoapOption->mode = ACTIVE_PUBLISH;
        discCoapOption->freq = option->option.publishOption.freq;
        discCoapOption->capability = option->option.publishOption.capabilityBitmap[0];
    } else {
        discCoapOption->mode = ACTIVE_DISCOVERY;
        discCoapOption->freq = option->option.subscribeOption.freq;
        discCoapOption->capability = option->option.subscribeOption.capabilityBitmap[0];
    }
    discCoapOption->allCap = allCap;
}

static int32_t Publish(const PublishOption *option, bool isActive)
{
    DISC_CHECK_AND_RETURN_RET_LOGW(option != NULL && g_publishMgr != NULL, SOFTBUS_INVALID_PARAM, DISC_COAP,
        "invalid param");
    DISC_CHECK_AND_RETURN_RET_LOGW(LOW <= option->freq && option->freq < FREQ_BUTT, SOFTBUS_INVALID_PARAM,
        DISC_COAP, "invalid freq: %d", option->freq);
    if (option->ranging) {
        DISC_LOGW(DISC_COAP, "coap publish not support ranging, is it misuse? just ignore");
    }

    DISC_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&(g_publishMgr->lock)) == 0, SOFTBUS_LOCK_ERR, DISC_COAP,
        "%s publish mutex lock failed", isActive ? "active" : "passive");
    DiscEventExtra discScanEventExtra = { .scanType = COAP };
    DiscEventExtra discBroadacastEventExtra = { .broadcastType = COAP, .broadcastFreq = option->freq };
    DISC_EVENT(EVENT_SCENE_SCAN, EVENT_STAGE_SCAN_START, discScanEventExtra);
    if (RegisterAllCapBitmap(CAPABILITY_NUM, option->capabilityBitmap, g_publishMgr, MAX_CAP_NUM) != SOFTBUS_OK) {
        SoftbusReportDiscFault(SOFTBUS_HISYSEVT_DISC_MEDIUM_COAP, SOFTBUS_HISYSEVT_DISCOVER_COAP_MERGE_CAP_FAIL);
        DISC_LOGW(DISC_COAP, "merge %s publish capability failed", isActive ? "active" : "passive");
        goto REG_FAIL;
    }
    if (g_publishMgr->isUpdate && DiscCoapRegisterCapability(CAPABILITY_NUM, g_publishMgr->allCap) != SOFTBUS_OK) {
        SoftbusReportDiscFault(SOFTBUS_HISYSEVT_DISC_MEDIUM_COAP, SOFTBUS_HISYSEVT_DISCOVER_COAP_REGISTER_CAP_FAIL);
        DISC_LOGW(DISC_COAP, "register all capability to dfinder failed.");
        goto REG_FAIL;
    }
    if (DiscCoapRegisterServiceData(option->capabilityData, option->dataLen,
        option->capabilityBitmap[0]) != SOFTBUS_OK) {
        DISC_LOGW(DISC_COAP, "register service data to dfinder failed.");
        goto REG_FAIL;
    }
    if (DiscCoapRegisterCapabilityData(option->capabilityData, option->dataLen,
        option->capabilityBitmap[0]) != SOFTBUS_OK) {
        DISC_LOGW(DISC_COAP, "register capability data to dfinder failed.");
        goto REG_FAIL;
    }
    if (isActive) {
        DiscCoapOption discCoapOption;
        DiscOption discOption = {
            .isPublish = true,
            .option.publishOption = *option,
        };
        SetDiscCoapOption(&discCoapOption, &discOption, 0);
        DISC_EVENT(EVENT_SCENE_BROADCAST, EVENT_STAGE_BROADCAST, discBroadacastEventExtra);
        if (DiscCoapStartDiscovery(&discCoapOption) != SOFTBUS_OK) {
            SoftbusReportDiscFault(SOFTBUS_HISYSEVT_DISC_MEDIUM_COAP,
                SOFTBUS_HISYSEVT_DISCOVER_COAP_START_DISCOVER_FAIL);
            DISC_LOGE(DISC_COAP, "coap active publish failed, allCap: %u", g_publishMgr->allCap[0]);
            goto BROADCAST_FAIL;
        }
    }
    (void)SoftBusMutexUnlock(&(g_publishMgr->lock));
    DISC_LOGW(DISC_COAP, "coap %s publish succ, allCap: %u", isActive ? "active" : "passive", g_publishMgr->allCap[0]);
    return SOFTBUS_OK;
REG_FAIL:
    discScanEventExtra.result = EVENT_STAGE_RESULT_FAILED;
    discScanEventExtra.errcode = SOFTBUS_DISCOVER_START_SCAN_FAIL;
    DISC_EVENT(EVENT_SCENE_SCAN, EVENT_STAGE_SCAN_START, discScanEventExtra);
    (void)SoftBusMutexUnlock(&(g_publishMgr->lock));
    return SOFTBUS_DISCOVER_COAP_START_PUBLISH_FAIL;
BROADCAST_FAIL:
    discBroadacastEventExtra.result = EVENT_STAGE_RESULT_FAILED;
    discBroadacastEventExtra.errcode = SOFTBUS_DISCOVER_START_BROADCAST_FAIL;
    DISC_EVENT(EVENT_SCENE_BROADCAST, EVENT_STAGE_BROADCAST, discBroadacastEventExtra);
    (void)SoftBusMutexUnlock(&(g_publishMgr->lock));
    return SOFTBUS_DISCOVER_COAP_START_PUBLISH_FAIL;
}

static int32_t CoapPublish(const PublishOption *option)
{
    return Publish(option, true);
}

static int32_t CoapStartScan(const PublishOption *option)
{
    return Publish(option, false);
}

static int32_t UnPublish(const PublishOption *option, bool isActive)
{
    DISC_CHECK_AND_RETURN_RET_LOGW(option != NULL && g_publishMgr != NULL, SOFTBUS_INVALID_PARAM,
        DISC_COAP, "invalid param");
    DISC_CHECK_AND_RETURN_RET_LOGW(LOW <= option->freq && option->freq < FREQ_BUTT, SOFTBUS_INVALID_PARAM,
        DISC_COAP, "invalid freq: %d", option->freq);
    DISC_CHECK_AND_RETURN_RET_LOGW(SoftBusMutexLock(&(g_publishMgr->lock)) == 0, SOFTBUS_LOCK_ERR, DISC_COAP,
        "%s unPublish mutex lock failed", isActive ? "active" : "passive");

    DiscEventExtra discScanEventExtra = { .scanType = COAP, .result = EVENT_STAGE_RESULT_OK };
    DISC_EVENT(EVENT_SCENE_SCAN, EVENT_STAGE_SCAN_START, discScanEventExtra);
    if (UnregisterAllCapBitmap(CAPABILITY_NUM, option->capabilityBitmap, g_publishMgr, MAX_CAP_NUM) != SOFTBUS_OK) {
        discScanEventExtra.result = EVENT_STAGE_RESULT_FAILED;
        discScanEventExtra.errcode = SOFTBUS_DISCOVER_COAP_CANCEL_CAP_FAIL;
        DISC_EVENT(EVENT_SCENE_SCAN, EVENT_STAGE_SCAN_START, discScanEventExtra);
        (void)SoftBusMutexUnlock(&(g_publishMgr->lock));
        DISC_LOGE(DISC_COAP, "unRegister %s publish capability failed", isActive ? "active" : "passive");
        SoftbusReportDiscFault(SOFTBUS_HISYSEVT_DISC_MEDIUM_COAP, SOFTBUS_HISYSEVT_DISCOVER_COAP_CANCEL_CAP_FAIL);
        return SOFTBUS_DISCOVER_COAP_CANCEL_CAP_FAIL;
    }
    if (g_publishMgr->isUpdate) {
        if (DiscCoapRegisterCapability(CAPABILITY_NUM, g_publishMgr->allCap) != SOFTBUS_OK) {
            discScanEventExtra.result = EVENT_STAGE_RESULT_FAILED;
            discScanEventExtra.errcode = SOFTBUS_DISCOVER_COAP_REGISTER_CAP_FAIL;
            DISC_EVENT(EVENT_SCENE_SCAN, EVENT_STAGE_SCAN_START, discScanEventExtra);
            (void)SoftBusMutexUnlock(&(g_publishMgr->lock));
            DISC_LOGE(DISC_COAP, "register all capability to dfinder failed.");
            SoftbusReportDiscFault(SOFTBUS_HISYSEVT_DISC_MEDIUM_COAP,
                SOFTBUS_HISYSEVT_DISCOVER_COAP_REGISTER_CAP_FAIL);
            return SOFTBUS_DISCOVER_COAP_REGISTER_CAP_FAIL;
        }
    }
    if (DiscCoapRegisterServiceData(option->capabilityData, option->dataLen,
        option->capabilityBitmap[0]) != SOFTBUS_OK) {
        discScanEventExtra.result = EVENT_STAGE_RESULT_FAILED;
        discScanEventExtra.errcode = SOFTBUS_DISCOVER_END_SCAN_FAIL;
        DISC_EVENT(EVENT_SCENE_SCAN, EVENT_STAGE_SCAN_START, discScanEventExtra);
        (void)SoftBusMutexUnlock(&(g_publishMgr->lock));
        DISC_LOGE(DISC_COAP, "register service data to dfinder failed.");
        return SOFTBUS_ERR;
    }
    if (isActive && g_publishMgr->isEmpty) {
        DiscEventExtra discEventExtra = {
            .broadcastType = COAP, .broadcastFreq = option->freq, .result = EVENT_STAGE_RESULT_OK
        };
        DISC_EVENT(EVENT_SCENE_BROADCAST, EVENT_STAGE_BROADCAST, discEventExtra);
        if (DiscCoapStopDiscovery() != SOFTBUS_OK) {
            discEventExtra.result = EVENT_STAGE_RESULT_FAILED;
            discEventExtra.errcode = SOFTBUS_DISCOVER_END_BROADCAST_FAIL;
            DISC_EVENT(EVENT_SCENE_BROADCAST, EVENT_STAGE_BROADCAST, discEventExtra);
            (void)SoftBusMutexUnlock(&(g_publishMgr->lock));
            DISC_LOGE(DISC_COAP, "coap unpublish failed, allCap: %u", g_publishMgr->allCap[0]);
            SoftbusReportDiscFault(SOFTBUS_HISYSEVT_DISC_MEDIUM_COAP,
                SOFTBUS_HISYSEVT_DISCOVER_COAP_STOP_DISCOVER_FAIL);
            return SOFTBUS_DISCOVER_COAP_STOP_PUBLISH_FAIL;
        }
    }
    (void)SoftBusMutexUnlock(&(g_publishMgr->lock));
    DISC_LOGI(DISC_COAP, "coap %s unPublish succ, allCap: %u", isActive ?
        "active" : "passive", g_publishMgr->allCap[0]);
    return SOFTBUS_OK;
}

static int32_t CoapUnPublish(const PublishOption *option)
{
    return UnPublish(option, true);
}

static int32_t CoapStopScan(const PublishOption *option)
{
    return UnPublish(option, false);
}

static int32_t Discovery(const SubscribeOption *option, bool isActive)
{
    DISC_CHECK_AND_RETURN_RET_LOGW(option != NULL && g_subscribeMgr != NULL, SOFTBUS_INVALID_PARAM,
        DISC_COAP, "invalid param");
    DISC_CHECK_AND_RETURN_RET_LOGW(LOW <= option->freq && option->freq < FREQ_BUTT, SOFTBUS_INVALID_PARAM,
        DISC_COAP, "invalid freq: %d", option->freq);
    DISC_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&(g_subscribeMgr->lock)) == 0, SOFTBUS_LOCK_ERR, DISC_COAP,
        "%s discovery mutex lock failed", isActive ? "active" : "passive");

    DiscEventExtra discScanEventExtra = { .scanType = COAP };
    DISC_EVENT(EVENT_SCENE_SCAN, EVENT_STAGE_SCAN_START, discScanEventExtra);
    if (RegisterAllCapBitmap(CAPABILITY_NUM, option->capabilityBitmap, g_subscribeMgr, MAX_CAP_NUM) != SOFTBUS_OK) {
        discScanEventExtra.result = EVENT_STAGE_RESULT_FAILED;
        discScanEventExtra.errcode = SOFTBUS_DISCOVER_START_SCAN_FAIL;
        DISC_EVENT(EVENT_SCENE_SCAN, EVENT_STAGE_SCAN_START, discScanEventExtra);
        (void)SoftBusMutexUnlock(&(g_subscribeMgr->lock));
        DISC_LOGE(DISC_COAP, "merge %s discovery capability failed", isActive ? "active" : "passive");
        SoftbusReportDiscFault(SOFTBUS_HISYSEVT_DISC_MEDIUM_COAP, SOFTBUS_HISYSEVT_DISCOVER_COAP_MERGE_CAP_FAIL);
        return SOFTBUS_DISCOVER_COAP_MERGE_CAP_FAIL;
    }
    if (g_subscribeMgr->isUpdate) {
        if (DiscCoapSetFilterCapability(CAPABILITY_NUM, g_subscribeMgr->allCap) != SOFTBUS_OK) {
            discScanEventExtra.result = EVENT_STAGE_RESULT_FAILED;
            discScanEventExtra.errcode = SOFTBUS_DISCOVER_START_SCAN_FAIL;
            DISC_EVENT(EVENT_SCENE_SCAN, EVENT_STAGE_SCAN_START, discScanEventExtra);
            (void)SoftBusMutexUnlock(&(g_subscribeMgr->lock));
            DISC_LOGE(DISC_COAP, "set all filter capability to dfinder failed.");
            SoftbusReportDiscFault(SOFTBUS_HISYSEVT_DISC_MEDIUM_COAP,
                SOFTBUS_HISYSEVT_DISCOVER_COAP_SET_FILTER_CAP_FAIL);
            return SOFTBUS_DISCOVER_COAP_SET_FILTER_CAP_FAIL;
        }
    }
    if (!isActive) {
        (void)SoftBusMutexUnlock(&(g_subscribeMgr->lock));
        DISC_LOGI(DISC_COAP, "coap start passive discovery succ, filters: %u", g_subscribeMgr->allCap[0]);
        return SOFTBUS_OK;
    }
    if (DiscCoapStopDiscovery() != SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&(g_subscribeMgr->lock));
        DISC_LOGE(DISC_COAP, "coap stop discovery failed, filters: %u", g_subscribeMgr->allCap[0]);
        SoftbusReportDiscFault(SOFTBUS_HISYSEVT_DISC_MEDIUM_COAP, SOFTBUS_HISYSEVT_DISCOVER_COAP_STOP_DISCOVER_FAIL);
        return SOFTBUS_DISCOVER_COAP_STOP_DISCOVER_FAIL;
    }
    DiscCoapOption discCoapOption;
    DiscOption discOption = {
        .isPublish = false,
        .option.subscribeOption = *option,
    };
    SetDiscCoapOption(&discCoapOption, &discOption, g_subscribeMgr->allCap[0]);
    DiscEventExtra discEventExtra = { .broadcastType = COAP, .broadcastFreq = option->freq };
    DISC_EVENT(EVENT_SCENE_BROADCAST, EVENT_STAGE_BROADCAST, discEventExtra);
    if (DiscCoapStartDiscovery(&discCoapOption) != SOFTBUS_OK) {
        discEventExtra.result = EVENT_STAGE_RESULT_FAILED;
        discEventExtra.errcode = SOFTBUS_DISCOVER_START_BROADCAST_FAIL;
        DISC_EVENT(EVENT_SCENE_BROADCAST, EVENT_STAGE_BROADCAST, discEventExtra);
        (void)SoftBusMutexUnlock(&(g_subscribeMgr->lock));
        DISC_LOGE(DISC_COAP, "coap start discovery failed, filters: %u", g_subscribeMgr->allCap[0]);
        SoftbusReportDiscFault(SOFTBUS_HISYSEVT_DISC_MEDIUM_COAP, SOFTBUS_HISYSEVT_DISCOVER_COAP_START_DISCOVER_FAIL);
        return SOFTBUS_DISCOVER_COAP_START_DISCOVER_FAIL;
    }
    (void)SoftBusMutexUnlock(&(g_subscribeMgr->lock));
    DISC_LOGI(DISC_COAP, "coap start active discovery succ, filters: %u", g_subscribeMgr->allCap[0]);
    return SOFTBUS_OK;
}

static int32_t CoapStartAdvertise(const SubscribeOption *option)
{
    return Discovery(option, true);
}

static int32_t CoapSubscribe(const SubscribeOption *option)
{
    return Discovery(option, false);
}

static int32_t StopDisc(const SubscribeOption *option, bool isActive)
{
    DISC_CHECK_AND_RETURN_RET_LOGW(option != NULL && g_subscribeMgr != NULL, SOFTBUS_INVALID_PARAM,
        DISC_COAP, "invalid param");
    DISC_CHECK_AND_RETURN_RET_LOGW(LOW <= option->freq && option->freq < FREQ_BUTT, SOFTBUS_INVALID_PARAM,
        DISC_COAP, "invalid freq: %d", option->freq);
    DISC_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&(g_subscribeMgr->lock)) == 0, SOFTBUS_LOCK_ERR,
        DISC_COAP, "stop %s discovery mutex lock failed", isActive ? "active" : "passive");

    DiscEventExtra discScanEventExtra = { .scanType = COAP, .result = EVENT_STAGE_RESULT_OK };
    DISC_EVENT(EVENT_SCENE_SCAN, EVENT_STAGE_SCAN_START, discScanEventExtra);
    if (UnregisterAllCapBitmap(CAPABILITY_NUM, option->capabilityBitmap, g_subscribeMgr,  MAX_CAP_NUM) != SOFTBUS_OK) {
        discScanEventExtra.result = EVENT_STAGE_RESULT_FAILED;
        discScanEventExtra.errcode = SOFTBUS_DISCOVER_END_SCAN_FAIL;
        DISC_EVENT(EVENT_SCENE_SCAN, EVENT_STAGE_SCAN_START, discScanEventExtra);
        (void)SoftBusMutexUnlock(&(g_subscribeMgr->lock));
        DISC_LOGE(DISC_COAP, "unRegister %s discovery capability failed", isActive ? "active" : "passive");
        SoftbusReportDiscFault(SOFTBUS_HISYSEVT_DISC_MEDIUM_COAP, SOFTBUS_HISYSEVT_DISCOVER_COAP_CANCEL_CAP_FAIL);
        return SOFTBUS_DISCOVER_COAP_CANCEL_CAP_FAIL;
    }
    if (g_subscribeMgr->isUpdate) {
        if (DiscCoapSetFilterCapability(CAPABILITY_NUM, g_subscribeMgr->allCap) != SOFTBUS_OK) {
            discScanEventExtra.result = EVENT_STAGE_RESULT_FAILED;
            discScanEventExtra.errcode = SOFTBUS_DISCOVER_END_SCAN_FAIL;
            DISC_EVENT(EVENT_SCENE_SCAN, EVENT_STAGE_SCAN_START, discScanEventExtra);
            (void)SoftBusMutexUnlock(&(g_subscribeMgr->lock));
            DISC_LOGE(DISC_COAP, "set all filter capability to dfinder failed.");
            SoftbusReportDiscFault(SOFTBUS_HISYSEVT_DISC_MEDIUM_COAP,
                SOFTBUS_HISYSEVT_DISCOVER_COAP_SET_FILTER_CAP_FAIL);
            return SOFTBUS_DISCOVER_COAP_SET_FILTER_CAP_FAIL;
        }
    }
    if (isActive && g_subscribeMgr->isEmpty) {
        DiscEventExtra discEventExtra = {
            .broadcastType = COAP, .broadcastFreq = option->freq, .result = EVENT_STAGE_RESULT_OK
        };
        DISC_EVENT(EVENT_SCENE_BROADCAST, EVENT_STAGE_BROADCAST, discEventExtra);
        if (DiscCoapStopDiscovery() != SOFTBUS_OK) {
            discEventExtra.result = EVENT_STAGE_RESULT_FAILED;
            discEventExtra.errcode = SOFTBUS_DISCOVER_END_BROADCAST_FAIL;
            DISC_EVENT(EVENT_SCENE_BROADCAST, EVENT_STAGE_BROADCAST, discEventExtra);
            (void)SoftBusMutexUnlock(&(g_subscribeMgr->lock));
            DISC_LOGE(DISC_COAP, "coap stop active discovery failed, filters: %u", g_subscribeMgr->allCap[0]);
            SoftbusReportDiscFault(SOFTBUS_HISYSEVT_DISC_MEDIUM_COAP,
                SOFTBUS_HISYSEVT_DISCOVER_COAP_STOP_DISCOVER_FAIL);
            return SOFTBUS_DISCOVER_COAP_STOP_DISCOVER_FAIL;
        }
    }
    (void)SoftBusMutexUnlock(&(g_subscribeMgr->lock));
    DISC_LOGI(DISC_COAP, "coap stop %s discovery succ, filters: %u",
        isActive ? "active" : "passive", g_subscribeMgr->allCap[0]);
    return SOFTBUS_OK;
}

static int32_t CoapStopAdvertise(const SubscribeOption *option)
{
    return StopDisc(option, true);
}

static int32_t CoapUnsubscribe(const SubscribeOption *option)
{
    return StopDisc(option, false);
}

static void CoapUpdateLocalIp(LinkStatus status)
{
    DiscCoapUpdateLocalIp(status);
}

static void CoapUpdateLocalDeviceInfo(InfoTypeChanged type)
{
    if (type == TYPE_LOCAL_DEVICE_NAME) {
        DiscCoapUpdateDevName();
    } else if (type == TYPE_ACCOUNT) {
        DiscCoapUpdateAccount();
    } else {
        DISC_LOGW(DISC_COAP, "invalid info change type: %d", type);
    }
}

static DiscoveryFuncInterface g_discCoapFuncInterface = {
    .Publish = CoapPublish,
    .StartScan = CoapStartScan,
    .Unpublish = CoapUnPublish,
    .StopScan = CoapStopScan,
    .StartAdvertise = CoapStartAdvertise,
    .Subscribe = CoapSubscribe,
    .StopAdvertise = CoapStopAdvertise,
    .Unsubscribe = CoapUnsubscribe,
    .LinkStatusChanged = CoapUpdateLocalIp,
    .UpdateLocalDeviceInfo = CoapUpdateLocalDeviceInfo
};

static DiscCoapInfo *NewDiscCoapInfo(void)
{
    DiscCoapInfo *coapInfo = (DiscCoapInfo*)SoftBusCalloc(sizeof(DiscCoapInfo));
    DISC_CHECK_AND_RETURN_RET_LOGE(coapInfo != NULL, NULL, DISC_INIT, "softbus malloc failed");

    if (SoftBusMutexInit(&(coapInfo->lock), NULL) != 0) {
        SoftBusFree(coapInfo);
        return NULL;
    }
    return coapInfo;
}

static void DeleteDiscCoapInfo(DiscCoapInfo *coapInfo)
{
    DISC_CHECK_AND_RETURN_LOGW(coapInfo != NULL, DISC_COAP, "coapInfo=NULL");
    (void)SoftBusMutexDestroy(&(coapInfo->lock));
    SoftBusFree(coapInfo);
}

static void DeinitCoapManager(void)
{
    DeleteDiscCoapInfo(g_publishMgr);
    g_publishMgr = NULL;
    DeleteDiscCoapInfo(g_subscribeMgr);
    g_subscribeMgr = NULL;
}

static int32_t InitCoapManager(void)
{
    if (g_publishMgr == NULL) {
        g_publishMgr = NewDiscCoapInfo();
    }
    if (g_subscribeMgr == NULL) {
        g_subscribeMgr = NewDiscCoapInfo();
    }
    if (g_publishMgr == NULL || g_subscribeMgr == NULL) {
        DeinitCoapManager();
        return SOFTBUS_DISCOVER_COAP_INIT_FAIL;
    }
    return SOFTBUS_OK;
}

DiscoveryFuncInterface *DiscCoapInit(DiscInnerCallback *discInnerCb)
{
    if (InitCoapManager() != SOFTBUS_OK) {
        DISC_LOGE(DISC_INIT, "coap manager init failed.");
        return NULL;
    }
    if (DiscNstackxInit() != SOFTBUS_OK) {
        DISC_LOGE(DISC_INIT, "dfinder init failed.");
        DeinitCoapManager();
        return NULL;
    }
    if (DiscCoapRegisterCb(discInnerCb) != SOFTBUS_OK) {
        DISC_LOGE(DISC_INIT, "register coap callback to dfinder failed.");
        DiscCoapDeinit();
        return NULL;
    }
    SoftBusRegDiscVarDump(COAP_PUBLISH_INFO, &CoapPubInfoDump);
    SoftBusRegDiscVarDump(COAP_SUBSCRIBE_INFO, &CoapSubInfoDump);
    DISC_LOGI(DISC_INIT, "coap discovery init success.");
    return &g_discCoapFuncInterface;
}

void DiscCoapDeinit(void)
{
    DeinitCoapManager();
    DiscNstackxDeinit();
}

static int CoapPubInfoDump(int fd)
{
    if (SoftBusMutexLock(&(g_publishMgr->lock)) != SOFTBUS_OK) {
        DISC_LOGE(DISC_COAP, "g_publishMgr mutex lock failed.");
        return SOFTBUS_LOCK_ERR;
    }
    SOFTBUS_DPRINTF(fd, "\n---------------CoapPublishInfo------------------\n");
    SOFTBUS_DPRINTF(fd, "publish allCap              : %u\n", *(g_publishMgr->allCap));
    SOFTBUS_DPRINTF(fd, "publish capCount            : %hd\n", *(g_publishMgr->capCount));
    SOFTBUS_DPRINTF(fd, "publish isUpdate            : %d\n", g_publishMgr->isUpdate);
    SOFTBUS_DPRINTF(fd, "publish isEmpty             : %d\n", g_publishMgr->isEmpty);
    (void)SoftBusMutexUnlock(&(g_publishMgr->lock));
    return SOFTBUS_OK;
}

static int CoapSubInfoDump(int fd)
{
    if (SoftBusMutexLock(&(g_subscribeMgr->lock)) != SOFTBUS_OK) {
        DISC_LOGE(DISC_COAP, "g_subscribeMgr mutex lock failed.");
        return SOFTBUS_LOCK_ERR;
    }
    SOFTBUS_DPRINTF(fd, "\n---------------CoapSubscribeInfo------------------\n");
    SOFTBUS_DPRINTF(fd, "subscribe allCap            : %u\n", *(g_subscribeMgr->allCap));
    SOFTBUS_DPRINTF(fd, "subscribe capCount          : %hd\n", *(g_subscribeMgr->capCount));
    SOFTBUS_DPRINTF(fd, "subscribe isUpdate          : %d\n", g_subscribeMgr->isUpdate);
    SOFTBUS_DPRINTF(fd, "subscribe isEmpty           : %d\n", g_subscribeMgr->isEmpty);
    (void)SoftBusMutexUnlock(&(g_subscribeMgr->lock));
    return SOFTBUS_OK;
}
