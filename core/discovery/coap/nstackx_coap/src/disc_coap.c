/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include <securec.h>
#include <stdio.h>

#include "disc_event.h"
#include "disc_log.h"
#include "disc_nstackx_adapter.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_error_code.h"
#include "legacy/softbus_hidumper_disc.h"
#include "legacy/softbus_hisysevt_discreporter.h"

#define INT32_MAX_BIT_NUM 32
#define MAX_CAP_NUM (CAPABILITY_NUM * INT32_MAX_BIT_NUM)

#define COAP_PUBLISH_INFO "coapPublishInfo"
#define COAP_SUBSCRIBE_INFO "coapSubscribeInfo"

typedef struct {
    bool isUpdate;
    bool isEmpty;
    int16_t capCount[MAX_CAP_NUM];
    uint32_t allCap[CAPABILITY_NUM];
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
        DISC_LOGE(DISC_COAP, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    DISC_CHECK_AND_RETURN_RET_LOGE((inCapBitmap[0] >> APPROACH_CAPABILITY_BITMAP) == 0, SOFTBUS_INVALID_PARAM,
        DISC_COAP, "CoAP not support approach capability");

    info->isUpdate = false;
    for (uint32_t i = 0; i < capBitmapNum; i++) {
        DISC_LOGD(DISC_COAP, "register input bitmap=%{public}u", inCapBitmap[i]);
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
        DISC_LOGD(DISC_COAP, "register all cap bitmap=%{public}u", (info->allCap)[i]);
    }
    return SOFTBUS_OK;
}

static int32_t UnregisterAllCapBitmap(uint32_t capBitmapNum, const uint32_t inCapBitmap[], DiscCoapInfo *info,
    uint32_t count)
{
    if (info == NULL || capBitmapNum == 0 || capBitmapNum > CAPABILITY_NUM || count > MAX_CAP_NUM) {
        DISC_LOGE(DISC_COAP, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    DISC_CHECK_AND_RETURN_RET_LOGE((inCapBitmap[0] >> APPROACH_CAPABILITY_BITMAP) == 0, SOFTBUS_INVALID_PARAM,
        DISC_COAP, "CoAP not support approach capability");

    info->isEmpty = true;
    info->isUpdate = false;
    for (uint32_t i = 0; i < capBitmapNum; i++) {
        DISC_LOGD(DISC_COAP, "unregister input bitmap=%{public}u", inCapBitmap[i]);
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
        DISC_LOGD(DISC_COAP, "register all cap bitmap=%{public}u", (info->allCap)[i]);
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

static void DfxRecordCoapEnd(bool isStart, bool isActive, bool isPublish, const void *option, int32_t reason)
{
    DiscEventExtra extra = { 0 };
    DiscEventExtraInit(&extra);
    extra.discType = COAP + 1;
    extra.discMode = isActive ? DISCOVER_MODE_ACTIVE : DISCOVER_MODE_PASSIVE;
    extra.errcode = reason;
    extra.result = (reason == SOFTBUS_OK) ? EVENT_STAGE_RESULT_OK : EVENT_STAGE_RESULT_FAILED;

    const char *capabilityData = NULL;
    uint32_t dataLen = MAX_CAPABILITYDATA_LEN - 1;
    if (isPublish) {
        extra.interFuncType = (isStart ? PUBLISH_FUNC : UNPUBLISH_FUNC) + 1;
        if (option != NULL) {
            PublishOption *publishOption = (PublishOption *)option;
            extra.broadcastFreq = publishOption->freq;
            capabilityData = (const char *)publishOption->capabilityData;
            dataLen = publishOption->dataLen < dataLen ? publishOption->dataLen : dataLen;
        }
    } else {
        extra.interFuncType = (isStart ? STARTDISCOVERTY_FUNC : STOPDISCOVERY_FUNC) + 1;
        if (option != NULL) {
            SubscribeOption *subscribeOption = (SubscribeOption *)option;
            extra.broadcastFreq = subscribeOption->freq;
            capabilityData = (const char *)subscribeOption->capabilityData;
            dataLen = subscribeOption->dataLen < dataLen ? subscribeOption->dataLen : dataLen;
        }
    }

    char data[MAX_CAPABILITYDATA_LEN] = { 0 };
    if (capabilityData != NULL && strncpy_s(data, MAX_CAPABILITYDATA_LEN, capabilityData, dataLen) == EOK) {
        extra.capabilityData = data;
    }
    DISC_EVENT(EVENT_SCENE_COAP, EVENT_STAGE_COAP, extra);
}

static void DfxRecordRegisterEnd(uint32_t capability, int32_t reason)
{
    if (reason == SOFTBUS_OK) {
        return;
    }

    DiscEventExtra extra = { 0 };
    DiscEventExtraInit(&extra);
    extra.discType = COAP + 1;
    extra.capabilityBit = (int32_t)capability;
    extra.errcode = reason;
    extra.result = EVENT_STAGE_RESULT_FAILED;
    DISC_EVENT(EVENT_SCENE_COAP, EVENT_STAGE_REGISTER, extra);
}

static void DfxRecordSetFilterEnd(uint32_t capability, int32_t reason)
{
    DiscEventExtra extra = { 0 };
    DiscEventExtraInit(&extra);
    extra.discType = COAP + 1;
    extra.capabilityBit = (int32_t)capability;
    extra.errcode = reason;
    extra.result = (reason == SOFTBUS_OK) ? EVENT_STAGE_RESULT_OK : EVENT_STAGE_RESULT_FAILED;
    DISC_EVENT(EVENT_SCENE_COAP, EVENT_STAGE_SET_FILTER, extra);
}

static bool CheckParam(const PublishOption *pubOption, const SubscribeOption *subOption, bool isPublish)
{
    if (isPublish) {
        DISC_CHECK_AND_RETURN_RET_LOGE(pubOption != NULL, false, DISC_COAP, "publish option is null");
        DISC_CHECK_AND_RETURN_RET_LOGE(g_publishMgr != NULL, false, DISC_COAP, "g_publishMgr is null");
        DISC_CHECK_AND_RETURN_RET_LOGE(LOW <= pubOption->freq && pubOption->freq < FREQ_BUTT, false, DISC_COAP,
            "invalid publish freq. freq=%{public}d", pubOption->freq);
        if (pubOption->ranging) {
            DISC_LOGW(DISC_COAP, "coap publish not support ranging");
        }
    } else {
        DISC_CHECK_AND_RETURN_RET_LOGE(subOption != NULL, false, DISC_COAP, "discovery option is null");
        DISC_CHECK_AND_RETURN_RET_LOGE(g_subscribeMgr != NULL, false, DISC_COAP, "g_subscribeMgr is null");
        DISC_CHECK_AND_RETURN_RET_LOGE(LOW <= subOption->freq && subOption->freq < FREQ_BUTT, false, DISC_COAP,
            "invalid discovery freq. freq=%{public}d", subOption->freq);
    }
    return true;
}

static bool CheckFeature(const PublishOption *option)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(option != NULL, false, DISC_COAP, "option is null");
    uint32_t capabilityBit = option->capabilityBitmap[0];
    switch (capabilityBit) {
        case 1 << DDMP_CAPABILITY_BITMAP:
#ifdef DSOFTBUS_FEATURE_DISC_LNN_COAP
            return true;
#else
            DISC_LOGW(DISC_COAP, "coap publish not support lnn");
            return false;
#endif /* DSOFTBUS_FEATURE_DISC_LNN_COAP */
        case 1 << SHARE_CAPABILITY_BITMAP:
#ifdef DSOFTBUS_FEATURE_DISC_SHARE_COAP
            return true;
#else
            DISC_LOGW(DISC_COAP, "coap publish not support share");
            return false;
#endif /* DSOFTBUS_FEATURE_DISC_SHARE_COAP */
        default:
#ifdef DSOFTBUS_FEATURE_DISC_COAP
            return true;
#else
            DISC_LOGW(DISC_COAP, "coap publish not support");
            return false;
#endif /* DSOFTBUS_FEATURE_DISC_COAP */
    }
}

static int32_t Publish(const PublishOption *option, bool isActive)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(CheckParam(option, NULL, true), SOFTBUS_INVALID_PARAM, DISC_COAP, "invalid param");
    DISC_CHECK_AND_RETURN_RET_LOGE(CheckFeature(option), SOFTBUS_INVALID_PARAM, DISC_COAP, "invalid param");
    DISC_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&(g_publishMgr->lock)) == 0, SOFTBUS_LOCK_ERR, DISC_COAP,
        "publish mutex lock failed. isActive=%{public}s", isActive ? "active" : "passive");
    if (RegisterAllCapBitmap(CAPABILITY_NUM, option->capabilityBitmap, g_publishMgr, MAX_CAP_NUM) != SOFTBUS_OK) {
        SoftbusReportDiscFault(SOFTBUS_HISYSEVT_DISC_MEDIUM_COAP, SOFTBUS_HISYSEVT_DISCOVER_COAP_MERGE_CAP_FAIL);
        DISC_LOGE(DISC_COAP, "merge publish capability failed. isActive=%{public}s", isActive ? "active" : "passive");
        goto PUB_FAIL;
    }
    if (g_publishMgr->isUpdate && DiscCoapRegisterCapability(CAPABILITY_NUM, g_publishMgr->allCap) != SOFTBUS_OK) {
        SoftbusReportDiscFault(SOFTBUS_HISYSEVT_DISC_MEDIUM_COAP, SOFTBUS_HISYSEVT_DISCOVER_COAP_REGISTER_CAP_FAIL);
        DISC_LOGE(DISC_COAP, "register all capability to dfinder failed.");
        goto PUB_FAIL;
    }
    uint32_t curCap = option->capabilityBitmap[0];
    if (DiscCoapRegisterServiceData(option, g_publishMgr->allCap[0]) != SOFTBUS_OK) {
        DfxRecordRegisterEnd(curCap, SOFTBUS_DISCOVER_COAP_REGISTER_CAP_FAIL);
        DISC_LOGE(DISC_COAP, "register service data to dfinder failed.");
        goto PUB_FAIL;
    }
#ifdef DSOFTBUS_FEATURE_DISC_SHARE_COAP
    if (DiscCoapRegisterCapabilityData(option->capabilityData, option->dataLen, curCap) != SOFTBUS_OK) {
        DISC_LOGW(DISC_COAP, "register capability data to dfinder failed.");
        goto PUB_FAIL;
    }
#endif /* DSOFTBUS_FEATURE_DISC_SHARE_COAP */
    if (isActive) {
        DiscCoapOption discCoapOption;
        DiscOption discOption = {
            .isPublish = true,
            .option.publishOption = *option,
        };
        SetDiscCoapOption(&discCoapOption, &discOption, 0);
        if (DiscCoapStartDiscovery(&discCoapOption) != SOFTBUS_OK) {
            SoftbusReportDiscFault(SOFTBUS_HISYSEVT_DISC_MEDIUM_COAP,
                SOFTBUS_HISYSEVT_DISCOVER_COAP_START_DISCOVER_FAIL);
            DISC_LOGE(DISC_COAP, "coap active publish failed, allCap=%{public}u", g_publishMgr->allCap[0]);
            goto PUB_FAIL;
        }
    }
    (void)SoftBusMutexUnlock(&(g_publishMgr->lock));
    DISC_LOGI(DISC_COAP, "coap publish succ, isActive=%{public}s, allCap=%{public}u ", isActive ? "active" : "passive",
        g_publishMgr->allCap[0]);
    return SOFTBUS_OK;
PUB_FAIL:
    (void)SoftBusMutexUnlock(&(g_publishMgr->lock));
    return SOFTBUS_DISCOVER_COAP_START_PUBLISH_FAIL;
}

static int32_t CoapPublish(const PublishOption *option)
{
    int32_t ret = Publish(option, true);
    DfxRecordCoapEnd(true, true, true, (void *)option, ret);
    return ret;
}

static int32_t CoapStartScan(const PublishOption *option)
{
    int32_t ret = Publish(option, false);
    if (ret != SOFTBUS_OK && option != NULL) {
        DiscAuditExtra extra = {
            .result = DISC_AUDIT_DISCONTINUE,
            .errcode = ret,
            .auditType = AUDIT_EVENT_MSG_ERROR,
            .discMode = DISCOVER_MODE_PASSIVE,
            .broadcastFreq = option->freq,
            .localCapabilityBitmap = option->capabilityBitmap[0],
        };
        DISC_AUDIT(AUDIT_SCENE_COAP_PUBLISH, extra);
    }
    DfxRecordCoapEnd(true, false, true, (void *)option, ret);
    return ret;
}

static int32_t UnPublish(const PublishOption *option, bool isActive)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(CheckParam(option, NULL, true), SOFTBUS_INVALID_PARAM, DISC_COAP, "invalid param");
    DISC_CHECK_AND_RETURN_RET_LOGE(CheckFeature(option), SOFTBUS_INVALID_PARAM, DISC_COAP, "invalid param");
    DISC_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&(g_publishMgr->lock)) == 0, SOFTBUS_LOCK_ERR, DISC_COAP,
        "unPublish mutex lock failed. isActive=%{public}s", isActive ? "active" : "passive");

    if (UnregisterAllCapBitmap(CAPABILITY_NUM, option->capabilityBitmap, g_publishMgr, MAX_CAP_NUM) != SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&(g_publishMgr->lock));
        DISC_LOGE(DISC_COAP,
            "unRegister publish capability failed. isActive=%{public}s", isActive ? "active" : "passive");
        SoftbusReportDiscFault(SOFTBUS_HISYSEVT_DISC_MEDIUM_COAP, SOFTBUS_HISYSEVT_DISCOVER_COAP_CANCEL_CAP_FAIL);
        return SOFTBUS_DISCOVER_COAP_CANCEL_CAP_FAIL;
    }
    if (g_publishMgr->isUpdate) {
        if (DiscCoapRegisterCapability(CAPABILITY_NUM, g_publishMgr->allCap) != SOFTBUS_OK) {
            (void)SoftBusMutexUnlock(&(g_publishMgr->lock));
            DISC_LOGE(DISC_COAP, "register all capability to dfinder failed.");
            SoftbusReportDiscFault(SOFTBUS_HISYSEVT_DISC_MEDIUM_COAP,
                SOFTBUS_HISYSEVT_DISCOVER_COAP_REGISTER_CAP_FAIL);
            return SOFTBUS_DISCOVER_COAP_REGISTER_CAP_FAIL;
        }
    }
    uint32_t curCap = option->capabilityBitmap[0];
    if (DiscCoapRegisterServiceData(option, g_publishMgr->allCap[0]) != SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&(g_publishMgr->lock));
        DfxRecordRegisterEnd(curCap, SOFTBUS_DISCOVER_COAP_REGISTER_CAP_FAIL);
        DISC_LOGE(DISC_COAP, "register service data to dfinder failed.");
        return SOFTBUS_DISCOVER_COAP_REGISTER_CAP_FAIL;
    }
    if (isActive && g_publishMgr->isEmpty) {
        if (DiscCoapStopDiscovery() != SOFTBUS_OK) {
            (void)SoftBusMutexUnlock(&(g_publishMgr->lock));
            DISC_LOGE(DISC_COAP, "coap unpublish failed, allCap=%{public}u", g_publishMgr->allCap[0]);
            SoftbusReportDiscFault(SOFTBUS_HISYSEVT_DISC_MEDIUM_COAP,
                SOFTBUS_HISYSEVT_DISCOVER_COAP_STOP_DISCOVER_FAIL);
            return SOFTBUS_DISCOVER_COAP_STOP_PUBLISH_FAIL;
        }
    }
    (void)SoftBusMutexUnlock(&(g_publishMgr->lock));
    DISC_LOGI(DISC_COAP, "coap unPublish succ, isActive=%{public}s, allCap=%{public}u", isActive ?
        "active" : "passive", g_publishMgr->allCap[0]);
    return SOFTBUS_OK;
}

static int32_t CoapUnPublish(const PublishOption *option)
{
    int32_t ret = UnPublish(option, true);
    DfxRecordCoapEnd(false, true, true, (void *)option, ret);
    return ret;
}

static int32_t CoapStopScan(const PublishOption *option)
{
    int32_t ret = UnPublish(option, false);
    DfxRecordCoapEnd(false, false, true, (void *)option, ret);
    return ret;
}

static bool UpdateFilter(void)
{
    if (!g_subscribeMgr->isUpdate) {
        return true;
    }
    int32_t ret = DiscCoapSetFilterCapability(CAPABILITY_NUM, g_subscribeMgr->allCap);
    if (ret != SOFTBUS_OK) {
        DfxRecordSetFilterEnd(g_subscribeMgr->allCap[0], ret);
        DISC_LOGE(DISC_COAP, "set all filter capability to dfinder failed.");
        SoftbusReportDiscFault(SOFTBUS_HISYSEVT_DISC_MEDIUM_COAP, SOFTBUS_HISYSEVT_DISCOVER_COAP_SET_FILTER_CAP_FAIL);
        return false;
    }
    DfxRecordSetFilterEnd(g_subscribeMgr->allCap[0], SOFTBUS_OK);
    return true;
}

static int32_t Discovery(const SubscribeOption *option, bool isActive)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(CheckParam(NULL, option, false), SOFTBUS_INVALID_PARAM, DISC_COAP, "invalid param");
    DISC_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&(g_subscribeMgr->lock)) == 0, SOFTBUS_LOCK_ERR, DISC_COAP,
        "discovery mutex lock failed. isActive=%{public}s", isActive ? "active" : "passive");

    if (RegisterAllCapBitmap(CAPABILITY_NUM, option->capabilityBitmap, g_subscribeMgr, MAX_CAP_NUM) != SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&(g_subscribeMgr->lock));
        DISC_LOGE(DISC_COAP, "merge discovery capability failed. isActive=%{public}s", isActive ? "active" : "passive");
        SoftbusReportDiscFault(SOFTBUS_HISYSEVT_DISC_MEDIUM_COAP, SOFTBUS_HISYSEVT_DISCOVER_COAP_MERGE_CAP_FAIL);
        return SOFTBUS_DISCOVER_COAP_MERGE_CAP_FAIL;
    }
    if (!UpdateFilter()) {
        (void)SoftBusMutexUnlock(&(g_subscribeMgr->lock));
        return SOFTBUS_DISCOVER_COAP_SET_FILTER_CAP_FAIL;
    }
    if (!isActive) {
        (void)SoftBusMutexUnlock(&(g_subscribeMgr->lock));
        DISC_LOGI(DISC_COAP, "coap start passive discovery succ, filters=%{public}u", g_subscribeMgr->allCap[0]);
        return SOFTBUS_OK;
    }
    if (DiscCoapStopDiscovery() != SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&(g_subscribeMgr->lock));
        DISC_LOGE(DISC_COAP, "coap stop discovery failed, filters=%{public}u", g_subscribeMgr->allCap[0]);
        SoftbusReportDiscFault(SOFTBUS_HISYSEVT_DISC_MEDIUM_COAP, SOFTBUS_HISYSEVT_DISCOVER_COAP_STOP_DISCOVER_FAIL);
        return SOFTBUS_DISCOVER_COAP_STOP_DISCOVER_FAIL;
    }
    DiscCoapOption discCoapOption;
    DiscOption discOption = {
        .isPublish = false,
        .option.subscribeOption = *option,
    };
    SetDiscCoapOption(&discCoapOption, &discOption, g_subscribeMgr->allCap[0]);
    if (DiscCoapStartDiscovery(&discCoapOption) != SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&(g_subscribeMgr->lock));
        DISC_LOGE(DISC_COAP, "coap start discovery failed, filters=%{public}u", g_subscribeMgr->allCap[0]);
        SoftbusReportDiscFault(SOFTBUS_HISYSEVT_DISC_MEDIUM_COAP, SOFTBUS_HISYSEVT_DISCOVER_COAP_START_DISCOVER_FAIL);
        return SOFTBUS_DISCOVER_COAP_START_DISCOVER_FAIL;
    }
    (void)SoftBusMutexUnlock(&(g_subscribeMgr->lock));
    DISC_LOGI(DISC_COAP, "coap start active discovery succ, filters=%{public}u", g_subscribeMgr->allCap[0]);
    return SOFTBUS_OK;
}

static int32_t CoapStartAdvertise(const SubscribeOption *option)
{
    int32_t ret = Discovery(option, true);
    if (ret != SOFTBUS_OK && option != NULL) {
        DiscAuditExtra extra = {
            .result = DISC_AUDIT_DISCONTINUE,
            .errcode = ret,
            .auditType = AUDIT_EVENT_MSG_ERROR,
            .discMode = DISCOVER_MODE_ACTIVE,
            .broadcastFreq = option->freq,
            .localCapabilityBitmap = option->capabilityBitmap[0],
        };
        DISC_AUDIT(AUDIT_SCENE_COAP_DISCOVERY, extra);
    }
    DfxRecordCoapEnd(true, true, false, (void *)option, ret);
    return ret;
}

static int32_t CoapSubscribe(const SubscribeOption *option)
{
    int32_t ret = Discovery(option, false);
    DfxRecordCoapEnd(true, false, false, (void *)option, ret);
    return ret;
}

static int32_t StopDisc(const SubscribeOption *option, bool isActive)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(CheckParam(NULL, option, false), SOFTBUS_INVALID_PARAM, DISC_COAP, "invalid param");
    DISC_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&(g_subscribeMgr->lock)) == 0, SOFTBUS_LOCK_ERR,
        DISC_COAP, "stop discovery mutex lock failed. isActive=%{public}s", isActive ? "active" : "passive");

    if (UnregisterAllCapBitmap(CAPABILITY_NUM, option->capabilityBitmap, g_subscribeMgr,  MAX_CAP_NUM) != SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&(g_subscribeMgr->lock));
        DISC_LOGE(DISC_COAP, "unRegister discovery capability failed. isActive=%{public}s",
            isActive ? "active" : "passive");
        SoftbusReportDiscFault(SOFTBUS_HISYSEVT_DISC_MEDIUM_COAP, SOFTBUS_HISYSEVT_DISCOVER_COAP_CANCEL_CAP_FAIL);
        return SOFTBUS_DISCOVER_COAP_CANCEL_CAP_FAIL;
    }
    if (!UpdateFilter()) {
        (void)SoftBusMutexUnlock(&(g_subscribeMgr->lock));
        return SOFTBUS_DISCOVER_COAP_SET_FILTER_CAP_FAIL;
    }
    if (isActive && g_subscribeMgr->isEmpty) {
        if (DiscCoapStopDiscovery() != SOFTBUS_OK) {
            (void)SoftBusMutexUnlock(&(g_subscribeMgr->lock));
            DISC_LOGE(DISC_COAP, "coap stop active discovery failed, filters=%{public}u", g_subscribeMgr->allCap[0]);
            SoftbusReportDiscFault(SOFTBUS_HISYSEVT_DISC_MEDIUM_COAP,
                SOFTBUS_HISYSEVT_DISCOVER_COAP_STOP_DISCOVER_FAIL);
            return SOFTBUS_DISCOVER_COAP_STOP_DISCOVER_FAIL;
        }
    }
    (void)SoftBusMutexUnlock(&(g_subscribeMgr->lock));
    DISC_LOGI(DISC_COAP, "coap stop discovery succ, isActive=%{public}s, filters=%{public}u",
        isActive ? "active" : "passive", g_subscribeMgr->allCap[0]);
    return SOFTBUS_OK;
}

static int32_t CoapStopAdvertise(const SubscribeOption *option)
{
    int32_t ret = StopDisc(option, true);
    DfxRecordCoapEnd(false, true, false, (void *)option, ret);
    return ret;
}

static int32_t CoapUnsubscribe(const SubscribeOption *option)
{
    int32_t ret = StopDisc(option, false);
    DfxRecordCoapEnd(false, false, false, (void *)option, ret);
    return ret;
}

static void CoapUpdateLocalIp(LinkStatus status)
{
    DiscCoapModifyNstackThread(status);
    DiscCoapUpdateLocalIp(status);
}

static void CoapUpdateLocalDeviceInfo(InfoTypeChanged type)
{
    if (type == TYPE_LOCAL_DEVICE_NAME) {
        DiscCoapUpdateDevName();
    } else if (type == TYPE_ACCOUNT) {
        DiscCoapUpdateAccount();
    } else {
        DISC_LOGW(DISC_COAP, "invalid info change type. type=%{public}d", type);
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
    DISC_CHECK_AND_RETURN_LOGE(coapInfo != NULL, DISC_COAP, "coapInfo=NULL");
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

static void DfxRecordCoapInitEnd(int32_t reason)
{
    DiscEventExtra extra = { 0 };
    DiscEventExtraInit(&extra);
    extra.initType = COAP + 1;
    extra.errcode = reason;
    extra.result = (reason == SOFTBUS_OK) ? EVENT_STAGE_RESULT_OK : EVENT_STAGE_RESULT_FAILED;
    DISC_EVENT(EVENT_SCENE_INIT, EVENT_STAGE_INIT, extra);
}

DiscoveryFuncInterface *DiscCoapInit(DiscInnerCallback *discInnerCb)
{
    int32_t ret = InitCoapManager();
    if (ret != SOFTBUS_OK) {
        DfxRecordCoapInitEnd(ret);
        DISC_LOGE(DISC_INIT, "coap manager init failed.");
        return NULL;
    }
    ret = DiscNstackxInit();
    if (ret != SOFTBUS_OK) {
        DfxRecordCoapInitEnd(ret);
        DISC_LOGE(DISC_INIT, "dfinder init failed.");
        DeinitCoapManager();
        return NULL;
    }
    ret = DiscCoapRegisterCb(discInnerCb);
    if (ret != SOFTBUS_OK) {
        DfxRecordCoapInitEnd(ret);
        DISC_LOGE(DISC_INIT, "register coap callback to dfinder failed.");
        DiscCoapDeinit();
        return NULL;
    }
    SoftBusRegDiscVarDump(COAP_PUBLISH_INFO, &CoapPubInfoDump);
    SoftBusRegDiscVarDump(COAP_SUBSCRIBE_INFO, &CoapSubInfoDump);
    DfxRecordCoapInitEnd(SOFTBUS_OK);
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
