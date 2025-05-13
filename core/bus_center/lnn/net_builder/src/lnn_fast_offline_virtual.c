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

#include "lnn_fast_offline.h"

#include "lnn_log.h"
#include "softbus_error_code.h"

int32_t LnnInitFastOffline(void)
{
    LNN_LOGI(LNN_INIT, "init virtual lnn fast offline");
    return SOFTBUS_OK;
}

void LnnDeinitFastOffline(void)
{
    LNN_LOGI(LNN_INIT, "Deinit virtual lnn fast offline");
}

int32_t LnnSendNotTrustedInfo(const NotTrustedDelayInfo *info, uint32_t num, LnnSyncInfoMsgComplete complete)
{
    (void)info;
    (void)num;
    return SOFTBUS_OK;
}

int32_t LnnBleFastOfflineOnceBegin(void)
{
    LNN_LOGI(LNN_BUILDER, "LnnBleFastOfflineOnceBegin virtual ok");
    return SOFTBUS_OK;
}

void LnnIpAddrChangeEventHandler(void)
{
    LNN_LOGI(LNN_BUILDER, "LnnIpAddrChangeEventHandler virtual ok");
}

void EhLoginEventHandler(void)
{
    LNN_LOGI(LNN_BUILDER, "EH handle SOFTBUS_ACCOUNT_LOG_IN");
}

int32_t LnnSyncTrustedRelationShip(const char *pkgName, const char *msg, uint32_t msgLen)
{
    (void)pkgName;
    (void)msg;
    (void)msgLen;
    LNN_LOGI(LNN_BUILDER, "not implement");
    return SOFTBUS_OK;
}

int32_t LnnSyncBleOfflineMsg(void)
{
    return SOFTBUS_OK;
}