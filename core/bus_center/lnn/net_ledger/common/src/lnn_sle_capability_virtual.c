/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "lnn_sle_capability.h"

#include "lnn_log.h"
#include "softbus_error_code.h"

int32_t SetSleRangeCapToLocalLedger(void)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t SetSleAddrToLocalLedger(void)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LocalLedgerInitSleCapacity(NodeInfo *nodeInfo)
{
    (void)nodeInfo;
    return SOFTBUS_OK;
}

void LocalLedgerDeinitSleCapacity(void)
{
}

void OnReceiveSleMacChangedMsg(LnnSyncInfoType type, const char *networkId, const uint8_t *msg, uint32_t size)
{
    (void)type;
    (void)networkId;
    (void)msg;
    (void)size;
}

void LnnSendSleInfoForAllNode(void)
{
}

int32_t LnnInitSleInfo(void)
{
    return SOFTBUS_OK;
}

void LnnDeinitSleInfo(void)
{
}
