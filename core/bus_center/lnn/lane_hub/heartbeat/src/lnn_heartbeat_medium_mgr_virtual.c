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

#include "lnn_heartbeat_medium_mgr.h"
#include "lnn_log.h"
#include "softbus_error_code.h"

int32_t LnnHbMediumMgrSetParam(void *param)
{
    (void)param;

    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnHbMediumMgrSendBegin(LnnHeartbeatSendBeginData *custData)
{
    (void)custData;

    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnHbMediumMgrSendEnd(LnnHeartbeatSendEndData *custData)
{
    (void)custData;

    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnHbMediumMgrStop(LnnHeartbeatType *type)
{
    (void)type;

    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnHbMediumMgrUpdateSendInfo(LnnHeartbeatUpdateInfoType type)
{
    (void)type;

    return SOFTBUS_NOT_IMPLEMENT;
}

void LnnHbClearRecvList(void)
{
}

int32_t LnnCleanTriggerSparkInfo(const char *udid, ConnectionAddrType addrType)
{
    (void)udid;
    (void)addrType;

    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnHbMediumMgrInit(void)
{
    return SOFTBUS_OK;
}

void LnnHbMediumMgrDeinit(void)
{
}

int32_t LnnRegistHeartbeatMediumMgr(LnnHeartbeatMediumMgr *mgr)
{
    (void)mgr;

    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnUnRegistHeartbeatMediumMgr(LnnHeartbeatMediumMgr *mgr)
{
    (void)mgr;

    return SOFTBUS_NOT_IMPLEMENT;
}

void LnnDumpHbMgrRecvList(void)
{
}

void LnnDumpHbOnlineNodeList(void)
{
}
