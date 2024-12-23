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

#include "lnn_net_builder.h"

#include "lnn_log.h"
#include "lnn_p2p_info.h"
#include "softbus_error_code.h"

int32_t LnnInitNetBuilder(void)
{
    LNN_LOGI(LNN_INIT, "init virtual net builder");
    return SOFTBUS_OK;
}

int32_t LnnInitNetBuilderDelay(void)
{
    return SOFTBUS_OK;
}

void LnnDeinitNetBuilder(void)
{
}

int32_t LnnServerJoin(ConnectionAddr *addr, const char *pkgName)
{
    (void)addr;
    (void)pkgName;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnServerLeave(const char *networkId, const char *pkgName)
{
    (void)networkId;
    (void)pkgName;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnNotifyDiscoveryDevice(
    const ConnectionAddr *addr, const LnnDfxDeviceInfoReport *infoReport, bool isNeedConnec)
{
    (void)addr;
    (void)infoReport;
    (void)isNeedConnec;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnRequestLeaveByAddrType(const bool *type, uint32_t typeLen)
{
    (void)type;
    (void)typeLen;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnInitLocalP2pInfo(NodeInfo *info)
{
    (void)info;
    return SOFTBUS_OK;
}

void ClearLnnBleReportExtraMap(void)
{
    return;
}

void ClearPcRestrictMap(void)
{
    return;
}

int32_t LnnRequestLeaveSpecific(const char *networkId, ConnectionAddrType addrType)
{
    (void)networkId;
    (void)addrType;
    return SOFTBUS_NOT_IMPLEMENT;
}
