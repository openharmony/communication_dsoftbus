/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef LNN_HISYSEVENT_MATCHER_H
#define LNN_HISYSEVENT_MATCHER_H

#include <gmock/gmock.h>

#include "convert/lnn_audit_converter.h"
#include "convert/lnn_event_converter.h"
#include "hisysevent_c.h"
#include "softbus_event.h"

static void MatchLnnEventNameTypeExtraInt32Param(const HiSysEventParam *params, int32_t index, int32_t extraParam)
{
    EXPECT_STREQ(params[index].name, g_lnnAssigners[index].name);
    EXPECT_EQ(params[index].t, g_lnnAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extraParam);
}

static void MatchLnnEventNameTypeExtraUint32Param(const HiSysEventParam *params, int32_t index, int32_t extraParam)
{
    EXPECT_STREQ(params[index].name, g_lnnAssigners[index].name);
    EXPECT_EQ(params[index].t, g_lnnAssigners[index].type);
    EXPECT_EQ(params[index].v.ui32, extraParam);
}

static void MatchLnnEventNameTypeExtraStrParam(const HiSysEventParam *params, int32_t index, const char *extraParam)
{
    EXPECT_STREQ(params[index].name, g_lnnAssigners[index].name);
    EXPECT_EQ(params[index].t, g_lnnAssigners[index].type);
    EXPECT_STREQ(params[index].v.s, extraParam);
}

static void MatchLnnEventNameTypeExtraStrParamAnony(const HiSysEventParam *params, int32_t index,
    const char *extraParam)
{
    char *anonyStr = NULL;
    EXPECT_STREQ(params[index].name, g_lnnAssigners[index].name);
    EXPECT_EQ(params[index].t, g_lnnAssigners[index].type);

    Anonymize(extraParam, &anonyStr);
    EXPECT_STREQ(params[index].v.s, AnonymizeWrapper(anonyStr));
    AnonymizeFree(anonyStr);
}

static void MatchLnnEventNameTypeExtraUint64Param(const HiSysEventParam *params, int32_t index, uint64_t extraParam)
{
    EXPECT_STREQ(params[index].name, g_lnnAssigners[index].name);
    EXPECT_EQ(params[index].t, g_lnnAssigners[index].type);
    EXPECT_EQ(params[index].v.ui64, extraParam);
}

static void MatchLnnEventNameTypeExtraInt64Param(const HiSysEventParam *params, int32_t index, int64_t extraParam)
{
    EXPECT_STREQ(params[index].name, g_lnnAssigners[index].name);
    EXPECT_EQ(params[index].t, g_lnnAssigners[index].type);
    EXPECT_EQ(params[index].v.i64, extraParam);
}

MATCHER_P2(LnnValidParamArrayMatcher, inExtra, validSize, "lnn valid param array match fail")
{
    const auto *params = static_cast<const HiSysEventParam *>(arg);
    params += SOFTBUS_ASSIGNER_SIZE; // Skip softbus params, they are matched by SoftbusParamArrayMatcher
    auto extra = static_cast<LnnEventExtra>(inExtra);
    int32_t index = 0;
    MatchLnnEventNameTypeExtraInt32Param(params, index, extra.result);
    MatchLnnEventNameTypeExtraInt32Param(params, ++index, extra.errcode);
    MatchLnnEventNameTypeExtraInt32Param(params, ++index, extra.authId);
    MatchLnnEventNameTypeExtraInt32Param(params, ++index, extra.discServerType);
    MatchLnnEventNameTypeExtraInt32Param(params, ++index, extra.gearCycle);
    MatchLnnEventNameTypeExtraInt32Param(params, ++index, extra.gearDuration);
    MatchLnnEventNameTypeExtraInt32Param(params, ++index, extra.connectionId);
    MatchLnnEventNameTypeExtraInt32Param(params, ++index, extra.authLinkType);
    MatchLnnEventNameTypeExtraInt32Param(params, ++index, extra.authRequestId);
    MatchLnnEventNameTypeExtraInt32Param(params, ++index, extra.authCostTime);
    MatchLnnEventNameTypeExtraInt32Param(params, ++index, extra.lnnType);
    MatchLnnEventNameTypeExtraInt32Param(params, ++index, extra.onlineNum);
    MatchLnnEventNameTypeExtraInt32Param(params, ++index, extra.peerDeviceAbility);
    MatchLnnEventNameTypeExtraInt32Param(params, ++index, extra.onlineType);
    MatchLnnEventNameTypeExtraInt32Param(params, ++index, extra.osType);
    MatchLnnEventNameTypeExtraUint32Param(params, ++index, extra.connOnlineReason);
    MatchLnnEventNameTypeExtraInt32Param(params, ++index, extra.laneId);
    MatchLnnEventNameTypeExtraInt32Param(params, ++index, extra.chanReqId);
    MatchLnnEventNameTypeExtraInt32Param(params, ++index, extra.connReqId);
    MatchLnnEventNameTypeExtraInt32Param(params, ++index, extra.strategy);
    MatchLnnEventNameTypeExtraUint64Param(params, ++index, extra.timeLatency);
    MatchLnnEventNameTypeExtraInt32Param(params, ++index, extra.triggerReason);
    MatchLnnEventNameTypeExtraInt64Param(params, ++index, extra.authSeq);
    MatchLnnEventNameTypeExtraInt32Param(params, ++index, extra.onlineDevCnt);
    MatchLnnEventNameTypeExtraInt32Param(params, ++index, extra.interval);
    MatchLnnEventNameTypeExtraInt32Param(params, ++index, extra.laneLinkType);
    MatchLnnEventNameTypeExtraInt32Param(params, ++index, extra.hmlChannelId);
    MatchLnnEventNameTypeExtraInt32Param(params, ++index, extra.p2pChannelId);
    MatchLnnEventNameTypeExtraInt32Param(params, ++index, extra.staChannelId);
    MatchLnnEventNameTypeExtraInt32Param(params, ++index, extra.apChannelId);
    MatchLnnEventNameTypeExtraInt32Param(params, ++index, extra.laneReqId);
    MatchLnnEventNameTypeExtraInt32Param(params, ++index, extra.minBW);
    MatchLnnEventNameTypeExtraInt32Param(params, ++index, extra.maxLaneLatency);
    MatchLnnEventNameTypeExtraInt32Param(params, ++index, extra.minLaneLatency);
    MatchLnnEventNameTypeExtraInt32Param(params, ++index, extra.isWifiDirectReuse);
    MatchLnnEventNameTypeExtraInt32Param(params, ++index, extra.bandWidth);
    MatchLnnEventNameTypeExtraInt32Param(params, ++index, extra.guideType);
    MatchLnnEventNameTypeExtraStrParam(params, ++index, extra.peerDeviceInfo);
    MatchLnnEventNameTypeExtraStrParamAnony(params, ++index, extra.peerIp);
    MatchLnnEventNameTypeExtraStrParamAnony(params, ++index, extra.peerBrMac);
    MatchLnnEventNameTypeExtraStrParamAnony(params, ++index, extra.peerBleMac);
    MatchLnnEventNameTypeExtraStrParamAnony(params, ++index, extra.peerWifiMac);
    MatchLnnEventNameTypeExtraStrParam(params, ++index, extra.peerPort);
    MatchLnnEventNameTypeExtraStrParamAnony(params, ++index, extra.peerUdid);
    MatchLnnEventNameTypeExtraStrParamAnony(params, ++index, extra.peerNetworkId);
    MatchLnnEventNameTypeExtraStrParam(params, ++index, extra.localDeviceType);
    MatchLnnEventNameTypeExtraStrParam(params, ++index, extra.peerDeviceType);
    MatchLnnEventNameTypeExtraStrParamAnony(params, ++index, extra.localUdidHash);
    MatchLnnEventNameTypeExtraStrParamAnony(params, ++index, extra.peerUdidHash);
    MatchLnnEventNameTypeExtraStrParam(params, ++index, extra.callerPkg);
    MatchLnnEventNameTypeExtraStrParam(params, ++index, extra.calleePkg);

    EXPECT_EQ(++index, validSize);
    return true;
}

MATCHER_P2(LnnInvalidParamArrayMatcher, inExtra, validSize, "lnn invalid param array match fail")
{
    const auto *params = static_cast<const HiSysEventParam *>(arg);
    params += SOFTBUS_ASSIGNER_SIZE; // Skip softbus params, they are matched by SoftbusParamArrayMatcher
    auto extra = static_cast<LnnEventExtra>(inExtra);
    int32_t index = 0;
    MatchLnnEventNameTypeExtraInt32Param(params, index, ((extra.result < 0) ? (-extra.result) : extra.result));
    MatchLnnEventNameTypeExtraInt32Param(params, ++index, ((extra.errcode < 0) ? (-extra.errcode) : extra.errcode));
    MatchLnnEventNameTypeExtraInt32Param(params, ++index, ((extra.authId < 0) ? (-extra.authId) : extra.authId));

    EXPECT_EQ(++index, validSize);
    return true;
}

static void MatchLnnAuditNameTypeInt32Param(const HiSysEventParam *params, int32_t index, int32_t extraParam)
{
    EXPECT_STREQ(params[index].name, g_lnnAuditAssigners[index].name);
    EXPECT_EQ(params[index].t, g_lnnAuditAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extraParam);
}

static void MatchLnnAuditNameTypeUint32Param(const HiSysEventParam *params, int32_t index, uint32_t extraParam)
{
    EXPECT_STREQ(params[index].name, g_lnnAuditAssigners[index].name);
    EXPECT_EQ(params[index].t, g_lnnAuditAssigners[index].type);
    EXPECT_EQ(params[index].v.ui32, extraParam);
}

static void MatchLnnAuditNameTypeUint64Param(const HiSysEventParam *params, int32_t index, uint64_t extraParam)
{
    EXPECT_STREQ(params[index].name, g_lnnAuditAssigners[index].name);
    EXPECT_EQ(params[index].t, g_lnnAuditAssigners[index].type);
    EXPECT_EQ(params[index].v.ui64, extraParam);
}

static void MatchLnnAuditNameTypeStrParam(const HiSysEventParam *params, int32_t index, const char *extraParam)
{
    EXPECT_STREQ(params[index].name, g_lnnAuditAssigners[index].name);
    EXPECT_EQ(params[index].t, g_lnnAuditAssigners[index].type);
    EXPECT_STREQ(params[index].v.s, extraParam);
}

MATCHER_P2(LnnAuditValidParamArrayMatcher, inExtra, validSize, "lnn audit valid param array match fail")
{
    const auto *params = static_cast<const HiSysEventParam *>(arg);
    params += SOFTBUS_ASSIGNER_SIZE - 1; // Skip softbus params, they are matched by SoftbusParamArrayMatcher
    auto extra = static_cast<LnnAuditExtra>(inExtra);
    int32_t index = 0;
    MatchLnnAuditNameTypeInt32Param(params, index, extra.result);
    MatchLnnAuditNameTypeInt32Param(params, ++index, extra.errCode);
    MatchLnnAuditNameTypeInt32Param(params, ++index, extra.auditType);
    MatchLnnAuditNameTypeUint64Param(params, ++index, extra.connId);
    MatchLnnAuditNameTypeInt32Param(params, ++index, extra.authLinkType);
    MatchLnnAuditNameTypeUint32Param(params, ++index, extra.authRequestId);
    MatchLnnAuditNameTypeInt32Param(params, ++index, extra.onlineNum);
    MatchLnnAuditNameTypeStrParam(params, ++index, extra.hostPkg);
    MatchLnnAuditNameTypeStrParam(params, ++index, extra.localIp);
    MatchLnnAuditNameTypeStrParam(params, ++index, extra.localBrMac);
    MatchLnnAuditNameTypeStrParam(params, ++index, extra.localBleMac);
    MatchLnnAuditNameTypeStrParam(params, ++index, extra.localUdid);
    MatchLnnAuditNameTypeStrParam(params, ++index, extra.localNetworkId);
    MatchLnnAuditNameTypeStrParam(params, ++index, extra.localDevName);
    MatchLnnAuditNameTypeStrParam(params, ++index, extra.peerIp);
    MatchLnnAuditNameTypeStrParam(params, ++index, extra.peerBrMac);
    MatchLnnAuditNameTypeStrParam(params, ++index, extra.peerBleMac);
    MatchLnnAuditNameTypeStrParam(params, ++index, extra.peerUdid);
    MatchLnnAuditNameTypeStrParam(params, ++index, extra.peerNetworkId);
    MatchLnnAuditNameTypeStrParam(params, ++index, extra.peerDevName);
    MatchLnnAuditNameTypeInt32Param(params, ++index, extra.localAuthPort);
    MatchLnnAuditNameTypeInt32Param(params, ++index, extra.localProxyPort);
    MatchLnnAuditNameTypeInt32Param(params, ++index, extra.localSessionPort);
    MatchLnnAuditNameTypeInt32Param(params, ++index, extra.localDevType);
    MatchLnnAuditNameTypeInt32Param(params, ++index, extra.peerAuthPort);
    MatchLnnAuditNameTypeInt32Param(params, ++index, extra.peerProxyPort);
    MatchLnnAuditNameTypeInt32Param(params, ++index, extra.peerSessionPort);
    MatchLnnAuditNameTypeInt32Param(params, ++index, extra.peerDevType);
    MatchLnnAuditNameTypeInt32Param(params, ++index, extra.attackTimes);
    MatchLnnAuditNameTypeInt32Param(params, ++index, extra.beAttackedPort);

    EXPECT_EQ(++index, validSize);
    return true;
}

MATCHER_P2(LnnAuditInvalidParamArrayMatcher, inExtra, validSize, "lnn audit invalid param array match fail")
{
    const auto *params = static_cast<const HiSysEventParam *>(arg);
    params += SOFTBUS_ASSIGNER_SIZE; // Skip softbus params, they are matched by SoftbusParamArrayMatcher
    auto extra = static_cast<LnnAuditExtra>(inExtra);
    int32_t index = 0;
    MatchLnnAuditNameTypeInt32Param(params, index, ((extra.result < 0) ? (-extra.result) : extra.result));
    MatchLnnAuditNameTypeInt32Param(params, ++index, ((extra.errCode < 0) ? (-extra.errCode) : extra.errCode));
    EXPECT_EQ(++index, validSize);
    return true;
}
#endif // LNN_HISYSEVENT_MATCHER_H
