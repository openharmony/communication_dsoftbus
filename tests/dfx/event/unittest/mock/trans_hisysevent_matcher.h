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

#ifndef TRANS_HISYSEVENT_MATCHER_H
#define TRANS_HISYSEVENT_MATCHER_H

#include <gmock/gmock.h>

#include "convert/trans_audit_converter.h"
#include "convert/trans_event_converter.h"
#include "hisysevent_c.h"
#include "softbus_event.h"

static void MatchTransEventNameTypeExtraUint8Param(const HiSysEventParam *params, int32_t index, uint8_t extraParam)
{
    EXPECT_STREQ(params[index].name, TRANS_ASSIGNERS[index].name);
    EXPECT_EQ(params[index].t, TRANS_ASSIGNERS[index].type);
    EXPECT_EQ(params[index].v.ui8, extraParam);
}

static void MatchTransEventNameTypeExtraUint16Param(const HiSysEventParam *params, int32_t index, uint16_t extraParam)
{
    EXPECT_STREQ(params[index].name, TRANS_ASSIGNERS[index].name);
    EXPECT_EQ(params[index].t, TRANS_ASSIGNERS[index].type);
    EXPECT_EQ(params[index].v.ui16, extraParam);
}

static void MatchTransEventNameTypeExtraInt32Param(const HiSysEventParam *params, int32_t index, int32_t extraParam)
{
    EXPECT_STREQ(params[index].name, TRANS_ASSIGNERS[index].name);
    EXPECT_EQ(params[index].t, TRANS_ASSIGNERS[index].type);
    EXPECT_EQ(params[index].v.i32, extraParam);
}

static void MatchTransEventNameTypeExtraInt64Param(const HiSysEventParam *params, int32_t index, int64_t extraParam)
{
    EXPECT_STREQ(params[index].name, TRANS_ASSIGNERS[index].name);
    EXPECT_EQ(params[index].t, TRANS_ASSIGNERS[index].type);
    EXPECT_EQ(params[index].v.i64, extraParam);
}

static void MatchTransEventNameTypeExtraStrParam(const HiSysEventParam *params, int32_t index,
    const char * extraParam)
{
    EXPECT_STREQ(params[index].name, TRANS_ASSIGNERS[index].name);
    EXPECT_EQ(params[index].t, TRANS_ASSIGNERS[index].type);
    EXPECT_STREQ(params[index].v.s, extraParam);
}

static void MatchTransEventNameTypeExtraStrParamAnony(const HiSysEventParam *params, int32_t index,
    const char * extraParam)
{
    char *anonyStr = NULL;
    EXPECT_STREQ(params[index].name, TRANS_ASSIGNERS[index].name);
    EXPECT_EQ(params[index].t, TRANS_ASSIGNERS[index].type);

    Anonymize(extraParam, &anonyStr);
    EXPECT_STREQ(params[index].v.s, AnonymizeWrapper(anonyStr));
    AnonymizeFree(anonyStr);
}

MATCHER_P2(TransValidParamArrayMatcher, inExtra, validSize, "trans valid param array match fail")
{
    const auto *params = static_cast<const HiSysEventParam *>(arg);
    params += SOFTBUS_ASSIGNER_SIZE; // Skip softbus params, they are matched by SoftbusParamArrayMatcher
    auto extra = static_cast<TransEventExtra>(inExtra);
    int32_t index = 0;
    MatchTransEventNameTypeExtraUint8Param(params, index, extra.talkieFreq);
    MatchTransEventNameTypeExtraUint8Param(params, ++index, extra.talkieType);
    MatchTransEventNameTypeExtraUint8Param(params, ++index, extra.talkieLevel);
    MatchTransEventNameTypeExtraInt32Param(params, ++index, extra.result);
    MatchTransEventNameTypeExtraInt32Param(params, ++index, extra.errcode);
    MatchTransEventNameTypeExtraStrParamAnony(params, ++index, extra.socketName);
    MatchTransEventNameTypeExtraInt32Param(params, ++index, extra.dataType);
    MatchTransEventNameTypeExtraInt32Param(params, ++index, extra.channelType);
    MatchTransEventNameTypeExtraInt32Param(params, ++index, extra.laneId);
    MatchTransEventNameTypeExtraInt32Param(params, ++index, extra.preferLinkType);
    MatchTransEventNameTypeExtraInt32Param(params, ++index, extra.laneTransType);
    MatchTransEventNameTypeExtraInt32Param(params, ++index, extra.channelId);
    MatchTransEventNameTypeExtraInt32Param(params, ++index, extra.requestId);
    MatchTransEventNameTypeExtraInt32Param(params, ++index, extra.connectionId);
    MatchTransEventNameTypeExtraInt32Param(params, ++index, extra.linkType);
    MatchTransEventNameTypeExtraInt32Param(params, ++index, extra.authId);
    MatchTransEventNameTypeExtraInt32Param(params, ++index, extra.socketFd);
    MatchTransEventNameTypeExtraInt32Param(params, ++index, extra.costTime);
    MatchTransEventNameTypeExtraInt32Param(params, ++index, extra.channelScore);
    MatchTransEventNameTypeExtraInt32Param(params, ++index, extra.peerChannelId);
    MatchTransEventNameTypeExtraInt32Param(params, ++index, extra.btFlow);
    MatchTransEventNameTypeExtraInt32Param(params, ++index, extra.pagingId);
    MatchTransEventNameTypeExtraInt32Param(params, ++index, extra.callPid);
    MatchTransEventNameTypeExtraInt32Param(params, ++index, extra.saId);
    MatchTransEventNameTypeExtraInt32Param(params, ++index, extra.businessFlag);
    MatchTransEventNameTypeExtraStrParam(params, ++index, extra.groupId);
    MatchTransEventNameTypeExtraStrParam(params, ++index, extra.subGroupId);
    MatchTransEventNameTypeExtraStrParamAnony(params, ++index, extra.peerNetworkId);
    MatchTransEventNameTypeExtraStrParamAnony(params, ++index, extra.peerUdid);
    MatchTransEventNameTypeExtraStrParam(params, ++index, extra.peerDevVer);
    MatchTransEventNameTypeExtraStrParamAnony(params, ++index, extra.localUdid);
    MatchTransEventNameTypeExtraStrParam(params, ++index, extra.callerPkg);
    MatchTransEventNameTypeExtraStrParam(params, ++index, extra.calleePkg);
    MatchTransEventNameTypeExtraStrParam(params, ++index, extra.firstTokenName);
    MatchTransEventNameTypeExtraStrParamAnony(params, ++index, extra.callerAccountId);
    MatchTransEventNameTypeExtraStrParamAnony(params, ++index, extra.calleeAccountId);
    MatchTransEventNameTypeExtraInt64Param(params, ++index, extra.firstTokenId);
    MatchTransEventNameTypeExtraInt32Param(params, ++index, extra.firstTokenType);
    MatchTransEventNameTypeExtraStrParam(params, ++index, extra.trafficStats);
    MatchTransEventNameTypeExtraInt32Param(params, ++index, extra.osType);
    MatchTransEventNameTypeExtraInt32Param(params, ++index, extra.deviceState);
    MatchTransEventNameTypeExtraInt32Param(params, ++index, extra.businessId);
    MatchTransEventNameTypeExtraInt32Param(params, ++index, extra.businessType);
    MatchTransEventNameTypeExtraInt32Param(params, ++index, extra.sessionId);
    MatchTransEventNameTypeExtraInt32Param(params, ++index, extra.minBW);
    MatchTransEventNameTypeExtraInt32Param(params, ++index, extra.maxLatency);
    MatchTransEventNameTypeExtraInt32Param(params, ++index, extra.minLatency);
    MatchTransEventNameTypeExtraUint16Param(params, ++index, extra.localStaChload);
    MatchTransEventNameTypeExtraUint16Param(params, ++index, extra.remoteStaChload);
    MatchTransEventNameTypeExtraUint16Param(params, ++index, extra.localHmlChload);
    MatchTransEventNameTypeExtraUint16Param(params, ++index, extra.remoteHmlChload);
    MatchTransEventNameTypeExtraUint16Param(params, ++index, extra.localP2pChload);
    MatchTransEventNameTypeExtraUint16Param(params, ++index, extra.remoteP2pChload);
    MatchTransEventNameTypeExtraUint8Param(params, ++index, extra.localStaChannel);
    MatchTransEventNameTypeExtraUint8Param(params, ++index, extra.remoteStaChannel);
    MatchTransEventNameTypeExtraUint8Param(params, ++index, extra.hmlChannel);
    MatchTransEventNameTypeExtraUint8Param(params, ++index, extra.localP2pChannel);
    MatchTransEventNameTypeExtraUint8Param(params, ++index, extra.remoteP2pChannel);
    MatchTransEventNameTypeExtraInt32Param(params, ++index, extra.localIsDbac);
    MatchTransEventNameTypeExtraInt32Param(params, ++index, extra.remoteIsDbac);
    MatchTransEventNameTypeExtraInt32Param(params, ++index, extra.localIsDbdc);
    MatchTransEventNameTypeExtraInt32Param(params, ++index, extra.remoteIsDbdc);
    MatchTransEventNameTypeExtraStrParam(params, ++index, extra.conCurrentId);
    MatchTransEventNameTypeExtraInt32Param(params, ++index, extra.multipathTag);
    MatchTransEventNameTypeExtraInt32Param(params, ++index, extra.fileRate);
    MatchTransEventNameTypeExtraInt32Param(params, ++index, extra.fileWirelessRate);
    MatchTransEventNameTypeExtraInt32Param(params, ++index, extra.fileWiredRate);
    MatchTransEventNameTypeExtraInt32Param(params, ++index, extra.bytesRate);
    MatchTransEventNameTypeExtraInt32Param(params, ++index, extra.fileChannelCnt);
    MatchTransEventNameTypeExtraInt32Param(params, ++index, extra.streamChannelCnt);
    MatchTransEventNameTypeExtraInt32Param(params, ++index, extra.dataLen);
    MatchTransEventNameTypeExtraInt64Param(params, ++index, extra.sessionDuration);
    MatchTransEventNameTypeExtraUint8Param(params, ++index, extra.channelStatus);
    MatchTransEventNameTypeExtraInt32Param(params, ++index, extra.userId);
    MatchTransEventNameTypeExtraInt32Param(params, ++index, extra.appIndex);

    EXPECT_EQ(++index, validSize);
    return true;
}

MATCHER_P2(TransInvalidParamArrayMatcher, inExtra, validSize, "trans invalid param array match fail")
{
    const auto *params = static_cast<const HiSysEventParam *>(arg);
    params += SOFTBUS_ASSIGNER_SIZE; // Skip softbus params, they are matched by SoftbusParamArrayMatcher
    auto extra = static_cast<TransEventExtra>(inExtra);
    int32_t index = 3;
    MatchTransEventNameTypeExtraInt32Param(params, index, ((extra.result < 0) ? (-extra.result) : extra.result));
    MatchTransEventNameTypeExtraInt32Param(params, ++index, ((extra.errcode < 0) ? (-extra.errcode) : extra.errcode));
    int32_t num = 36;
    EXPECT_STREQ(params[++index].name, TRANS_ASSIGNERS[num].name);
    EXPECT_EQ(params[index].t, TRANS_ASSIGNERS[num].type);
    EXPECT_EQ(params[index].v.i64, extra.firstTokenId);
    num = 47;
    EXPECT_STREQ(params[++index].name, TRANS_ASSIGNERS[num].name);
    EXPECT_EQ(params[index].t, TRANS_ASSIGNERS[num].type);
    EXPECT_EQ(params[index].v.i64, extra.localStaChload);
    EXPECT_STREQ(params[++index].name, TRANS_ASSIGNERS[++num].name);
    EXPECT_EQ(params[index].t, TRANS_ASSIGNERS[num].type);
    EXPECT_EQ(params[index].v.i64, extra.remoteStaChload);
    EXPECT_STREQ(params[++index].name, TRANS_ASSIGNERS[++num].name);
    EXPECT_EQ(params[index].t, TRANS_ASSIGNERS[num].type);
    EXPECT_EQ(params[index].v.i64, extra.localHmlChload);
    EXPECT_STREQ(params[++index].name, TRANS_ASSIGNERS[++num].name);
    EXPECT_EQ(params[index].t, TRANS_ASSIGNERS[num].type);
    EXPECT_EQ(params[index].v.i64, extra.remoteHmlChload);
    EXPECT_STREQ(params[++index].name, TRANS_ASSIGNERS[++num].name);
    EXPECT_EQ(params[index].t, TRANS_ASSIGNERS[num].type);
    EXPECT_EQ(params[index].v.i64, extra.localP2pChload);
    EXPECT_STREQ(params[++index].name, TRANS_ASSIGNERS[++num].name);
    EXPECT_EQ(params[index].t, TRANS_ASSIGNERS[num].type);
    EXPECT_EQ(params[index].v.i64, extra.remoteP2pChload);
    EXPECT_STREQ(params[++index].name, TRANS_ASSIGNERS[++num].name);
    EXPECT_EQ(params[index].t, TRANS_ASSIGNERS[num].type);
    EXPECT_EQ(params[index].v.i64, extra.localStaChannel);
    EXPECT_STREQ(params[++index].name, TRANS_ASSIGNERS[++num].name);
    EXPECT_EQ(params[index].t, TRANS_ASSIGNERS[num].type);
    EXPECT_EQ(params[index].v.i64, extra.remoteStaChannel);
    EXPECT_STREQ(params[++index].name, TRANS_ASSIGNERS[++num].name);
    EXPECT_EQ(params[index].t, TRANS_ASSIGNERS[num].type);
    EXPECT_EQ(params[index].v.i64, extra.hmlChannel);
    EXPECT_STREQ(params[++index].name, TRANS_ASSIGNERS[++num].name);
    EXPECT_EQ(params[index].t, TRANS_ASSIGNERS[num].type);
    EXPECT_EQ(params[index].v.i64, extra.localP2pChannel);
    EXPECT_STREQ(params[++index].name, TRANS_ASSIGNERS[++num].name);
    EXPECT_EQ(params[index].t, TRANS_ASSIGNERS[num].type);
    EXPECT_EQ(params[index].v.i64, extra.remoteP2pChannel);
    num = 70;
    EXPECT_STREQ(params[++index].name, TRANS_ASSIGNERS[++num].name);
    EXPECT_EQ(params[index].t, TRANS_ASSIGNERS[num].type);
    EXPECT_EQ(params[index].v.i64, extra.channelStatus);
    EXPECT_STREQ(params[++index].name, TRANS_ASSIGNERS[++num].name);
    EXPECT_EQ(params[index].t, TRANS_ASSIGNERS[num].type);
    EXPECT_EQ(params[index].v.i64, extra.userId);
    EXPECT_STREQ(params[++index].name, TRANS_ASSIGNERS[++num].name);
    EXPECT_EQ(params[index].t, TRANS_ASSIGNERS[num].type);
    EXPECT_EQ(params[index].v.i64, extra.appIndex);
    EXPECT_EQ(++index, validSize);
    return true;
}

static void MatchTransAlarmNameTypeExtraInt32Param(const HiSysEventParam *params, int32_t index, int32_t extraParam)
{
    EXPECT_STREQ(params[index].name, g_transAlarmAssigners[index].name);
    EXPECT_EQ(params[index].t, g_transAlarmAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extraParam);
}

static void MatchTransAlarmNameTypeExtraStrParam(const HiSysEventParam *params, int32_t index, const char *extraParam)
{
    EXPECT_STREQ(params[index].name, g_transAlarmAssigners[index].name);
    EXPECT_EQ(params[index].t, g_transAlarmAssigners[index].type);
    EXPECT_STREQ(params[index].v.s, extraParam);
}

static void MatchTransAlarmNameTypeExtraStrParamAnony(const HiSysEventParam *params, int32_t index,
    const char *extraParam)
{
    char *anonyStr = NULL;
    EXPECT_STREQ(params[index].name, g_transAlarmAssigners[index].name);
    EXPECT_EQ(params[index].t, g_transAlarmAssigners[index].type);

    Anonymize(extraParam, &anonyStr);
    EXPECT_STREQ(params[index].v.s, AnonymizeWrapper(anonyStr));
    AnonymizeFree(anonyStr);
}

MATCHER_P2(TransAlarmValidParamArrayMatcher, inExtra, validSize, "trans alarm valid param array match fail")
{
    const auto *params = static_cast<const HiSysEventParam *>(arg);
    params += SOFTBUS_ASSIGNER_SIZE; // Skip softbus params, they are matched by SoftbusParamArrayMatcher
    auto extra = static_cast<TransAlarmExtra>(inExtra);
    int32_t index = 0;
    MatchTransAlarmNameTypeExtraInt32Param(params, index, extra.result);
    MatchTransAlarmNameTypeExtraInt32Param(params, ++index, extra.errcode);
    MatchTransAlarmNameTypeExtraInt32Param(params, ++index, extra.callerPid);
    MatchTransAlarmNameTypeExtraInt32Param(params, ++index, extra.linkType);
    MatchTransAlarmNameTypeExtraInt32Param(params, ++index, extra.minBw);
    MatchTransAlarmNameTypeExtraInt32Param(params, ++index, extra.methodId);
    MatchTransAlarmNameTypeExtraInt32Param(params, ++index, extra.duration);
    MatchTransAlarmNameTypeExtraInt32Param(params, ++index, extra.curFlow);
    MatchTransAlarmNameTypeExtraInt32Param(params, ++index, extra.limitFlow);
    MatchTransAlarmNameTypeExtraInt32Param(params, ++index, extra.limitTime);
    MatchTransAlarmNameTypeExtraInt32Param(params, ++index, extra.occupyRes);
    MatchTransAlarmNameTypeExtraInt32Param(params, ++index, extra.syncType);
    MatchTransAlarmNameTypeExtraInt32Param(params, ++index, extra.syncData);
    MatchTransAlarmNameTypeExtraInt32Param(params, ++index, extra.retryCount);
    MatchTransAlarmNameTypeExtraInt32Param(params, ++index, extra.retryReason);
    MatchTransAlarmNameTypeExtraStrParam(params, ++index, extra.conflictName);
    MatchTransAlarmNameTypeExtraStrParam(params, ++index, extra.conflictedName);
    MatchTransAlarmNameTypeExtraStrParam(params, ++index, extra.occupyedName);
    MatchTransAlarmNameTypeExtraStrParam(params, ++index, extra.permissionName);
    MatchTransAlarmNameTypeExtraStrParamAnony(params, ++index, extra.sessionName);
    EXPECT_EQ(++index, validSize);
    return true;
}

static void MatchTransAuditNameTypeExtraInt32Param(const HiSysEventParam *params, int32_t index, int32_t extraParam)
{
    EXPECT_STREQ(params[index].name, g_transAuditAssigners[index].name);
    EXPECT_EQ(params[index].t, g_transAuditAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extraParam);
}

static void MatchTransAuditNameTypeExtraStrParam(const HiSysEventParam *params, int32_t index, const char *extraParam)
{
    EXPECT_STREQ(params[index].name, g_transAuditAssigners[index].name);
    EXPECT_EQ(params[index].t, g_transAuditAssigners[index].type);
    EXPECT_STREQ(params[index].v.s, extraParam);
}

MATCHER_P2(TransAuditValidParamArrayMatcher, inExtra, validSize, "trans valid param array match fail")
{
    const auto *params = static_cast<const HiSysEventParam *>(arg);
    params += SOFTBUS_ASSIGNER_SIZE; // Skip softbus params, they are matched by SoftbusParamArrayMatcher
    auto extra = static_cast<TransAuditExtra>(inExtra);
    int32_t index = 0;
    MatchTransAuditNameTypeExtraStrParam(params, index, extra.hostPkg);
    MatchTransAuditNameTypeExtraInt32Param(params, ++index, extra.result);
    MatchTransAuditNameTypeExtraInt32Param(params, ++index, extra.errcode);
    MatchTransAuditNameTypeExtraInt32Param(params, ++index, extra.auditType);
    MatchTransAuditNameTypeExtraStrParam(params, ++index, extra.localIp);
    MatchTransAuditNameTypeExtraStrParam(params, ++index, extra.localPort);
    MatchTransAuditNameTypeExtraStrParam(params, ++index, extra.localDevId);
    MatchTransAuditNameTypeExtraInt32Param(params, ++index, extra.localDevType);
    MatchTransAuditNameTypeExtraStrParam(params, ++index, extra.localSessName);
    MatchTransAuditNameTypeExtraInt32Param(params, ++index, extra.localChannelId);
    MatchTransAuditNameTypeExtraStrParam(params, ++index, extra.peerIp);
    MatchTransAuditNameTypeExtraStrParam(params, ++index, extra.peerPort);
    MatchTransAuditNameTypeExtraStrParam(params, ++index, extra.peerDevId);
    MatchTransAuditNameTypeExtraInt32Param(params, ++index, extra.peerDevType);
    MatchTransAuditNameTypeExtraStrParam(params, ++index, extra.peerSessName);
    MatchTransAuditNameTypeExtraInt32Param(params, ++index, extra.peerChannelId);
    MatchTransAuditNameTypeExtraInt32Param(params, ++index, extra.channelType);
    MatchTransAuditNameTypeExtraInt32Param(params, ++index, extra.authId);
    MatchTransAuditNameTypeExtraInt32Param(params, ++index, extra.reqId);
    MatchTransAuditNameTypeExtraInt32Param(params, ++index, extra.linkType);
    MatchTransAuditNameTypeExtraInt32Param(params, ++index, extra.connId);
    MatchTransAuditNameTypeExtraInt32Param(params, ++index, extra.socketFd);
    MatchTransAuditNameTypeExtraInt32Param(params, ++index, extra.dataType);
    MatchTransAuditNameTypeExtraInt32Param(params, ++index, extra.dataLen);
    MatchTransAuditNameTypeExtraInt32Param(params, ++index, extra.dataSeq);
    MatchTransAuditNameTypeExtraInt32Param(params, ++index, extra.costTime);
    MatchTransAuditNameTypeExtraInt32Param(params, ++index, extra.dataTraffic);
    MatchTransAuditNameTypeExtraInt32Param(params, ++index, extra.reqCount);

    EXPECT_EQ(++index, validSize);
    return true;
}
#endif // TRANS_HISYSEVENT_MATCHER_H
