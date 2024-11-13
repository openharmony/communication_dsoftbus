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

#ifndef CONN_HISYSEVENT_MATCHER_H
#define CONN_HISYSEVENT_MATCHER_H

#include <gmock/gmock.h>

#include "convert/conn_audit_converter.h"
#include "convert/conn_event_converter.h"
#include "hisysevent_c.h"
#include "softbus_event.h"

static void MatchConnEventNameTypeExtraInt32Param(const HiSysEventParam *params, int32_t index, int32_t extraParam)
{
    EXPECT_STREQ(params[index].name, g_connAssigners[index].name);
    EXPECT_EQ(params[index].t, g_connAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extraParam);
}

static void MatchConnEventNameTypeExtraUint32Param(const HiSysEventParam *params, int32_t index, uint32_t extraParam)
{
    EXPECT_STREQ(params[index].name, g_connAssigners[index].name);
    EXPECT_EQ(params[index].t, g_connAssigners[index].type);
    EXPECT_EQ(params[index].v.ui32, extraParam);
}

static void MatchConnEventNameTypeExtraUint64Param(const HiSysEventParam *params, int32_t index, uint64_t extraParam)
{
    EXPECT_STREQ(params[index].name, g_connAssigners[index].name);
    EXPECT_EQ(params[index].t, g_connAssigners[index].type);
    EXPECT_EQ(params[index].v.ui64, extraParam);
}

static void MatchConnEventNameTypeExtraStrParam(const HiSysEventParam *params, int32_t index, const char * extraParam)
{
    EXPECT_STREQ(params[index].name, g_connAssigners[index].name);
    EXPECT_EQ(params[index].t, g_connAssigners[index].type);
    EXPECT_STREQ(params[index].v.s, extraParam);
}

static void MatchNotConnEventNameExtraStrParam(const HiSysEventParam *params, int32_t index, const char * extraParam)
{
    EXPECT_NE(params[index].name, g_connAssigners[index].name);
}

static void MatchConnEventNameTypeExtraStrParamAnony(const HiSysEventParam *params, int32_t index,
    const char * extraParam)
{
    char *anonyStr = NULL;
    EXPECT_STREQ(params[index].name, g_connAssigners[index].name);
    EXPECT_EQ(params[index].t, g_connAssigners[index].type);

    Anonymize(extraParam, &anonyStr);
    EXPECT_STREQ(params[index].v.s, AnonymizeWrapper(anonyStr));
    AnonymizeFree(anonyStr);
}

static int32_t MatchConnEventNameTypeExtraForAddMsg(const HiSysEventParam *params, int32_t index, ConnEventExtra extra)
{
    MatchConnEventNameTypeExtraInt32Param(params, ++index, extra.osType);
    MatchNotConnEventNameExtraStrParam(params, ++index, extra.localDeviceType);
    MatchNotConnEventNameExtraStrParam(params, ++index, extra.remoteDeviceType);
    MatchConnEventNameTypeExtraInt32Param(params, ++index, extra.p2pChannel);
    MatchConnEventNameTypeExtraInt32Param(params, ++index, extra.hmlChannel);
    MatchConnEventNameTypeExtraInt32Param(params, ++index, extra.staChannel);
    MatchConnEventNameTypeExtraInt32Param(params, ++index, extra.apChannel);
    MatchConnEventNameTypeExtraStrParam(params, ++index, extra.peerDevVer);
    MatchConnEventNameTypeExtraInt32Param(params, ++index, extra.remoteScreenStatus);
    MatchConnEventNameTypeExtraInt32Param(params, ++index, extra.businessType);
    MatchConnEventNameTypeExtraInt32Param(params, ++index, extra.businessId);
    MatchConnEventNameTypeExtraInt32Param(params, ++index, extra.timeout);
    MatchConnEventNameTypeExtraInt32Param(params, ++index, extra.fastestConnectEnable);
    MatchConnEventNameTypeExtraInt32Param(params, ++index, extra.coapDataChannel);
    MatchConnEventNameTypeExtraInt32Param(params, ++index, extra.enableWideBandwidth);
    MatchConnEventNameTypeExtraInt32Param(params, ++index, extra.p2pRole);
    MatchConnEventNameTypeExtraInt32Param(params, ++index, extra.needHmlConnect);
    MatchConnEventNameTypeExtraStrParam(params, ++index, extra.businessTag);
    return ++index;
}

MATCHER_P2(ConnValidParamArrayMatcher, inExtra, validSize, "conn valid param array match fail")
{
    const auto *params = static_cast<const HiSysEventParam *>(arg);
    params += SOFTBUS_ASSIGNER_SIZE; // Skip softbus params, they are matched by SoftbusParamArrayMatcher
    auto extra = static_cast<ConnEventExtra>(inExtra);
    int32_t index = 0;
    MatchConnEventNameTypeExtraInt32Param(params, index, extra.result);
    MatchConnEventNameTypeExtraInt32Param(params, ++index, extra.errcode);
    MatchConnEventNameTypeExtraInt32Param(params, ++index, extra.connectionId);
    MatchConnEventNameTypeExtraInt32Param(params, ++index, extra.requestId);
    MatchConnEventNameTypeExtraInt32Param(params, ++index, extra.linkType);
    MatchConnEventNameTypeExtraInt32Param(params, ++index, extra.authType);
    MatchConnEventNameTypeExtraInt32Param(params, ++index, extra.authId);
    MatchConnEventNameTypeExtraStrParam(params, ++index, extra.lnnType);
    MatchConnEventNameTypeExtraInt32Param(params, ++index, extra.expectRole);
    MatchConnEventNameTypeExtraInt32Param(params, ++index, extra.costTime);
    MatchConnEventNameTypeExtraInt32Param(params, ++index, extra.rssi);
    MatchConnEventNameTypeExtraInt32Param(params, ++index, extra.load);
    MatchConnEventNameTypeExtraInt32Param(params, ++index, extra.frequency);
    MatchConnEventNameTypeExtraInt32Param(params, ++index, extra.connProtocol);
    MatchConnEventNameTypeExtraInt32Param(params, ++index, extra.connRole);
    MatchConnEventNameTypeExtraInt32Param(params, ++index, extra.connRcDelta);
    MatchConnEventNameTypeExtraInt32Param(params, ++index, extra.connRc);
    MatchConnEventNameTypeExtraInt32Param(params, ++index, extra.supportFeature);
    MatchConnEventNameTypeExtraInt32Param(params, ++index, extra.moduleId);
    MatchConnEventNameTypeExtraUint32Param(params, ++index, extra.proType);
    MatchConnEventNameTypeExtraInt32Param(params, ++index, extra.fd);
    MatchConnEventNameTypeExtraInt32Param(params, ++index, extra.cfd);
    MatchConnEventNameTypeExtraStrParam(params, ++index, extra.challengeCode);
    MatchConnEventNameTypeExtraStrParamAnony(params, ++index, extra.peerIp);
    MatchConnEventNameTypeExtraStrParamAnony(params, ++index, extra.peerBrMac);
    MatchConnEventNameTypeExtraStrParamAnony(params, ++index, extra.peerBleMac);
    MatchConnEventNameTypeExtraStrParamAnony(params, ++index, extra.peerWifiMac);
    MatchConnEventNameTypeExtraStrParam(params, ++index, extra.peerPort);
    MatchConnEventNameTypeExtraStrParamAnony(params, ++index, extra.peerNetworkId);
    MatchConnEventNameTypeExtraStrParamAnony(params, ++index, extra.peerUdid);
    MatchConnEventNameTypeExtraStrParam(params, ++index, extra.peerDeviceType);
    MatchConnEventNameTypeExtraStrParamAnony(params, ++index, extra.localNetworkId);
    MatchConnEventNameTypeExtraStrParam(params, ++index, extra.callerPkg);
    MatchConnEventNameTypeExtraStrParam(params, ++index, extra.calleePkg);
    MatchConnEventNameTypeExtraInt32Param(params, ++index, extra.bootLinkType);
    MatchConnEventNameTypeExtraInt32Param(params, ++index, extra.isRenegotiate);
    MatchConnEventNameTypeExtraInt32Param(params, ++index, extra.isReuse);
    MatchConnEventNameTypeExtraUint64Param(params, ++index, extra.negotiateTime);
    MatchConnEventNameTypeExtraUint64Param(params, ++index, extra.linkTime);
    auto ret = MatchConnEventNameTypeExtraForAddMsg(params, index, extra);
    EXPECT_EQ(ret, validSize);
    return true;
}

MATCHER_P2(ConnInvalidParamArrayMatcher, inExtra, validSize, "conn invalid param array match fail")
{
    const auto *params = static_cast<const HiSysEventParam *>(arg);
    params += SOFTBUS_ASSIGNER_SIZE; // Skip softbus params, they are matched by SoftbusParamArrayMatcher
    auto extra = static_cast<ConnEventExtra>(inExtra);
    int32_t index = 0;
    MatchConnEventNameTypeExtraInt32Param(params, index, ((extra.result < 0) ? (-extra.result) : extra.result));
    MatchConnEventNameTypeExtraInt32Param(params, ++index, ((extra.errcode < 0) ? (-extra.errcode) : extra.errcode));
    EXPECT_EQ(++index, validSize);
    return true;
}

static void MatchConnAuditNameTypeExtraInt32Param(const HiSysEventParam *params, int32_t index, int32_t extraParam)
{
    EXPECT_STREQ(params[index].name, g_connAuditAssigners[index].name);
    EXPECT_EQ(params[index].t, g_connAuditAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extraParam);
}

static void MatchConnAuditNameTypeExtraStrParam(const HiSysEventParam *params, int32_t index, const char *extraParam)
{
    EXPECT_STREQ(params[index].name, g_connAuditAssigners[index].name);
    EXPECT_EQ(params[index].t, g_connAuditAssigners[index].type);
    EXPECT_STREQ(params[index].v.s, extraParam);
}

MATCHER_P2(ConnAuditValidParamArrayMatcher, inExtra, validSize, "conn valid param array match fail")
{
    const auto *params = static_cast<const HiSysEventParam *>(arg);
    params += SOFTBUS_ASSIGNER_SIZE; // Skip softbus params, they are matched by SoftbusParamArrayMatcher
    auto extra = static_cast<ConnAuditExtra>(inExtra);
    int32_t index = 0;

    MatchConnAuditNameTypeExtraInt32Param(params, index, extra.errcode);
    MatchConnAuditNameTypeExtraInt32Param(params, ++index, extra.auditType);
    MatchConnAuditNameTypeExtraInt32Param(params, ++index, extra.connectionId);
    MatchConnAuditNameTypeExtraInt32Param(params, ++index, extra.requestId);
    MatchConnAuditNameTypeExtraInt32Param(params, ++index, extra.linkType);
    MatchConnAuditNameTypeExtraInt32Param(params, ++index, extra.expectRole);
    MatchConnAuditNameTypeExtraInt32Param(params, ++index, extra.costTime);
    MatchConnAuditNameTypeExtraInt32Param(params, ++index, extra.connectTimes);
    MatchConnAuditNameTypeExtraStrParam(params, ++index, extra.frequency);
    MatchConnAuditNameTypeExtraStrParam(params, ++index, extra.challengeCode);
    MatchConnAuditNameTypeExtraStrParam(params, ++index, extra.peerBrMac);
    MatchConnAuditNameTypeExtraStrParam(params, ++index, extra.localBrMac);
    MatchConnAuditNameTypeExtraStrParam(params, ++index, extra.peerBleMac);
    MatchConnAuditNameTypeExtraStrParam(params, ++index, extra.localBleMac);
    MatchConnAuditNameTypeExtraStrParam(params, ++index, extra.peerDeviceType);
    MatchConnAuditNameTypeExtraStrParam(params, ++index, extra.peerUdid);
    MatchConnAuditNameTypeExtraStrParam(params, ++index, extra.localUdid);
    MatchConnAuditNameTypeExtraStrParam(params, ++index, extra.connPayload);
    MatchConnAuditNameTypeExtraStrParam(params, ++index, extra.localDeviceName);
    MatchConnAuditNameTypeExtraStrParam(params, ++index, extra.peerIp);
    MatchConnAuditNameTypeExtraStrParam(params, ++index, extra.localIp);
    MatchConnAuditNameTypeExtraStrParam(params, ++index, extra.callerPkg);
    MatchConnAuditNameTypeExtraStrParam(params, ++index, extra.calleePkg);
    MatchConnAuditNameTypeExtraStrParam(params, ++index, extra.peerPort);
    MatchConnAuditNameTypeExtraStrParam(params, ++index, extra.localPort);

    EXPECT_EQ(++index, validSize);
    return true;
}
#endif // CONN_HISYSEVENT_MATCHER_H
