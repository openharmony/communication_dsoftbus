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

#ifndef DISC_HISYSEVENT_MATCHER_H
#define DISC_HISYSEVENT_MATCHER_H

#include <gmock/gmock.h>

#include "convert/disc_event_converter.h"
#include "hisysevent_c.h"
#include "softbus_event.h"

static void MatchDiscEventNameTypeExtraInt32Param(const HiSysEventParam *params, int32_t index, int32_t extraParam)
{
    EXPECT_STREQ(params[index].name, g_discAssigners[index].name);
    EXPECT_EQ(params[index].t, g_discAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extraParam);
}

static void MatchDiscEventNameTypeExtraStrParam(const HiSysEventParam *params, int32_t index, const char * extraParam)
{
    EXPECT_STREQ(params[index].name, g_discAssigners[index].name);
    EXPECT_EQ(params[index].t, g_discAssigners[index].type);
    EXPECT_STREQ(params[index].v.s, extraParam);
}

static void MatchDiscEventNameTypeExtraStrParamAnony(const HiSysEventParam *params, int32_t index,
    const char * extraParam)
{
    char *anonyStr = NULL;
    EXPECT_STREQ(params[index].name, g_discAssigners[index].name);
    EXPECT_EQ(params[index].t, g_discAssigners[index].type);
    Anonymize(extraParam, &anonyStr);
    EXPECT_STREQ(params[index].v.s, AnonymizeWrapper(anonyStr));
    AnonymizeFree(anonyStr);
}

MATCHER_P2(DiscValidParamArrayMatcher, inExtra, validSize, "disc valid param array match fail")
{
    const auto *params = static_cast<const HiSysEventParam *>(arg);
    params += SOFTBUS_ASSIGNER_SIZE; // Skip softbus params, they are matched by SoftbusParamArrayMatcher
    auto extra = static_cast<DiscEventExtra>(inExtra);
    int32_t index = 0;
    MatchDiscEventNameTypeExtraInt32Param(params, index, extra.result);
    MatchDiscEventNameTypeExtraInt32Param(params, ++index, extra.errcode);
    MatchDiscEventNameTypeExtraInt32Param(params, ++index, extra.initType);
    MatchDiscEventNameTypeExtraStrParam(params, ++index, extra.serverType);
    MatchDiscEventNameTypeExtraInt32Param(params, ++index, extra.advHandle);
    MatchDiscEventNameTypeExtraInt32Param(params, ++index, extra.bcOverMaxCnt);
    MatchDiscEventNameTypeExtraInt32Param(params, ++index, extra.interFuncType);
    MatchDiscEventNameTypeExtraInt32Param(params, ++index, extra.capabilityBit);
    MatchDiscEventNameTypeExtraStrParam(params, ++index, extra.capabilityData);
    MatchDiscEventNameTypeExtraInt32Param(params, ++index, extra.bleTurnState);
    MatchDiscEventNameTypeExtraInt32Param(params, ++index, extra.ipLinkStatus);
    MatchDiscEventNameTypeExtraInt32Param(params, ++index, extra.coapChangeType);
    MatchDiscEventNameTypeExtraInt32Param(params, ++index, extra.broadcastType);
    MatchDiscEventNameTypeExtraInt32Param(params, ++index, extra.broadcastFreq);
    MatchDiscEventNameTypeExtraInt32Param(params, ++index, extra.minInterval);
    MatchDiscEventNameTypeExtraInt32Param(params, ++index, extra.maxInterval);
    MatchDiscEventNameTypeExtraInt32Param(params, ++index, extra.currentNum);
    MatchDiscEventNameTypeExtraInt32Param(params, ++index, extra.scanType);
    MatchDiscEventNameTypeExtraInt32Param(params, ++index, extra.scanCount);
    MatchDiscEventNameTypeExtraStrParam(params, ++index, extra.scanCycle);
    MatchDiscEventNameTypeExtraInt32Param(params, ++index, extra.discType);
    MatchDiscEventNameTypeExtraInt32Param(params, ++index, extra.discMode);
    MatchDiscEventNameTypeExtraInt32Param(params, ++index, extra.successCnt);
    MatchDiscEventNameTypeExtraInt32Param(params, ++index, extra.failCnt);
    MatchDiscEventNameTypeExtraInt32Param(params, ++index, extra.startTime);
    MatchDiscEventNameTypeExtraInt32Param(params, ++index, extra.costTime);
    MatchDiscEventNameTypeExtraStrParamAnony(params, ++index, extra.localNetworkId);
    MatchDiscEventNameTypeExtraStrParamAnony(params, ++index, extra.peerIp);
    MatchDiscEventNameTypeExtraStrParamAnony(params, ++index, extra.peerBrMac);
    MatchDiscEventNameTypeExtraStrParamAnony(params, ++index, extra.peerBleMac);
    MatchDiscEventNameTypeExtraStrParamAnony(params, ++index, extra.peerWifiMac);
    MatchDiscEventNameTypeExtraStrParam(params, ++index, extra.peerPort);
    MatchDiscEventNameTypeExtraStrParamAnony(params, ++index, extra.peerNetworkId);
    MatchDiscEventNameTypeExtraStrParam(params, ++index, extra.peerDeviceType);
    MatchDiscEventNameTypeExtraStrParam(params, ++index, extra.callerPkg);
    EXPECT_EQ(++index, validSize);
    return true;
}

MATCHER_P2(DiscInvalidParamArrayMatcher, inExtra, validSize, "disc invalid param array match fail")
{
    const auto *params = static_cast<const HiSysEventParam *>(arg);
    params += SOFTBUS_ASSIGNER_SIZE; // Skip softbus params, they are matched by SoftbusParamArrayMatcher
    auto extra = static_cast<DiscEventExtra>(inExtra);
    int32_t index = 0;
    MatchDiscEventNameTypeExtraInt32Param(params, index, ((extra.result < 0) ? (-extra.result) : extra.result));
    MatchDiscEventNameTypeExtraInt32Param(params, ++index, ((extra.errcode < 0) ? (-extra.errcode) : extra.errcode));
    EXPECT_EQ(++index, validSize);
    return true;
}

#endif // DISC_HISYSEVENT_MATCHER_H
