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

MATCHER_P2(DiscValidParamArrayMatcher, inExtra, validSize, "disc valid param array match fail")
{
    const auto *params = static_cast<const HiSysEventParam *>(arg);
    params += SOFTBUS_ASSIGNER_SIZE; // Skip softbus params, they are matched by SoftbusParamArrayMatcher
    auto extra = static_cast<DiscEventExtra>(inExtra);
    int32_t index = 0;
    EXPECT_STREQ(params[index].name, g_discAssigners[index].name);
    EXPECT_EQ(params[index].t, g_discAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.result);
    ++index;
    EXPECT_STREQ(params[index].name, g_discAssigners[index].name);
    EXPECT_EQ(params[index].t, g_discAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.errcode);
    ++index;
    EXPECT_STREQ(params[index].name, g_discAssigners[index].name);
    EXPECT_EQ(params[index].t, g_discAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.initType);
    ++index;
    EXPECT_STREQ(params[index].name, g_discAssigners[index].name);
    EXPECT_EQ(params[index].t, g_discAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.serverType);
    ++index;
    EXPECT_STREQ(params[index].name, g_discAssigners[index].name);
    EXPECT_EQ(params[index].t, g_discAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.interFuncType);
    ++index;
    EXPECT_STREQ(params[index].name, g_discAssigners[index].name);
    EXPECT_EQ(params[index].t, g_discAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.capabilityBit);
    ++index;
    EXPECT_STREQ(params[index].name, g_discAssigners[index].name);
    EXPECT_EQ(params[index].t, g_discAssigners[index].type);
    EXPECT_STREQ(params[index].v.s, extra.capabilityData);
    ++index;
    EXPECT_STREQ(params[index].name, g_discAssigners[index].name);
    EXPECT_EQ(params[index].t, g_discAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.bleTurnState);
    ++index;
    EXPECT_STREQ(params[index].name, g_discAssigners[index].name);
    EXPECT_EQ(params[index].t, g_discAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.ipLinkStatus);
    ++index;
    EXPECT_STREQ(params[index].name, g_discAssigners[index].name);
    EXPECT_EQ(params[index].t, g_discAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.coapChangeType);
    ++index;
    EXPECT_STREQ(params[index].name, g_discAssigners[index].name);
    EXPECT_EQ(params[index].t, g_discAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.broadcastType);
    ++index;
    EXPECT_STREQ(params[index].name, g_discAssigners[index].name);
    EXPECT_EQ(params[index].t, g_discAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.broadcastFreq);
    ++index;
    EXPECT_STREQ(params[index].name, g_discAssigners[index].name);
    EXPECT_EQ(params[index].t, g_discAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.scanType);
    ++index;
    EXPECT_STREQ(params[index].name, g_discAssigners[index].name);
    EXPECT_EQ(params[index].t, g_discAssigners[index].type);
    EXPECT_STREQ(params[index].v.s, extra.scanCycle);
    ++index;
    EXPECT_STREQ(params[index].name, g_discAssigners[index].name);
    EXPECT_EQ(params[index].t, g_discAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.discType);
    ++index;
    EXPECT_STREQ(params[index].name, g_discAssigners[index].name);
    EXPECT_EQ(params[index].t, g_discAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.discMode);
    ++index;
    EXPECT_STREQ(params[index].name, g_discAssigners[index].name);
    EXPECT_EQ(params[index].t, g_discAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.costTime);
    ++index;
    EXPECT_STREQ(params[index].name, g_discAssigners[index].name);
    EXPECT_EQ(params[index].t, g_discAssigners[index].type);
    char *anonyStr = NULL;
    Anonymize(extra.localNetworkId, &anonyStr);
    EXPECT_STREQ(params[index].v.s, anonyStr);
    AnonymizeFree(anonyStr);
    ++index;
    EXPECT_STREQ(params[index].name, g_discAssigners[index].name);
    EXPECT_EQ(params[index].t, g_discAssigners[index].type);
    Anonymize(extra.peerIp, &anonyStr);
    EXPECT_STREQ(params[index].v.s, anonyStr);
    AnonymizeFree(anonyStr);
    ++index;
    EXPECT_STREQ(params[index].name, g_discAssigners[index].name);
    EXPECT_EQ(params[index].t, g_discAssigners[index].type);
    Anonymize(extra.peerBrMac, &anonyStr);
    EXPECT_STREQ(params[index].v.s, anonyStr);
    AnonymizeFree(anonyStr);
    ++index;
    EXPECT_STREQ(params[index].name, g_discAssigners[index].name);
    EXPECT_EQ(params[index].t, g_discAssigners[index].type);
    Anonymize(extra.peerBleMac, &anonyStr);
    EXPECT_STREQ(params[index].v.s, anonyStr);
    AnonymizeFree(anonyStr);
    ++index;
    EXPECT_STREQ(params[index].name, g_discAssigners[index].name);
    EXPECT_EQ(params[index].t, g_discAssigners[index].type);
    Anonymize(extra.peerWifiMac, &anonyStr);
    EXPECT_STREQ(params[index].v.s, anonyStr);
    AnonymizeFree(anonyStr);
    ++index;
    EXPECT_STREQ(params[index].name, g_discAssigners[index].name);
    EXPECT_EQ(params[index].t, g_discAssigners[index].type);
    EXPECT_STREQ(params[index].v.s, extra.peerPort);
    ++index;
    EXPECT_STREQ(params[index].name, g_discAssigners[index].name);
    EXPECT_EQ(params[index].t, g_discAssigners[index].type);
    Anonymize(extra.peerNetworkId, &anonyStr);
    EXPECT_STREQ(params[index].v.s, anonyStr);
    AnonymizeFree(anonyStr);
    ++index;
    EXPECT_STREQ(params[index].name, g_discAssigners[index].name);
    EXPECT_EQ(params[index].t, g_discAssigners[index].type);
    EXPECT_STREQ(params[index].v.s, extra.peerDeviceType);
    ++index;
    EXPECT_STREQ(params[index].name, g_discAssigners[index].name);
    EXPECT_EQ(params[index].t, g_discAssigners[index].type);
    EXPECT_STREQ(params[index].v.s, extra.callerPkg);

    EXPECT_EQ(++index, validSize);
    return true;
}

MATCHER_P2(DiscInvalidParamArrayMatcher, inExtra, validSize, "disc invalid param array match fail")
{
    const auto *params = static_cast<const HiSysEventParam *>(arg);
    params += SOFTBUS_ASSIGNER_SIZE; // Skip softbus params, they are matched by SoftbusParamArrayMatcher
    auto extra = static_cast<DiscEventExtra>(inExtra);
    int32_t index = 0;
    EXPECT_STREQ(params[index].name, g_discAssigners[index].name);
    EXPECT_EQ(params[index].t, g_discAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, ((extra.result < 0) ? (-extra.result) : extra.result));
    ++index;
    EXPECT_STREQ(params[index].name, g_discAssigners[index].name);
    EXPECT_EQ(params[index].t, g_discAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, ((extra.errcode < 0) ? (-extra.errcode) : extra.errcode));
    EXPECT_EQ(++index, validSize);
    return true;
}

#endif // DISC_HISYSEVENT_MATCHER_H
