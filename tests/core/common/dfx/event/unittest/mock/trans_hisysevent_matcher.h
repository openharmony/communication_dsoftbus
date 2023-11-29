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

#include "convert/trans_event_converter.h"
#include "hisysevent_c.h"
#include "softbus_event.h"

MATCHER_P2(TransValidParamArrayMatcher, inExtra, validSize, "trans valid param array match fail")
{
    const auto *params = static_cast<const HiSysEventParam *>(arg);
    params += SOFTBUS_ASSIGNER_SIZE; // Skip softbus params, they are matched by SoftbusParamArrayMatcher
    auto extra = static_cast<TransEventExtra>(inExtra);
    int32_t index = 0;
    EXPECT_STREQ(params[index].name, g_transAssigners[index].name);
    EXPECT_EQ(params[index].t, g_transAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.result);
    ++index;
    EXPECT_STREQ(params[index].name, g_transAssigners[index].name);
    EXPECT_EQ(params[index].t, g_transAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.errcode);
    ++index;
    EXPECT_STREQ(params[index].name, g_transAssigners[index].name);
    EXPECT_EQ(params[index].t, g_transAssigners[index].type);
    EXPECT_STREQ(params[index].v.s, extra.socketName);
    ++index;
    EXPECT_STREQ(params[index].name, g_transAssigners[index].name);
    EXPECT_EQ(params[index].t, g_transAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.dataType);
    ++index;
    EXPECT_STREQ(params[index].name, g_transAssigners[index].name);
    EXPECT_EQ(params[index].t, g_transAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.channelType);
    ++index;
    EXPECT_STREQ(params[index].name, g_transAssigners[index].name);
    EXPECT_EQ(params[index].t, g_transAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.laneId);
    ++index;
    EXPECT_STREQ(params[index].name, g_transAssigners[index].name);
    EXPECT_EQ(params[index].t, g_transAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.preferLinkType);
    ++index;
    EXPECT_STREQ(params[index].name, g_transAssigners[index].name);
    EXPECT_EQ(params[index].t, g_transAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.laneTransType);
    ++index;
    EXPECT_STREQ(params[index].name, g_transAssigners[index].name);
    EXPECT_EQ(params[index].t, g_transAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.channelId);
    ++index;
    EXPECT_STREQ(params[index].name, g_transAssigners[index].name);
    EXPECT_EQ(params[index].t, g_transAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.requestId);
    ++index;
    EXPECT_STREQ(params[index].name, g_transAssigners[index].name);
    EXPECT_EQ(params[index].t, g_transAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.connectionId);
    ++index;
    EXPECT_STREQ(params[index].name, g_transAssigners[index].name);
    EXPECT_EQ(params[index].t, g_transAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.linkType);
    ++index;
    EXPECT_STREQ(params[index].name, g_transAssigners[index].name);
    EXPECT_EQ(params[index].t, g_transAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.authId);
    ++index;
    EXPECT_STREQ(params[index].name, g_transAssigners[index].name);
    EXPECT_EQ(params[index].t, g_transAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.socketFd);
    ++index;
    EXPECT_STREQ(params[index].name, g_transAssigners[index].name);
    EXPECT_EQ(params[index].t, g_transAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.costTime);
    ++index;
    EXPECT_STREQ(params[index].name, g_transAssigners[index].name);
    EXPECT_EQ(params[index].t, g_transAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.channelScore);
    ++index;
    EXPECT_STREQ(params[index].name, g_transAssigners[index].name);
    EXPECT_EQ(params[index].t, g_transAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.peerChannelId);
    ++index;
    EXPECT_STREQ(params[index].name, g_transAssigners[index].name);
    EXPECT_EQ(params[index].t, g_transAssigners[index].type);
    EXPECT_STREQ(params[index].v.s, extra.peerNetworkId);
    ++index;
    EXPECT_STREQ(params[index].name, g_transAssigners[index].name);
    EXPECT_EQ(params[index].t, g_transAssigners[index].type);
    EXPECT_STREQ(params[index].v.s, extra.callerPkg);
    ++index;
    EXPECT_STREQ(params[index].name, g_transAssigners[index].name);
    EXPECT_EQ(params[index].t, g_transAssigners[index].type);
    EXPECT_STREQ(params[index].v.s, extra.calleePkg);

    EXPECT_EQ(++index, validSize);
    return true;
}

MATCHER_P2(TransInvalidParamArrayMatcher, inExtra, validSize, "trans invalid param array match fail")
{
    const auto *params = static_cast<const HiSysEventParam *>(arg);
    params += SOFTBUS_ASSIGNER_SIZE; // Skip softbus params, they are matched by SoftbusParamArrayMatcher
    auto extra = static_cast<TransEventExtra>(inExtra);
    int32_t index = 0;
    EXPECT_STREQ(params[index].name, g_transAssigners[index].name);
    EXPECT_EQ(params[index].t, g_transAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, ((extra.result < 0) ? (-extra.result) : extra.result));
    ++index;
    EXPECT_STREQ(params[index].name, g_transAssigners[index].name);
    EXPECT_EQ(params[index].t, g_transAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, ((extra.errcode < 0) ? (-extra.errcode) : extra.errcode));
    EXPECT_EQ(++index, validSize);
    return true;
}
#endif // TRANS_HISYSEVENT_MATCHER_H
