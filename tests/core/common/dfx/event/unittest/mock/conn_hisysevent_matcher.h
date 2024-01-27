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

#include "convert/conn_event_converter.h"
#include "convert/conn_audit_converter.h"
#include "hisysevent_c.h"
#include "softbus_event.h"

MATCHER_P2(ConnValidParamArrayMatcher, inExtra, validSize, "conn valid param array match fail")
{
    const auto *params = static_cast<const HiSysEventParam *>(arg);
    params += SOFTBUS_ASSIGNER_SIZE; // Skip softbus params, they are matched by SoftbusParamArrayMatcher
    auto extra = static_cast<ConnEventExtra>(inExtra);
    int32_t index = 0;
    EXPECT_STREQ(params[index].name, g_connAssigners[index].name);
    EXPECT_EQ(params[index].t, g_connAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.result);
    ++index;
    EXPECT_STREQ(params[index].name, g_connAssigners[index].name);
    EXPECT_EQ(params[index].t, g_connAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.errcode);
    ++index;
    EXPECT_STREQ(params[index].name, g_connAssigners[index].name);
    EXPECT_EQ(params[index].t, g_connAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.connectionId);
    ++index;
    EXPECT_STREQ(params[index].name, g_connAssigners[index].name);
    EXPECT_EQ(params[index].t, g_connAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.requestId);
    ++index;
    EXPECT_STREQ(params[index].name, g_connAssigners[index].name);
    EXPECT_EQ(params[index].t, g_connAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.linkType);
    ++index;
    EXPECT_STREQ(params[index].name, g_connAssigners[index].name);
    EXPECT_EQ(params[index].t, g_connAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.authType);
    ++index;
    EXPECT_STREQ(params[index].name, g_connAssigners[index].name);
    EXPECT_EQ(params[index].t, g_connAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.authId);
    ++index;
    EXPECT_STREQ(params[index].name, g_connAssigners[index].name);
    EXPECT_EQ(params[index].t, g_connAssigners[index].type);
    EXPECT_STREQ(params[index].v.s, extra.lnnType);
    ++index;
    EXPECT_STREQ(params[index].name, g_connAssigners[index].name);
    EXPECT_EQ(params[index].t, g_connAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.expectRole);
    ++index;
    EXPECT_STREQ(params[index].name, g_connAssigners[index].name);
    EXPECT_EQ(params[index].t, g_connAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.costTime);
    ++index;
    EXPECT_STREQ(params[index].name, g_connAssigners[index].name);
    EXPECT_EQ(params[index].t, g_connAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.rssi);
    ++index;
    EXPECT_STREQ(params[index].name, g_connAssigners[index].name);
    EXPECT_EQ(params[index].t, g_connAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.load);
    ++index;
    EXPECT_STREQ(params[index].name, g_connAssigners[index].name);
    EXPECT_EQ(params[index].t, g_connAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.frequency);
    ++index;
    EXPECT_STREQ(params[index].name, g_connAssigners[index].name);
    EXPECT_EQ(params[index].t, g_connAssigners[index].type);
    char *anonyStr = NULL;
    Anonymize(extra.peerIp, &anonyStr);
    EXPECT_STREQ(params[index].v.s, anonyStr);
    AnonymizeFree(anonyStr);
    ++index;
    EXPECT_STREQ(params[index].name, g_connAssigners[index].name);
    EXPECT_EQ(params[index].t, g_connAssigners[index].type);
    Anonymize(extra.peerBrMac, &anonyStr);
    EXPECT_STREQ(params[index].v.s, anonyStr);
    AnonymizeFree(anonyStr);
    ++index;
    EXPECT_STREQ(params[index].name, g_connAssigners[index].name);
    EXPECT_EQ(params[index].t, g_connAssigners[index].type);
    Anonymize(extra.peerBleMac, &anonyStr);
    EXPECT_STREQ(params[index].v.s, anonyStr);
    AnonymizeFree(anonyStr);
    ++index;
    EXPECT_STREQ(params[index].name, g_connAssigners[index].name);
    EXPECT_EQ(params[index].t, g_connAssigners[index].type);
    Anonymize(extra.peerWifiMac, &anonyStr);
    EXPECT_STREQ(params[index].v.s, anonyStr);
    AnonymizeFree(anonyStr);
    ++index;
    EXPECT_STREQ(params[index].name, g_connAssigners[index].name);
    EXPECT_EQ(params[index].t, g_connAssigners[index].type);
    EXPECT_STREQ(params[index].v.s, extra.peerPort);
    ++index;
    EXPECT_STREQ(params[index].name, g_connAssigners[index].name);
    EXPECT_EQ(params[index].t, g_connAssigners[index].type);
    EXPECT_STREQ(params[index].v.s, extra.callerPkg);
    ++index;
    EXPECT_STREQ(params[index].name, g_connAssigners[index].name);
    EXPECT_EQ(params[index].t, g_connAssigners[index].type);
    EXPECT_STREQ(params[index].v.s, extra.calleePkg);

    EXPECT_EQ(++index, validSize);
    return true;
}

MATCHER_P2(ConnInvalidParamArrayMatcher, inExtra, validSize, "conn invalid param array match fail")
{
    const auto *params = static_cast<const HiSysEventParam *>(arg);
    params += SOFTBUS_ASSIGNER_SIZE; // Skip softbus params, they are matched by SoftbusParamArrayMatcher
    auto extra = static_cast<ConnEventExtra>(inExtra);
    int32_t index = 0;
    EXPECT_STREQ(params[index].name, g_connAssigners[index].name);
    EXPECT_EQ(params[index].t, g_connAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, ((extra.result < 0) ? (-extra.result) : extra.result));
    ++index;
    EXPECT_STREQ(params[index].name, g_connAssigners[index].name);
    EXPECT_EQ(params[index].t, g_connAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, ((extra.errcode < 0) ? (-extra.errcode) : extra.errcode));
    EXPECT_EQ(++index, validSize);
    return true;
}

MATCHER_P2(ConnAuditValidParamArrayMatcher, inExtra, validSize, "conn valid param array match fail")
{
    const auto *params = static_cast<const HiSysEventParam *>(arg);
    params += SOFTBUS_ASSIGNER_SIZE; // Skip softbus params, they are matched by SoftbusParamArrayMatcher
    auto extra = static_cast<ConnAuditExtra>(inExtra);
    int32_t index = 0;

    EXPECT_STREQ(params[index].name, g_connAuditAssigners[index].name);
    EXPECT_EQ(params[index].t, g_connAuditAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.errcode);
    ++index;
    EXPECT_STREQ(params[index].name, g_connAuditAssigners[index].name);
    EXPECT_EQ(params[index].t, g_connAuditAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.auditType);
    ++index;
    EXPECT_STREQ(params[index].name, g_connAuditAssigners[index].name);
    EXPECT_EQ(params[index].t, g_connAuditAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.connectionId);
    ++index;
    EXPECT_STREQ(params[index].name, g_connAuditAssigners[index].name);
    EXPECT_EQ(params[index].t, g_connAuditAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.requestId);
    ++index;
    EXPECT_STREQ(params[index].name, g_connAuditAssigners[index].name);
    EXPECT_EQ(params[index].t, g_connAuditAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.linkType);
    ++index;
    EXPECT_STREQ(params[index].name, g_connAuditAssigners[index].name);
    EXPECT_EQ(params[index].t, g_connAuditAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.expectRole);
    ++index;
    EXPECT_STREQ(params[index].name, g_connAuditAssigners[index].name);
    EXPECT_EQ(params[index].t, g_connAuditAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.costTime);

    ++index;
    EXPECT_STREQ(params[index].name, g_connAuditAssigners[index].name);
    EXPECT_EQ(params[index].t, g_connAuditAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.connectTimes);

    ++index;
    EXPECT_STREQ(params[index].name, g_connAuditAssigners[index].name);
    EXPECT_EQ(params[index].t, g_connAuditAssigners[index].type);
    EXPECT_STREQ(params[index].v.s, extra.frequency);

    ++index;
    EXPECT_STREQ(params[index].name, g_connAuditAssigners[index].name);
    EXPECT_EQ(params[index].t, g_connAuditAssigners[index].type);
    EXPECT_STREQ(params[index].v.s, extra.peerBrMac);

    ++index;
    EXPECT_STREQ(params[index].name, g_connAuditAssigners[index].name);
    EXPECT_EQ(params[index].t, g_connAuditAssigners[index].type);
    EXPECT_STREQ(params[index].v.s, extra.localBrMac);

    ++index;
    EXPECT_STREQ(params[index].name, g_connAuditAssigners[index].name);
    EXPECT_EQ(params[index].t, g_connAuditAssigners[index].type);
    EXPECT_STREQ(params[index].v.s, extra.peerBleMac);

    ++index;
    EXPECT_STREQ(params[index].name, g_connAuditAssigners[index].name);
    EXPECT_EQ(params[index].t, g_connAuditAssigners[index].type);
    EXPECT_STREQ(params[index].v.s, extra.localBleMac);

    ++index;
    EXPECT_STREQ(params[index].name, g_connAuditAssigners[index].name);
    EXPECT_EQ(params[index].t, g_connAuditAssigners[index].type);
    EXPECT_STREQ(params[index].v.s, extra.peerDeviceType);

    ++index;
    EXPECT_STREQ(params[index].name, g_connAuditAssigners[index].name);
    EXPECT_EQ(params[index].t, g_connAuditAssigners[index].type);
    EXPECT_STREQ(params[index].v.s, extra.peerUdid);

    ++index;
    EXPECT_STREQ(params[index].name, g_connAuditAssigners[index].name);
    EXPECT_EQ(params[index].t, g_connAuditAssigners[index].type);
    EXPECT_STREQ(params[index].v.s, extra.localUdid);

    ++index;
    EXPECT_STREQ(params[index].name, g_connAuditAssigners[index].name);
    EXPECT_EQ(params[index].t, g_connAuditAssigners[index].type);
    EXPECT_STREQ(params[index].v.s, extra.connPayload);

    ++index;
    EXPECT_STREQ(params[index].name, g_connAuditAssigners[index].name);
    EXPECT_EQ(params[index].t, g_connAuditAssigners[index].type);
    EXPECT_STREQ(params[index].v.s, extra.localDeviceName);

    ++index;
    EXPECT_STREQ(params[index].name, g_connAuditAssigners[index].name);
    EXPECT_EQ(params[index].t, g_connAuditAssigners[index].type);
    EXPECT_STREQ(params[index].v.s, extra.peerIp);

    ++index;
    EXPECT_STREQ(params[index].name, g_connAuditAssigners[index].name);
    EXPECT_EQ(params[index].t, g_connAuditAssigners[index].type);
    EXPECT_STREQ(params[index].v.s, extra.localIp);

    ++index;
    EXPECT_STREQ(params[index].name, g_connAuditAssigners[index].name);
    EXPECT_EQ(params[index].t, g_connAuditAssigners[index].type);
    EXPECT_STREQ(params[index].v.s, extra.callerPkg);

    ++index;
    EXPECT_STREQ(params[index].name, g_connAuditAssigners[index].name);
    EXPECT_EQ(params[index].t, g_connAuditAssigners[index].type);
    EXPECT_STREQ(params[index].v.s, extra.calleePkg);

    ++index;
    EXPECT_STREQ(params[index].name, g_connAuditAssigners[index].name);
    EXPECT_EQ(params[index].t, g_connAuditAssigners[index].type);
    EXPECT_STREQ(params[index].v.s, extra.peerPort);

    ++index;
    EXPECT_STREQ(params[index].name, g_connAuditAssigners[index].name);
    EXPECT_EQ(params[index].t, g_connAuditAssigners[index].type);
    EXPECT_STREQ(params[index].v.s, extra.localPort);

    EXPECT_EQ(++index, validSize);
    return true;
}
#endif // CONN_HISYSEVENT_MATCHER_H
