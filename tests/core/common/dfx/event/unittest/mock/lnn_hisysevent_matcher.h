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

MATCHER_P2(LnnValidParamArrayMatcher, inExtra, validSize, "lnn valid param array match fail")
{
    const auto *params = static_cast<const HiSysEventParam *>(arg);
    params += SOFTBUS_ASSIGNER_SIZE; // Skip softbus params, they are matched by SoftbusParamArrayMatcher
    auto extra = static_cast<LnnEventExtra>(inExtra);
    int32_t index = 0;
    EXPECT_STREQ(params[index].name, g_lnnAssigners[index].name);
    EXPECT_EQ(params[index].t, g_lnnAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.result);
    ++index;
    EXPECT_STREQ(params[index].name, g_lnnAssigners[index].name);
    EXPECT_EQ(params[index].t, g_lnnAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.errcode);
    ++index;
    EXPECT_STREQ(params[index].name, g_lnnAssigners[index].name);
    EXPECT_EQ(params[index].t, g_lnnAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.authId);
    ++index;
    EXPECT_STREQ(params[index].name, g_lnnAssigners[index].name);
    EXPECT_EQ(params[index].t, g_lnnAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.discServerType);
    ++index;
    EXPECT_STREQ(params[index].name, g_lnnAssigners[index].name);
    EXPECT_EQ(params[index].t, g_lnnAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.gearCycle);
    ++index;
    EXPECT_STREQ(params[index].name, g_lnnAssigners[index].name);
    EXPECT_EQ(params[index].t, g_lnnAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.gearDuration);
    ++index;
    EXPECT_STREQ(params[index].name, g_lnnAssigners[index].name);
    EXPECT_EQ(params[index].t, g_lnnAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.connectionId);
    ++index;
    EXPECT_STREQ(params[index].name, g_lnnAssigners[index].name);
    EXPECT_EQ(params[index].t, g_lnnAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.authLinkType);
    ++index;
    EXPECT_STREQ(params[index].name, g_lnnAssigners[index].name);
    EXPECT_EQ(params[index].t, g_lnnAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.authCostTime);
    ++index;
    EXPECT_STREQ(params[index].name, g_lnnAssigners[index].name);
    EXPECT_EQ(params[index].t, g_lnnAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.lnnType);
    ++index;
    EXPECT_STREQ(params[index].name, g_lnnAssigners[index].name);
    EXPECT_EQ(params[index].t, g_lnnAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.onlineNum);
    ++index;
    EXPECT_STREQ(params[index].name, g_lnnAssigners[index].name);
    EXPECT_EQ(params[index].t, g_lnnAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.peerDeviceAbility);
    ++index;
    EXPECT_STREQ(params[index].name, g_lnnAssigners[index].name);
    EXPECT_EQ(params[index].t, g_lnnAssigners[index].type);
    EXPECT_STREQ(params[index].v.s, extra.peerDeviceInfo);
    ++index;
    EXPECT_STREQ(params[index].name, g_lnnAssigners[index].name);
    EXPECT_EQ(params[index].t, g_lnnAssigners[index].type);
    char *anonyStr = NULL;
    Anonymize(extra.peerIp, &anonyStr);
    EXPECT_STREQ(params[index].v.s, anonyStr);
    AnonymizeFree(anonyStr);
    ++index;
    EXPECT_STREQ(params[index].name, g_lnnAssigners[index].name);
    EXPECT_EQ(params[index].t, g_lnnAssigners[index].type);
    Anonymize(extra.peerBrMac, &anonyStr);
    EXPECT_STREQ(params[index].v.s, anonyStr);
    AnonymizeFree(anonyStr);
    ++index;
    EXPECT_STREQ(params[index].name, g_lnnAssigners[index].name);
    EXPECT_EQ(params[index].t, g_lnnAssigners[index].type);
    Anonymize(extra.peerBleMac, &anonyStr);
    EXPECT_STREQ(params[index].v.s, anonyStr);
    AnonymizeFree(anonyStr);
    ++index;
    EXPECT_STREQ(params[index].name, g_lnnAssigners[index].name);
    EXPECT_EQ(params[index].t, g_lnnAssigners[index].type);
    Anonymize(extra.peerWifiMac, &anonyStr);
    EXPECT_STREQ(params[index].v.s, anonyStr);
    AnonymizeFree(anonyStr);
    ++index;
    EXPECT_STREQ(params[index].name, g_lnnAssigners[index].name);
    EXPECT_EQ(params[index].t, g_lnnAssigners[index].type);
    EXPECT_STREQ(params[index].v.s, extra.peerPort);
    ++index;
    EXPECT_STREQ(params[index].name, g_lnnAssigners[index].name);
    EXPECT_EQ(params[index].t, g_lnnAssigners[index].type);
    Anonymize(extra.peerUdid, &anonyStr);
    EXPECT_STREQ(params[index].v.s, anonyStr);
    AnonymizeFree(anonyStr);
    ++index;
    EXPECT_STREQ(params[index].name, g_lnnAssigners[index].name);
    EXPECT_EQ(params[index].t, g_lnnAssigners[index].type);
    Anonymize(extra.peerNetworkId, &anonyStr);
    EXPECT_STREQ(params[index].v.s, anonyStr);
    AnonymizeFree(anonyStr);
    ++index;
    EXPECT_STREQ(params[index].name, g_lnnAssigners[index].name);
    EXPECT_EQ(params[index].t, g_lnnAssigners[index].type);
    EXPECT_STREQ(params[index].v.s, extra.peerDeviceType);
    ++index;
    EXPECT_STREQ(params[index].name, g_lnnAssigners[index].name);
    EXPECT_EQ(params[index].t, g_lnnAssigners[index].type);
    EXPECT_STREQ(params[index].v.s, extra.callerPkg);
    ++index;
    EXPECT_STREQ(params[index].name, g_lnnAssigners[index].name);
    EXPECT_EQ(params[index].t, g_lnnAssigners[index].type);
    EXPECT_STREQ(params[index].v.s, extra.calleePkg);

    EXPECT_EQ(++index, validSize);
    return true;
}

MATCHER_P2(LnnInvalidParamArrayMatcher, inExtra, validSize, "lnn invalid param array match fail")
{
    const auto *params = static_cast<const HiSysEventParam *>(arg);
    params += SOFTBUS_ASSIGNER_SIZE; // Skip softbus params, they are matched by SoftbusParamArrayMatcher
    auto extra = static_cast<LnnEventExtra>(inExtra);
    int32_t index = 0;
    EXPECT_STREQ(params[index].name, g_lnnAssigners[index].name);
    EXPECT_EQ(params[index].t, g_lnnAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, ((extra.result < 0) ? (-extra.result) : extra.result));
    ++index;
    EXPECT_STREQ(params[index].name, g_lnnAssigners[index].name);
    EXPECT_EQ(params[index].t, g_lnnAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, ((extra.errcode < 0) ? (-extra.errcode) : extra.errcode));
    ++index;
    EXPECT_STREQ(params[index].name, g_lnnAssigners[index].name);
    EXPECT_EQ(params[index].t, g_lnnAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, ((extra.authId < 0) ? (-extra.authId) : extra.authId));
    EXPECT_EQ(++index, validSize);
    return true;
}

MATCHER_P2(LnnAuditValidParamArrayMatcher, inExtra, validSize, "lnn audit valid param array match fail")
{
    const auto *params = static_cast<const HiSysEventParam *>(arg);
    params += SOFTBUS_ASSIGNER_SIZE - 1; // Skip softbus params, they are matched by SoftbusParamArrayMatcher
    auto extra = static_cast<LnnAuditExtra>(inExtra);
    int32_t index = 0;
    EXPECT_STREQ(params[index].name, g_lnnAuditAssigners[index].name);
    EXPECT_EQ(params[index].t, g_lnnAuditAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.result);
    ++index;
    EXPECT_STREQ(params[index].name, g_lnnAuditAssigners[index].name);
    EXPECT_EQ(params[index].t, g_lnnAuditAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.errCode);
    ++index;
    EXPECT_STREQ(params[index].name, g_lnnAuditAssigners[index].name);
    EXPECT_EQ(params[index].t, g_lnnAuditAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.auditType);
    ++index;
    EXPECT_STREQ(params[index].name, g_lnnAuditAssigners[index].name);
    EXPECT_EQ(params[index].t, g_lnnAuditAssigners[index].type);
    EXPECT_EQ(params[index].v.ui64, extra.connId);
    ++index;
    EXPECT_STREQ(params[index].name, g_lnnAuditAssigners[index].name);
    EXPECT_EQ(params[index].t, g_lnnAuditAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.authLinkType);
    ++index;
    EXPECT_STREQ(params[index].name, g_lnnAuditAssigners[index].name);
    EXPECT_EQ(params[index].t, g_lnnAuditAssigners[index].type);
    EXPECT_EQ(params[index].v.ui32, extra.authRequestId);
    ++index;
    EXPECT_STREQ(params[index].name, g_lnnAuditAssigners[index].name);
    EXPECT_EQ(params[index].t, g_lnnAuditAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.onlineNum);
    ++index;
    EXPECT_STREQ(params[index].name, g_lnnAuditAssigners[index].name);
    EXPECT_EQ(params[index].t, g_lnnAuditAssigners[index].type);
    EXPECT_STREQ(params[index].v.s, extra.hostPkg);
    ++index;
    EXPECT_STREQ(params[index].name, g_lnnAuditAssigners[index].name);
    EXPECT_EQ(params[index].t, g_lnnAuditAssigners[index].type);
    EXPECT_STREQ(params[index].v.s, extra.localIp);
    ++index;
    EXPECT_STREQ(params[index].name, g_lnnAuditAssigners[index].name);
    EXPECT_EQ(params[index].t, g_lnnAuditAssigners[index].type);
    EXPECT_STREQ(params[index].v.s, extra.localBrMac);
    ++index;
    EXPECT_STREQ(params[index].name, g_lnnAuditAssigners[index].name);
    EXPECT_EQ(params[index].t, g_lnnAuditAssigners[index].type);
    EXPECT_STREQ(params[index].v.s, extra.localBleMac);
    ++index;
    EXPECT_STREQ(params[index].name, g_lnnAuditAssigners[index].name);
    EXPECT_EQ(params[index].t, g_lnnAuditAssigners[index].type);
    EXPECT_STREQ(params[index].v.s, extra.localUdid);
    ++index;
    EXPECT_STREQ(params[index].name, g_lnnAuditAssigners[index].name);
    EXPECT_EQ(params[index].t, g_lnnAuditAssigners[index].type);
    EXPECT_STREQ(params[index].v.s, extra.localNetworkId);
    ++index;
    EXPECT_STREQ(params[index].name, g_lnnAuditAssigners[index].name);
    EXPECT_EQ(params[index].t, g_lnnAuditAssigners[index].type);
    EXPECT_STREQ(params[index].v.s, extra.localDevName);
    ++index;
    EXPECT_STREQ(params[index].name, g_lnnAuditAssigners[index].name);
    EXPECT_EQ(params[index].t, g_lnnAuditAssigners[index].type);
    EXPECT_STREQ(params[index].v.s, extra.peerIp);
    ++index;
    EXPECT_STREQ(params[index].name, g_lnnAuditAssigners[index].name);
    EXPECT_EQ(params[index].t, g_lnnAuditAssigners[index].type);
    EXPECT_STREQ(params[index].v.s, extra.peerBrMac);
    ++index;
    EXPECT_STREQ(params[index].name, g_lnnAuditAssigners[index].name);
    EXPECT_EQ(params[index].t, g_lnnAuditAssigners[index].type);
    EXPECT_STREQ(params[index].v.s, extra.peerBleMac);
    ++index;
    EXPECT_STREQ(params[index].name, g_lnnAuditAssigners[index].name);
    EXPECT_EQ(params[index].t, g_lnnAuditAssigners[index].type);
    EXPECT_STREQ(params[index].v.s, extra.peerUdid);
    ++index;
    EXPECT_STREQ(params[index].name, g_lnnAuditAssigners[index].name);
    EXPECT_EQ(params[index].t, g_lnnAuditAssigners[index].type);
    EXPECT_STREQ(params[index].v.s, extra.peerNetworkId);
    ++index;
    EXPECT_STREQ(params[index].name, g_lnnAuditAssigners[index].name);
    EXPECT_EQ(params[index].t, g_lnnAuditAssigners[index].type);
    EXPECT_STREQ(params[index].v.s, extra.peerDevName);
    ++index;
    EXPECT_STREQ(params[index].name, g_lnnAuditAssigners[index].name);
    EXPECT_EQ(params[index].t, g_lnnAuditAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.localAuthPort);
    ++index;
    EXPECT_STREQ(params[index].name, g_lnnAuditAssigners[index].name);
    EXPECT_EQ(params[index].t, g_lnnAuditAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.localProxyPort);
    ++index;
    EXPECT_STREQ(params[index].name, g_lnnAuditAssigners[index].name);
    EXPECT_EQ(params[index].t, g_lnnAuditAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.localSessionPort);
    ++index;
    EXPECT_STREQ(params[index].name, g_lnnAuditAssigners[index].name);
    EXPECT_EQ(params[index].t, g_lnnAuditAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.localDevType);
    ++index;
    EXPECT_STREQ(params[index].name, g_lnnAuditAssigners[index].name);
    EXPECT_EQ(params[index].t, g_lnnAuditAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.peerAuthPort);
    ++index;
    EXPECT_STREQ(params[index].name, g_lnnAuditAssigners[index].name);
    EXPECT_EQ(params[index].t, g_lnnAuditAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.peerProxyPort);
    ++index;
    EXPECT_STREQ(params[index].name, g_lnnAuditAssigners[index].name);
    EXPECT_EQ(params[index].t, g_lnnAuditAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.peerSessionPort);
    ++index;
    EXPECT_STREQ(params[index].name, g_lnnAuditAssigners[index].name);
    EXPECT_EQ(params[index].t, g_lnnAuditAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.peerDevType);
    ++index;
    EXPECT_STREQ(params[index].name, g_lnnAuditAssigners[index].name);
    EXPECT_EQ(params[index].t, g_lnnAuditAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.attackTimes);
    ++index;
    EXPECT_STREQ(params[index].name, g_lnnAuditAssigners[index].name);
    EXPECT_EQ(params[index].t, g_lnnAuditAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, extra.beAttackedPort);

    EXPECT_EQ(++index, validSize);
    return true;
}

MATCHER_P2(LnnAuditInvalidParamArrayMatcher, inExtra, validSize, "lnn audit invalid param array match fail")
{
    const auto *params = static_cast<const HiSysEventParam *>(arg);
    params += SOFTBUS_ASSIGNER_SIZE; // Skip softbus params, they are matched by SoftbusParamArrayMatcher
    auto extra = static_cast<LnnAuditExtra>(inExtra);
    int32_t index = 0;
    EXPECT_STREQ(params[index].name, g_lnnAuditAssigners[index].name);
    EXPECT_EQ(params[index].t, g_lnnAuditAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, ((extra.result < 0) ? (-extra.result) : extra.result));
    ++index;
    EXPECT_STREQ(params[index].name, g_lnnAuditAssigners[index].name);
    EXPECT_EQ(params[index].t, g_lnnAuditAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, ((extra.errCode < 0) ? (-extra.errCode) : extra.errCode));
    EXPECT_EQ(++index, validSize);
    return true;
}
#endif // LNN_HISYSEVENT_MATCHER_H
