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

#ifndef SOFTBUS_HISYSEVENT_MATCHER_H
#define SOFTBUS_HISYSEVENT_MATCHER_H

#include <gmock/gmock.h>

#include "convert/softbus_event_converter.h"
#include "hisysevent_c.h"
#include "softbus_event.h"

MATCHER_P(ParamArraySizeMatcher, formSize, "param array size match fail")
{
    auto paramSize = static_cast<int>(arg);
    EXPECT_EQ(paramSize, (formSize + SOFTBUS_ASSIGNER_SIZE));
    return true;
}

MATCHER_P2(SoftbusParamArrayMatcher, inForm, validSize, "softbus param array match fail")
{
    const auto *params = static_cast<const HiSysEventParam *>(arg);
    auto form = static_cast<SoftbusEventForm>(inForm);
    int32_t index = 0;
    EXPECT_STREQ(params[index].name, g_softbusAssigners[index].name);
    EXPECT_EQ(params[index].t, g_softbusAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, form.scene);
    ++index;
    EXPECT_STREQ(params[index].name, g_softbusAssigners[index].name);
    EXPECT_EQ(params[index].t, g_softbusAssigners[index].type);
    EXPECT_EQ(params[index].v.i32, form.stage);
    ++index;
    EXPECT_STREQ(params[index].name, g_softbusAssigners[index].name);
    EXPECT_EQ(params[index].t, g_softbusAssigners[index].type);
    EXPECT_STREQ(params[index].v.s, SOFTBUS_EVENT_PKG_NAME);
    ++index;
    EXPECT_STREQ(params[index].name, g_softbusAssigners[index].name);
    EXPECT_EQ(params[index].t, g_softbusAssigners[index].type);
    EXPECT_STREQ(params[index].v.s, form.func);
    EXPECT_EQ(++index, validSize);
    return true;
}
#endif // SOFTBUS_HISYSEVENT_MATCHER_H
