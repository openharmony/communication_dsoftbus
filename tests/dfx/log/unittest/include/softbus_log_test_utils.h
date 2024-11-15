/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef SOFTBUS_LOG_TEST_UTILS_H
#define SOFTBUS_LOG_TEST_UTILS_H

#include <string>

#include "softbus_log.h"

template <typename LABLE_TYPE>
void ExpectMatchSoftBusLogAttrs(const SoftBusLogLabel &attrs, LABLE_TYPE label, uint32_t domain,
    const std::string &tag)
{
    EXPECT_EQ(label, attrs.label);
    EXPECT_EQ(domain, attrs.domain);
    EXPECT_STREQ(tag.c_str(), attrs.tag);
}

#endif // SOFTBUS_LOG_TEST_UTILS_H
