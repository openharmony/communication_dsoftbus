/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>

#include "client_qos_manager.h"
#include "client_trans_session_service.h"
#include "session.h"
#include "softbus_error_code.h"

using namespace testing::ext;

namespace OHOS {
const int32_t G_VALID_SESSION_ID = 1;
const int32_t G_INVALID_SESSION_ID = 1;
const int32_t G_VALID_APP_TYPE = 1;
const int32_t G_VALID_QUALITY = 1;

class TransQosTest : public testing::Test {
public:
    TransQosTest()
    {}
    ~TransQosTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void TransQosTest::SetUpTestCase(void)
{}

void TransQosTest::TearDownTestCase(void)
{}

/**
 * @tc.name: TransQosTest001
 * @tc.desc: test the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransQosTest, QosReportTest001, TestSize.Level0)
{
    int32_t ret;
    ret = QosReport(G_INVALID_SESSION_ID, G_VALID_APP_TYPE, QOS_IMPROVE);
    EXPECT_NE(ret, SOFTBUS_OK);

    ret = QosReport(G_VALID_SESSION_ID, G_VALID_APP_TYPE, QOS_RECOVER);
    EXPECT_NE(ret, SOFTBUS_OK);

    ret = QosReport(G_VALID_SESSION_ID, G_VALID_APP_TYPE, QOS_IMPROVE);
    EXPECT_NE(ret, SOFTBUS_OK);

    ret = ClientQosReport(G_VALID_SESSION_ID, G_VALID_APP_TYPE, QOS_IMPROVE, G_VALID_QUALITY);
    EXPECT_NE(ret, SOFTBUS_NOT_IMPLEMENT);
}
} // namespace OHOS