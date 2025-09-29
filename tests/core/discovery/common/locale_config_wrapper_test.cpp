/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "parameter_mock.h"
#include "disc_log.h"
#include "locale_config_wrapper.h"

using namespace testing::ext;
using testing::_;
using testing::NiceMock;
using testing::NotNull;
using testing::Return;

namespace OHOS {
class LocaleConfigWrapperTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
    }

    static void TearDownTestCase()
    {
    }

    void SetUp() override { }
    void TearDown() override { }
};

/*
 * @tc.name: IsZHLanguage001
 * @tc.desc: The language was successfully obtained for the first time
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocaleConfigWrapperTest, IsZHLanguage001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "IsZHLanguage001 begin ----");
    ParameterMock parameterMock;

    EXPECT_CALL(parameterMock, GetParameter).WillOnce(ParameterMock::ActionOfGetParameter2);
    EXPECT_EQ(true, IsZHLanguage());

    EXPECT_CALL(parameterMock, GetParameter).WillOnce(ParameterMock::ActionOfGetParameter3);
    EXPECT_EQ(true, IsZHLanguage());
    DISC_LOGI(DISC_TEST, "IsZHLanguage001 end ----");
}

/*
 * @tc.name: IsZHLanguage002
 * @tc.desc: The first attempt failed, but the second attempt was successful
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocaleConfigWrapperTest, IsZHLanguage002, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "IsZHLanguage002 begin ----");
    ParameterMock parameterMock;

    EXPECT_CALL(parameterMock, GetParameter).WillOnce(ParameterMock::ActionOfGetParameter1)
                                            .WillRepeatedly(ParameterMock::ActionOfGetParameter2);
    
    EXPECT_EQ(true, IsZHLanguage());
    DISC_LOGI(DISC_TEST, "IsZHLanguage002 end ----");
}

/*
 * @tc.name: IsZHLanguage003
 * @tc.desc: The first attempt was successful, but not Chinese
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocaleConfigWrapperTest, IsZHLanguage003, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "IsZHLanguage003 begin ----");
    ParameterMock parameterMock;

    EXPECT_CALL(parameterMock, GetParameter).WillOnce(ParameterMock::ActionOfGetParameter4);
    
    EXPECT_EQ(false, IsZHLanguage());
    DISC_LOGI(DISC_TEST, "IsZHLanguage003 end ----");
}

} // namespace OHOS