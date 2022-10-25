/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include <unistd.h>
#include "disc_nstackx_adapter.c"

using namespace testing::ext;
namespace OHOS {
class DiscNstackxAdapterTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override {}
    void TearDown() override {}
};

/*
* @tc.name: testParseServiceData001
* @tc.desc: test ParseServiceData
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscNstackxAdapterTest, testParseServiceData001, TestSize.Level1)
{
    cJSON *jsonObject = cJSON_CreateObject();
    bool ret = AddStringToJsonObject(jsonObject, JSON_SERVICE_DATA, "port:-10");
    EXPECT_EQ(ret, true);
    if (!ret) {
        cJSON_Delete(jsonObject);
        return;
    }

    DeviceInfo deviceInfo;
    ParseServiceData(jsonObject, &deviceInfo);
    cJSON_Delete(jsonObject);
}
}