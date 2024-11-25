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

#include <cstring>
#include <fcntl.h>

#include "bus_center_adapter.h"
#include "lnn_ip_utils_adapter.h"
#include "softbus_adapter_file.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "gtest/gtest.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
const char *g_FileName = "example.txt";

class DsoftbusOtherTest : public testing::Test {
protected:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};
void DsoftbusOtherTest::SetUpTestCase(void) { }
void DsoftbusOtherTest::TearDownTestCase(void)
{
    int32_t ret = remove(g_FileName);
    if (ret == 0) {
        return;
    }
}
void DsoftbusOtherTest::SetUp(void) { }
void DsoftbusOtherTest::TearDown(void) { }

/*
 * @tc.name: GetCommonDevInfoTest001
 * @tc.desc: value is nullptr
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(DsoftbusOtherTest, GetCommonDevInfo001, TestSize.Level0)
{
    char value[] = "abcdefg";
    int32_t len = 10;
    int32_t ret = GetCommonDevInfo(COMM_DEVICE_KEY_DEVTYPE, value, len);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = GetCommonDevInfo(COMM_DEVICE_KEY_BT_MAC, value, len);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = GetCommonDevInfo(COMM_DEVICE_KEY_BUTT, value, len);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: GetCommonDevInfoTest002
 * @tc.desc: value is nullptr
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(DsoftbusOtherTest, GetCommonDevInfo002, TestSize.Level0)
{
    int32_t len = 10;
    int32_t ret = GetCommonDevInfo(COMM_DEVICE_KEY_DEVNAME, NULL, len);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = GetCommonDevInfo(COMM_DEVICE_KEY_UDID, NULL, len);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = GetCommonDevInfo(COMM_DEVICE_KEY_DEVTYPE, NULL, len);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = GetCommonDevInfo(COMM_DEVICE_KEY_BT_MAC, NULL, len);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = GetCommonDevInfo(COMM_DEVICE_KEY_BUTT, NULL, len);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: GetCommonDevInfoTest003
 * @tc.desc: len is illegal
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(DsoftbusOtherTest, GetCommonDevInfo003, TestSize.Level0)
{
    char value[] = "abcdefg";
    int32_t len = 0;
    int32_t ret = GetCommonDevInfo(COMM_DEVICE_KEY_DEVNAME, value, len);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = GetCommonDevInfo(COMM_DEVICE_KEY_UDID, value, len);
    EXPECT_EQ(SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR, ret);
}

/*
 * @tc.name: GetCommonDevInfoTest004
 * @tc.desc: value is illegal
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(DsoftbusOtherTest, GetCommonDevInfo004, TestSize.Level0)
{
    char value[] = "abcdefg";
    int32_t len = 10;
    int32_t ret = GetCommonDevInfo(COMM_DEVICE_KEY_DEVNAME, value, len);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = GetCommonDevInfo(COMM_DEVICE_KEY_UDID, value, len);
    EXPECT_EQ(SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR, ret);
}
} // namespace OHOS
