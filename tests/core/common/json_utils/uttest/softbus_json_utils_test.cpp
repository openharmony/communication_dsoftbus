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

#include <securec.h>
#include "cJSON.h"
#include "gtest/gtest.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "softbus_json_utils.h"

#define ARRAY_LEN 10
#define INPUT_NUM 123
#define DOUBLE_NUM 123.456

using namespace testing;
using namespace testing::ext;

namespace OHOS {

class SoftbusJsonUtilsTest : public testing::Test {
public:
    SoftbusJsonUtilsTest()
    {}
    ~SoftbusJsonUtilsTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void SoftbusJsonUtilsTest::SetUpTestCase(void) { }

void SoftbusJsonUtilsTest::TearDownTestCase(void) { }

/**
 * @tc.name: NullJsonTest
 * @tc.desc: When the json parameter is NULL, the return value is SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusJsonUtilsTest, GetStringItemByJsonObject001, TestSize.Level1)
{
    char target[ARRAY_LEN];
    int32_t ret = GetStringItemByJsonObject(NULL, "string", target, ARRAY_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: NullStringTest
 * @tc.desc: When the string parameter is NULL, the return value is SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusJsonUtilsTest, GetStringItemByJsonObject002, TestSize.Level1)
{
    cJSON *json = cJSON_CreateObject();
    char target[ARRAY_LEN];
    int32_t ret = GetStringItemByJsonObject(json, NULL, target, ARRAY_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    cJSON_Delete(json);
}

/**
 * @tc.name: NullStringTest
 * @tc.desc: When the target parameter is NULL, the return value is SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusJsonUtilsTest, GetStringItemByJsonObject003, TestSize.Level1)
{
    cJSON *json = cJSON_CreateObject();
    int32_t ret = GetStringItemByJsonObject(json, "string", NULL, ARRAY_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    cJSON_Delete(json);
}

/**
 * @tc.name: InvalidStringTest
 * @tc.desc: Test returns SOFTBUS_ERR when the specified string does not exist in the json object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusJsonUtilsTest, GetStringItemByJsonObject004, TestSize.Level1)
{
    cJSON *json = cJSON_CreateObject();
    char target[ARRAY_LEN];
    int32_t ret = GetStringItemByJsonObject(json, "string", target, ARRAY_LEN);
    EXPECT_EQ(ret, SOFTBUS_ERR);
    cJSON_Delete(json);
}

/**
 * @tc.name: StringTooLongTest
 * @tc.desc: Returns SOFTBUS_INVALID_PARAM when the string length in the json object is greater than the targetLen
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusJsonUtilsTest, GetStringItemByJsonObject005, TestSize.Level1)
{
    cJSON *json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "string",
        "This is a very long string that is definitely too long to fit in the target buffer.");
    char target[ARRAY_LEN];
    int32_t ret = GetStringItemByJsonObject(json, "string", target, ARRAY_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    cJSON_Delete(json);
}

/**
 * @tc.name: SuccessTest
 * @tc.desc: Returns SOFTBUS_INVALID_PARAM when the string length in the json object is greater than the targetLen
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusJsonUtilsTest, GetStringItemByJsonObject006, TestSize.Level1)
{
    cJSON *json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "string", "short");
    char target[ARRAY_LEN];
    int32_t ret = GetStringItemByJsonObject(json, "string", target, ARRAY_LEN);
    EXPECT_EQ(ret, SOFTBUS_OK);
    cJSON_Delete(json);
}

/**
 * @tc.name: NullJsonTest
 * @tc.desc: Returns false if json parameter is NULL
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusJsonUtilsTest, GetJsonObjectSignedNumberItem001, TestSize.Level1)
{
    int32_t target;
    bool ret = GetJsonObjectSignedNumberItem(NULL, "test", &target);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: NullStringTest
 * @tc.desc: Returns false if string argument is NULL
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusJsonUtilsTest, GetJsonObjectSignedNumberItem002, TestSize.Level1)
{
    cJSON *json = cJSON_CreateObject();
    int32_t target;
    bool ret = GetJsonObjectSignedNumberItem(json, "test", &target);
    EXPECT_FALSE(ret);
    cJSON_Delete(json);
}

/**
 * @tc.name: NullTargetTest
 * @tc.desc: Returns false if target argument is NULL
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusJsonUtilsTest, GetJsonObjectSignedNumberItem003, TestSize.Level1)
{
    cJSON *json = cJSON_CreateObject();
    bool ret = GetJsonObjectSignedNumberItem(json, "test", NULL);
    EXPECT_FALSE(ret);
    cJSON_Delete(json);
}

/**
 * @tc.name: InvalidStringTest
 * @tc.desc: Returns false if the entry specified by string does not exist for the json object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusJsonUtilsTest, GetJsonObjectSignedNumberItem004, TestSize.Level1)
{
    cJSON *json = cJSON_CreateObject();
    int32_t target;
    bool ret = GetJsonObjectSignedNumberItem(json, "test", &target);
    EXPECT_FALSE(ret);
    cJSON_Delete(json);
}

/**
 * @tc.name: ValidStringTest
 * @tc.desc: Returns success when the item specified by the string parameter exists in the json object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusJsonUtilsTest, GetJsonObjectSignedNumberItem005, TestSize.Level1)
{
    cJSON *json = cJSON_CreateObject();
    cJSON_AddNumberToObject(json, "test", INPUT_NUM);
    int32_t target;
    bool ret = GetJsonObjectSignedNumberItem(json, "test", &target);
    EXPECT_TRUE(ret);
    EXPECT_DOUBLE_EQ(target, INPUT_NUM);
    cJSON_Delete(json);
}

/**
 * @tc.name: NullJsonTest
 * @tc.desc: Returns false if json parameter is NULL
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusJsonUtilsTest, GetJsonObjectDoubleItem001, TestSize.Level1)
{
    double target;
    bool ret = GetJsonObjectDoubleItem(NULL, "test", &target);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: NullStringTest
 * @tc.desc: Returns false if string parameter is NULL
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusJsonUtilsTest, GetJsonObjectDoubleItem002, TestSize.Level1)
{
    cJSON *json = cJSON_CreateObject();
    double target;
    bool ret = GetJsonObjectDoubleItem(json, NULL, &target);
    EXPECT_FALSE(ret);
    cJSON_Delete(json);
}

/**
 * @tc.name: NullTargetTest
 * @tc.desc: Returns false if target parameter is NULL
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusJsonUtilsTest, GetJsonObjectDoubleItem003, TestSize.Level1)
{
    cJSON *json = cJSON_CreateObject();
    bool ret = GetJsonObjectDoubleItem(json, "test", NULL);
    EXPECT_FALSE(ret);
    cJSON_Delete(json);
}

/**
 * @tc.name: InvalidStringTest
 * @tc.desc: Returns false if the entry specified by string does not exist for the json object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusJsonUtilsTest, GetJsonObjectDoubleItem004, TestSize.Level1)
{
    cJSON *json = cJSON_CreateObject();
    double target;
    bool ret = GetJsonObjectDoubleItem(json, "test", &target);
    EXPECT_FALSE(ret);
    cJSON_Delete(json);
}

/**
 * @tc.name: ValidStringTest
 * @tc.desc: Returns success when the item specified by the string parameter exists in the json object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusJsonUtilsTest, GetJsonObjectDoubleItem005, TestSize.Level1)
{
    cJSON *json = cJSON_CreateObject();
    cJSON_AddNumberToObject(json, "test", DOUBLE_NUM);
    double target;
    bool ret = GetJsonObjectDoubleItem(json, "test", &target);
    EXPECT_TRUE(ret);
    EXPECT_DOUBLE_EQ(target, DOUBLE_NUM);
    cJSON_Delete(json);
}

/**
 * @tc.name: NullJsonTest
 * @tc.desc: Returns false if json parameter is NULL
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusJsonUtilsTest, GetJsonObjectNumber64Item001, TestSize.Level1)
{
    int64_t target;
    bool ret = GetJsonObjectNumber64Item(NULL, "test", &target);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: NullStringTest
 * @tc.desc: Returns false if string parameter is NULL
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusJsonUtilsTest, GetJsonObjectNumber64Item002, TestSize.Level1)
{
    cJSON *json = cJSON_CreateObject();
    int64_t target;
    bool ret = GetJsonObjectNumber64Item(json, NULL, &target);
    EXPECT_FALSE(ret);
    cJSON_Delete(json);
}

/**
 * @tc.name: NullTargetTest
 * @tc.desc: Returns false if target parameter is NULL
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusJsonUtilsTest, GetJsonObjectNumber64Item003, TestSize.Level1)
{
    cJSON *json = cJSON_CreateObject();
    bool ret = GetJsonObjectNumber64Item(json, "test", NULL);
    EXPECT_FALSE(ret);
    cJSON_Delete(json);
}

/**
 * @tc.name: InvalidStringTest
 * @tc.desc: Returns false if the entry specified by string does not exist for the json object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusJsonUtilsTest, GetJsonObjectNumber64Item004, TestSize.Level1)
{
    cJSON *json = cJSON_CreateObject();
    int64_t target;
    bool ret = GetJsonObjectNumber64Item(json, "test", &target);
    EXPECT_FALSE(ret);
    cJSON_Delete(json);
}

/**
 * @tc.name: ValidStringTest
 * @tc.desc: Returns success when the item specified by the string parameter exists in the json object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusJsonUtilsTest, GetJsonObjectNumber64Item005, TestSize.Level1)
{
    int64_t target;
    cJSON *json = cJSON_CreateObject();
    cJSON_AddNumberToObject(json, "test", -1.0); // -1.0 is test value
    bool ret = GetJsonObjectNumber64Item(json, "test", &target);
    EXPECT_FALSE(ret);
    cJSON_Delete(json);
}

/**
 * @tc.name: ValidStringTest
 * @tc.desc: Returns success when the item specified by the string parameter exists in the json object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusJsonUtilsTest, GetJsonObjectNumber64Item006, TestSize.Level1)
{
    int64_t target;
    cJSON *json = cJSON_CreateObject();
    cJSON_AddNumberToObject(json, "test", 1.0); // -1.0 is test value
    bool ret = GetJsonObjectNumber64Item(json, "test", &target);
    EXPECT_TRUE(ret);
    EXPECT_EQ(1, target);
    cJSON_Delete(json);
}

/**
 * @tc.name: NullJsonTest
 * @tc.desc: When the json parameter is NULL, the return value is SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusJsonUtilsTest, GetJsonObjectSignedNumber64Item001, TestSize.Level1)
{
    int64_t target;
    bool ret = GetJsonObjectSignedNumber64Item(NULL, "test", &target);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: NullStringTest
 * @tc.desc: When the string parameter is NULL, the return value is SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusJsonUtilsTest, GetJsonObjectSignedNumber64Item002, TestSize.Level1)
{
    int64_t target;
    cJSON *json = cJSON_CreateObject();
    bool ret = GetJsonObjectSignedNumber64Item(json, NULL, &target);
    EXPECT_FALSE(ret);
    cJSON_Delete(json);
}

/**
 * @tc.name: NullTargetTest
 * @tc.desc: When the target parameter is NULL, the return value is SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusJsonUtilsTest, GetJsonObjectSignedNumber64Item003, TestSize.Level1)
{
    cJSON *json = cJSON_CreateObject();
    bool ret = GetJsonObjectSignedNumber64Item(json, "test", NULL);
    EXPECT_FALSE(ret);
    cJSON_Delete(json);
}

/**
 * @tc.name: InvalidStringTest
 * @tc.desc: Test returns false when the specified string does not exist in the json object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusJsonUtilsTest, GetJsonObjectSignedNumber64Item004, TestSize.Level1)
{
    int64_t target;
    cJSON *json = cJSON_CreateObject();
    bool ret = GetJsonObjectSignedNumber64Item(json, "test", &target);
    EXPECT_FALSE(ret);
    cJSON_Delete(json);
}

/**
 * @tc.name: ValidString
 * @tc.desc: Returns true when the string length in the json object is greater than the targetLen
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusJsonUtilsTest, GetJsonObjectSignedNumber64Item005, TestSize.Level1)
{
    int64_t target;
    cJSON *json = cJSON_CreateObject();
    cJSON_AddNumberToObject(json, "test", 123456789012345); // 123456789012345 is test value
    bool ret = GetJsonObjectSignedNumber64Item(json, "test", &target);
    EXPECT_TRUE(ret);
    EXPECT_EQ(target, 123456789012345); // 123456789012345 is test value
    cJSON_Delete(json);
}

/**
 * @tc.name: NullJsonTest
 * @tc.desc: Returns false if json parameter is NULL
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusJsonUtilsTest, GetJsonObjectBoolItem001, TestSize.Level1)
{
    bool result;
    bool ret = GetJsonObjectBoolItem(NULL, "test", &result);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: NullStringTest
 * @tc.desc: Returns false if string parameter is NULL
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusJsonUtilsTest, GetJsonObjectBoolItem002, TestSize.Level1)
{
    bool result;
    cJSON *json = cJSON_CreateObject();
    bool ret = GetJsonObjectBoolItem(json, NULL, &result);
    EXPECT_FALSE(ret);
    cJSON_Delete(json);
}

/**
 * @tc.name: NullTargetTest
 * @tc.desc: Returns false if target parameter is NULL
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusJsonUtilsTest, GetJsonObjectBoolItem003, TestSize.Level1)
{
    cJSON *json = cJSON_CreateObject();
    bool ret = GetJsonObjectBoolItem(json, "test", NULL);
    EXPECT_FALSE(ret);
    cJSON_Delete(json);
}

/**
 * @tc.name: InvalidStringTest
 * @tc.desc: Returns false if the entry specified by string does not exist for the json object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusJsonUtilsTest, GetJsonObjectBoolItem004, TestSize.Level1)
{
    bool result;
    cJSON *json = cJSON_CreateObject();
    bool ret = GetJsonObjectBoolItem(json, "test", &result);
    EXPECT_FALSE(ret);
    cJSON_Delete(json);
}

/**
 * @tc.name: NullJsonTest
 * @tc.desc: When the json parameter is NULL, the return value is SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusJsonUtilsTest, AddNumber64ToJsonObject001, TestSize.Level1)
{
    int64_t num = 1234567890; // 1234567890 is test value
    const char *string = "test";
    bool ret = AddNumber64ToJsonObject(NULL, string, num);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: NullStringTest
 * @tc.desc: When the string parameter is NULL, the return value is SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusJsonUtilsTest, AddNumber64ToJsonObject002, TestSize.Level1)
{
    cJSON *json = cJSON_CreateObject();
    int64_t num = 1234567890; // 1234567890 is test value
    bool ret = AddNumber64ToJsonObject(json, NULL, num);
    EXPECT_FALSE(ret);
    cJSON_Delete(json);
}

/**
 * @tc.name: NullTargetTest
 * @tc.desc: When the target parameter is NULL, the return value is SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusJsonUtilsTest, AddNumber64ToJsonObject003, TestSize.Level1)
{
    cJSON *json = cJSON_CreateObject();
    int64_t num = 1234567890; // 1234567890 is test value
    const char *string = "test";
    bool ret = AddNumber64ToJsonObject(json, string, num);
    EXPECT_TRUE(ret);
    cJSON *item = cJSON_GetObjectItem(json, string);
    EXPECT_NE(item, NULL);
    EXPECT_EQ(item->type, cJSON_Number);
    EXPECT_EQ(item->valuedouble, num);
    cJSON_Delete(json);
}

/**
 * @tc.name: NullJsonTest
 * @tc.desc: Returns false if json parameter is NULL
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusJsonUtilsTest, AddBoolToJsonObject001, TestSize.Level1)
{
    bool ret = AddBoolToJsonObject(NULL, "key", true);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: NullStringTest
 * @tc.desc: Returns false if string parameter is NULL
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusJsonUtilsTest, AddBoolToJsonObject002, TestSize.Level1)
{
    cJSON *json = cJSON_CreateObject();
    bool ret = AddBoolToJsonObject(json, NULL, true);
    EXPECT_FALSE(ret);
    cJSON_Delete(json);
}

/**
 * @tc.name: NullTargetTest
 * @tc.desc: Returns false if target parameter is NULL
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusJsonUtilsTest, AddBoolToJsonObject003, TestSize.Level1)
{
    cJSON *json = cJSON_CreateObject();
    bool ret = AddBoolToJsonObject(json, "key", true);
    EXPECT_TRUE(ret);
    cJSON_Delete(json);
}

/**
 * @tc.name: InvalidStringTest
 * @tc.desc: Returns false when cJSON_AddItemToObject returns false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusJsonUtilsTest, AddBoolToJsonObject004, TestSize.Level1)
{
    cJSON *json = cJSON_CreateObject();
    cJSON *item = cJSON_CreateBool(true);
    cJSON_AddItemToObject(json, "key", item);
    bool ret = AddBoolToJsonObject(json, "key", true);
    EXPECT_TRUE(ret);
    cJSON_Delete(json);
}

/**
 * @tc.name: ValidStringTest
 * @tc.desc: Returns success when the item specified by the string parameter exists in the json object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusJsonUtilsTest, AddBoolToJsonObject005, TestSize.Level1)
{
    cJSON *json = cJSON_CreateObject();
    bool ret = AddBoolToJsonObject(json, "key", true);
    EXPECT_TRUE(ret);
    cJSON_Delete(json);
}

/**
 * @tc.name: NullJsonTest
 * @tc.desc: When the json parameter is NULL, the return value is SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusJsonUtilsTest, GetDynamicStringItemByJsonObject001, TestSize.Level1)
{
    const char *string = "test";
    uint32_t limit = ARRAY_LEN;
    char *result = GetDynamicStringItemByJsonObject(NULL, string, limit);
    ASSERT_EQ(result, NULL);
}

/**
 * @tc.name: NullStringTest
 * @tc.desc: When the string parameter is NULL, the return value is SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusJsonUtilsTest, GetDynamicStringItemByJsonObject002, TestSize.Level1)
{
    cJSON *json = cJSON_CreateObject();
    uint32_t limit = ARRAY_LEN;
    char *result = GetDynamicStringItemByJsonObject(json, NULL, limit);
    ASSERT_EQ(result, NULL);
    cJSON_Delete(json);
}

/**
 * @tc.name: NullStringTest
 * @tc.desc: When the target parameter is NULL, the return value is SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusJsonUtilsTest, GetDynamicStringItemByJsonObject003, TestSize.Level1)
{
    cJSON *json = cJSON_CreateObject();
    const char *string = "test";
    uint32_t limit = ARRAY_LEN;
    char *result = GetDynamicStringItemByJsonObject(json, string, limit);
    ASSERT_EQ(result, NULL);
    cJSON_Delete(json);
}

/**
 * @tc.name: InvalidStringTest
 * @tc.desc: Test returns SOFTBUS_ERR when the specified string does not exist in the json object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusJsonUtilsTest, GetDynamicStringItemByJsonObject004, TestSize.Level1)
{
    cJSON *json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "test", "This is a test string");
    const char *string = "test";
    uint32_t limit = 5; // 5 is value
    char *result = GetDynamicStringItemByJsonObject(json, string, limit);
    ASSERT_EQ(result, NULL);
    cJSON_Delete(json);
}

/**
 * @tc.name: StringTooLongTest
 * @tc.desc: Returns SOFTBUS_INVALID_PARAM when the string length in the json object is greater than the targetLen
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusJsonUtilsTest, GetDynamicStringItemByJsonObject005, TestSize.Level1)
{
    cJSON *json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "test", "This is a test string.");
    const char *string = "test";
    uint32_t limit = 20; // 20 is test value
    char *result = GetDynamicStringItemByJsonObject(json, string, limit);
    ASSERT_STREQ(result, NULL);
    cJSON_Delete(json);
    SoftBusFree(result);
}

/**
 * @tc.name: NullJsonTest
 * @tc.desc: When the json parameter is NULL, the return value is SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusJsonUtilsTest, AddIntArrayToJsonObject001, TestSize.Level1)
{
    const char *string = "test";
    int32_t array[] = {1, 2, 3}; // 1, 2, 3 are test values
    int32_t arrayLen = 3; // 3 is test value
    bool result = AddIntArrayToJsonObject(NULL, string, array, arrayLen);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: NullStringTest
 * @tc.desc: When the string parameter is NULL, the return value is SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusJsonUtilsTest, AddIntArrayToJsonObject002, TestSize.Level1)
{
    cJSON *json = cJSON_CreateObject();
    int32_t array[] = {1, 2, 3}; // 1, 2, 3 are test values
    int32_t arrayLen = 3; // 3 is test value
    bool result = AddIntArrayToJsonObject(json, NULL, array, arrayLen);
    EXPECT_FALSE(result);
    cJSON_Delete(json);
}

/**
 * @tc.name: NullStringTest
 * @tc.desc: When the target parameter is NULL, the return value is SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusJsonUtilsTest, AddIntArrayToJsonObject003, TestSize.Level1)
{
    cJSON *json = cJSON_CreateObject();
    const char *string = "test";
    int32_t arrayLen = 3; // 3 is test value
    bool result = AddIntArrayToJsonObject(json, string, NULL, arrayLen);
    EXPECT_FALSE(result);
    cJSON_Delete(json);
}

/**
 * @tc.name: InvalidStringTest
 * @tc.desc: Test returns SOFTBUS_ERR when the specified string does not exist in the json object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusJsonUtilsTest, AddIntArrayToJsonObject004, TestSize.Level1)
{
    cJSON *json = cJSON_CreateObject();
    const char *string = "test";
    int32_t array[] = {1, 2, 3}; // 1, 2, 3 are test values
    int32_t arrayLen = 0;
    bool result = AddIntArrayToJsonObject(json, string, array, arrayLen);
    EXPECT_FALSE(result);
    cJSON_Delete(json);
}

/**
 * @tc.name: StringTooLongTest
 * @tc.desc: Returns SOFTBUS_INVALID_PARAM when the string length in the json object is greater than the targetLen
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusJsonUtilsTest, AddIntArrayToJsonObject005, TestSize.Level1)
{
    cJSON *json = cJSON_CreateObject();
    const char *string = "test";
    int32_t array[] = {1, 2, 3}; // 1, 2, 3 are test values
    int32_t arrayLen = 3; // 3 is test value
    bool result = AddIntArrayToJsonObject(json, string, array, arrayLen);
    EXPECT_TRUE(result);
    cJSON_Delete(json);
}

/**
 * @tc.name: NullJsonTest
 * @tc.desc: When the json parameter is NULL, the return value is SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusJsonUtilsTest, GetJsonObjectIntArrayItem001, TestSize.Level1)
{
    int32_t array[ARRAY_LEN];
    bool result = GetJsonObjectIntArrayItem(NULL, "string", array, ARRAY_LEN);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: NullStringTest
 * @tc.desc: When the string parameter is NULL, the return value is SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusJsonUtilsTest, GetJsonObjectIntArrayItem002, TestSize.Level1)
{
    cJSON *json = cJSON_CreateObject();
    int32_t array[ARRAY_LEN];
    bool result = GetJsonObjectIntArrayItem(json, NULL, array, ARRAY_LEN);
    EXPECT_FALSE(result);
    cJSON_Delete(json);
}

/**
 * @tc.name: NullStringTest
 * @tc.desc: When the target parameter is NULL, the return value is SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusJsonUtilsTest, GetJsonObjectIntArrayItem003, TestSize.Level1)
{
    cJSON *json = cJSON_CreateObject();
    bool result = GetJsonObjectIntArrayItem(NULL, "string", NULL, ARRAY_LEN);
    EXPECT_FALSE(result);
    cJSON_Delete(json);
}

/**
 * @tc.name: InvalidStringTest
 * @tc.desc: Test returns SOFTBUS_ERR when the specified string does not exist in the json object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusJsonUtilsTest, GetJsonObjectIntArrayItem004, TestSize.Level1)
{
    cJSON *json = cJSON_CreateObject();
    int32_t array[ARRAY_LEN];
    bool result = GetJsonObjectIntArrayItem(json, "string", array, 0);
    EXPECT_FALSE(result);
    cJSON_Delete(json);
}

/**
 * @tc.name: StringTooLongTest
 * @tc.desc: Returns SOFTBUS_INVALID_PARAM when the string length in the json object is greater than the targetLen
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusJsonUtilsTest, GetJsonObjectIntArrayItem005, TestSize.Level1)
{
    cJSON *json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "string", "not an array");
    int32_t array[ARRAY_LEN];
    bool result = GetJsonObjectIntArrayItem(json, "string", array, ARRAY_LEN);
    EXPECT_FALSE(result);
    cJSON_Delete(json);
}

/**
 * @tc.name: SuccessTest
 * @tc.desc: Returns SOFTBUS_INVALID_PARAM when the string length in the json object is greater than the targetLen
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusJsonUtilsTest, GetJsonObjectIntArrayItem006, TestSize.Level1)
{
    cJSON *json = cJSON_CreateObject();
    cJSON *array = cJSON_CreateArray();
    cJSON_AddItemToArray(array, cJSON_CreateNumber(1));
    cJSON_AddItemToArray(array, cJSON_CreateNumber(2));
    cJSON_AddItemToObject(json, "string", array);
    int32_t result[ARRAY_LEN];
    bool ret = GetJsonObjectIntArrayItem(json, "string", result, ARRAY_LEN);
    EXPECT_TRUE(ret);
    EXPECT_EQ(1, result[0]); // 1 0 is test value
    EXPECT_EQ(2, result[1]); // 2 1 is test value
    cJSON_Delete(json);
}

}