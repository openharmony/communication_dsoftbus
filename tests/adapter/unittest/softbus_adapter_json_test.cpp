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

#include "gtest/gtest.h"

#include <cstddef>
#include <cstdint>
#include <securec.h>
#include <string.h>

#include "softbus_adapter_json.h"
#include "softbus_adapter_mem.h"

using namespace testing::ext;

namespace {
// JsonObj is a public POD struct { void *context; }. Building one with a null
// context lets us reach every `json == nullptr` branch in the adapter without
// any memory mocking.
JsonObj MakeNullContextObj()
{
    JsonObj obj;
    obj.context = nullptr;
    return obj;
}

// Compile-time element count of a fixed-size array, used in assertions instead
// of repeating the literal element count.
template <typename T, std::size_t N>
constexpr std::size_t ArraySize(const T (&)[N])
{
    return N;
}

// ---- Keys reused across cases --------------------------------------------
constexpr char KEY_BOOL[] = "bool_key";
constexpr char KEY_INT[] = "int_key";
constexpr char KEY_STR[] = "str_key";
constexpr char KEY_ARR[] = "arr_key";
constexpr char KEY_BYTES[] = "bytes_key";
constexpr char KEY_MISSING[] = "missing_key";

// ---- Lifecycle -----------------------------------------------------------
constexpr int32_t CREATE_REPEAT_COUNT = 16;  // create/free repetitions for leak check
constexpr uint32_t FREE_BUF_SIZE = 32;       // scratch buffer handed to JSON_Free

// ---- Buffer capacities ---------------------------------------------------
constexpr uint32_t BUF_SIZE_SMALL = 8;       // bytes, for short string reads
constexpr uint32_t BUF_SIZE_MEDIUM = 16;     // bytes
constexpr uint32_t BUF_SIZE_LARGE = 64;      // bytes, for longer string reads
constexpr int32_t ARRAY_CAP_SMALL = 4;       // elements, for the out-array slot list
constexpr int32_t ARRAY_CAP_LARGE = 8;       // elements, for the out-array slot list

// ---- Sizes deliberately too small, used to drive failure paths -----------
constexpr uint32_t DST_SIZE_TOO_SMALL_ZERO = 1;    // room for the NUL byte only
constexpr uint32_t DST_SIZE_TOO_SMALL_PARTIAL = 3; // shorter than the stored "value"
constexpr int32_t ARRAY_LEN_TOO_SMALL = 2;         // less than the 3-element array
constexpr uint32_t BYTES_BUFLEN_TOO_SMALL = 2;     // less than the 4-byte payload

// ---- Canonical values written & read back through typed accessors --------
constexpr int16_t VAL_INT16 = 1234;
constexpr int32_t VAL_INT32 = 100000;
constexpr int64_t VAL_INT64 = 10000000000LL;
constexpr int32_t VAL_INT32_NEG = -12345;
constexpr int32_t VAL_PRINT_INT = 42;

// Round-trip / overwrite payload values
constexpr int16_t RT_INT16 = 16;
constexpr int32_t RT_INT32 = 3200;
constexpr int64_t RT_INT64 = 64000000LL;
constexpr int32_t RT_OVERWRITE_INT = 100;

// ---- Byte payloads -------------------------------------------------------
constexpr uint8_t BYTES_PAYLOAD[] = { 0x00, 0x01, 0x02, 0xFF };
constexpr uint8_t BYTES_PAYLOAD_ALT[] = { 0x10, 0x20, 0x30 };
}  // namespace

class AdaptorDsoftbusJsonTest : public testing::Test {
protected:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void AdaptorDsoftbusJsonTest::SetUpTestCase(void) { }
void AdaptorDsoftbusJsonTest::TearDownTestCase(void) { }
void AdaptorDsoftbusJsonTest::SetUp() { }
void AdaptorDsoftbusJsonTest::TearDown() { }

// ---------------------------------------------------------------------------
// JSON_CreateObject / JSON_Delete / JSON_Free
// ---------------------------------------------------------------------------

/*
 * @tc.name: JsonCreateObjectTest001
 * @tc.desc: JSON_CreateObject returns a non-null object with a valid context
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonCreateObjectTest001, TestSize.Level1)
{
    JsonObj *obj = JSON_CreateObject();
    EXPECT_NE(nullptr, obj);
    ASSERT_NE(nullptr, obj);
    EXPECT_NE(nullptr, obj->context);
    JSON_Delete(obj);
}

/*
 * @tc.name: JsonCreateObjectTest002
 * @tc.desc: repeatedly create/free objects does not leak or crash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonCreateObjectTest002, TestSize.Level1)
{
    for (int32_t i = 0; i < CREATE_REPEAT_COUNT; ++i) {
        JsonObj *obj = JSON_CreateObject();
        EXPECT_NE(nullptr, obj);
        JSON_Delete(obj);
    }
}

/*
 * @tc.name: JsonDeleteTest001
 * @tc.desc: JSON_Delete on a valid object releases its context
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonDeleteTest001, TestSize.Level1)
{
    JsonObj *obj = JSON_CreateObject();
    ASSERT_NE(nullptr, obj);
    JSON_Delete(obj);  // context != nullptr branch
}

/*
 * @tc.name: JsonDeleteTest002
 * @tc.desc: JSON_Delete tolerates a null pointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonDeleteTest002, TestSize.Level1)
{
    JSON_Delete(nullptr);  // obj == nullptr branch
    JSON_Delete(nullptr);  // idempotent
}

/*
 * @tc.name: JsonFreeTest001
 * @tc.desc: JSON_Free releases a buffer allocated via SoftBusCalloc
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonFreeTest001, TestSize.Level1)
{
    void *buf = SoftBusCalloc(FREE_BUF_SIZE);
    ASSERT_NE(nullptr, buf);
    JSON_Free(buf);  // obj != nullptr branch
}

/*
 * @tc.name: JsonFreeTest002
 * @tc.desc: JSON_Free tolerates a null pointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonFreeTest002, TestSize.Level1)
{
    JSON_Free(nullptr);  // obj == nullptr branch
}

// ---------------------------------------------------------------------------
// JSON_PrintUnformatted
// ---------------------------------------------------------------------------

/*
 * @tc.name: JsonPrintUnformattedTest001
 * @tc.desc: print an object that carries several value types
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonPrintUnformattedTest001, TestSize.Level1)
{
    JsonObj *obj = JSON_CreateObject();
    ASSERT_NE(nullptr, obj);
    EXPECT_TRUE(JSON_AddBoolToObject(obj, "b", true));
    EXPECT_TRUE(JSON_AddInt32ToObject(obj, "i", VAL_PRINT_INT));
    EXPECT_TRUE(JSON_AddStringToObject(obj, "s", "hello"));
    char *str = JSON_PrintUnformatted(obj);
    EXPECT_NE(nullptr, str);
    if (str != nullptr) {
        EXPECT_NE(nullptr, strstr(str, "hello"));
        JSON_Free(str);
    }
    JSON_Delete(obj);
}

/*
 * @tc.name: JsonPrintUnformattedTest002
 * @tc.desc: print an empty object yields a non-null "{}"-like string
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonPrintUnformattedTest002, TestSize.Level1)
{
    JsonObj *obj = JSON_CreateObject();
    ASSERT_NE(nullptr, obj);
    char *str = JSON_PrintUnformatted(obj);
    EXPECT_NE(nullptr, str);
    JSON_Free(str);
    JSON_Delete(obj);
}

/*
 * @tc.name: JsonPrintUnformattedTest003
 * @tc.desc: print rejects a null object pointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonPrintUnformattedTest003, TestSize.Level1)
{
    EXPECT_EQ(nullptr, JSON_PrintUnformatted(nullptr));  // obj == nullptr
}

/*
 * @tc.name: JsonPrintUnformattedTest004
 * @tc.desc: print rejects an object whose context is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonPrintUnformattedTest004, TestSize.Level1)
{
    JsonObj nullObj = MakeNullContextObj();
    EXPECT_EQ(nullptr, JSON_PrintUnformatted(&nullObj));  // context == nullptr
}

// ---------------------------------------------------------------------------
// JSON_Parse
// ---------------------------------------------------------------------------

/*
 * @tc.name: JsonParseTest001
 * @tc.desc: parse a well-formed object and read back its fields
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonParseTest001, TestSize.Level1)
{
    const char *text = "{\"name\":\"abc\",\"age\":10,\"flag\":true}";
    JsonObj *obj = JSON_Parse(text, strlen(text));
    ASSERT_NE(nullptr, obj);
    char name[BUF_SIZE_MEDIUM] = {0};
    EXPECT_TRUE(JSON_GetStringFromObject(obj, "name", name, sizeof(name)));
    EXPECT_STREQ("abc", name);
    int32_t age = 0;
    EXPECT_TRUE(JSON_GetInt32FromOject(obj, "age", &age));
    EXPECT_EQ(10, age);
    bool flag = false;
    EXPECT_TRUE(JSON_GetBoolFromOject(obj, "flag", &flag));
    EXPECT_EQ(true, flag);
    JSON_Delete(obj);
}

/*
 * @tc.name: JsonParseTest002
 * @tc.desc: parse an empty object; the item loop runs zero iterations
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonParseTest002, TestSize.Level1)
{
    const char *text = "{}";
    JsonObj *obj = JSON_Parse(text, strlen(text));
    EXPECT_NE(nullptr, obj);
    JSON_Delete(obj);
}

/*
 * @tc.name: JsonParseTest003
 * @tc.desc: parse a nested object/array structure
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonParseTest003, TestSize.Level1)
{
    const char *text = "{\"outer\":{\"inner\":1},\"list\":[1,2,3]}";
    JsonObj *obj = JSON_Parse(text, strlen(text));
    EXPECT_NE(nullptr, obj);
    JSON_Delete(obj);
}

/*
 * @tc.name: JsonParseTest004
 * @tc.desc: parse malformed input returns null (is_discarded branch)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonParseTest004, TestSize.Level1)
{
    const char *invalid = "{invalid}";
    EXPECT_EQ(nullptr, JSON_Parse(invalid, strlen(invalid)));
}

/*
 * @tc.name: JsonParseTest005
 * @tc.desc: parse a truncated buffer that cuts off mid-token fails gracefully
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonParseTest005, TestSize.Level1)
{
    const char *full = "{\"k\":\"value\"}";
    // length stops before the value's closing quote -> malformed payload
    const uint32_t truncatedLen = 6;
    EXPECT_EQ(nullptr, JSON_Parse(full, truncatedLen));
}

// ---------------------------------------------------------------------------
// JSON_AddBoolToObject / JSON_GetBoolFromOject
// ---------------------------------------------------------------------------

/*
 * @tc.name: JsonAddBoolToObjectTest001
 * @tc.desc: add a true boolean value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonAddBoolToObjectTest001, TestSize.Level1)
{
    JsonObj *obj = JSON_CreateObject();
    ASSERT_NE(nullptr, obj);
    EXPECT_TRUE(JSON_AddBoolToObject(obj, KEY_BOOL, true));
    bool v = false;
    EXPECT_TRUE(JSON_GetBoolFromOject(obj, KEY_BOOL, &v));
    EXPECT_EQ(true, v);
    JSON_Delete(obj);
}

/*
 * @tc.name: JsonAddBoolToObjectTest002
 * @tc.desc: add a false boolean value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonAddBoolToObjectTest002, TestSize.Level1)
{
    JsonObj *obj = JSON_CreateObject();
    ASSERT_NE(nullptr, obj);
    EXPECT_TRUE(JSON_AddBoolToObject(obj, KEY_BOOL, false));
    bool v = true;
    EXPECT_TRUE(JSON_GetBoolFromOject(obj, KEY_BOOL, &v));
    EXPECT_EQ(false, v);
    JSON_Delete(obj);
}

/*
 * @tc.name: JsonAddBoolToObjectTest003
 * @tc.desc: add rejects a null object pointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonAddBoolToObjectTest003, TestSize.Level1)
{
    EXPECT_FALSE(JSON_AddBoolToObject(nullptr, KEY_BOOL, true));
}

/*
 * @tc.name: JsonAddBoolToObjectTest004
 * @tc.desc: add rejects a null key
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonAddBoolToObjectTest004, TestSize.Level1)
{
    JsonObj *obj = JSON_CreateObject();
    ASSERT_NE(nullptr, obj);
    EXPECT_FALSE(JSON_AddBoolToObject(obj, nullptr, true));
    JSON_Delete(obj);
}

/*
 * @tc.name: JsonAddBoolToObjectTest005
 * @tc.desc: add rejects an object whose context is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonAddBoolToObjectTest005, TestSize.Level1)
{
    JsonObj nullObj = MakeNullContextObj();
    EXPECT_FALSE(JSON_AddBoolToObject(&nullObj, KEY_BOOL, true));
}

/*
 * @tc.name: JsonGetBoolFromOjectTest001
 * @tc.desc: get returns false and leaves output untouched when obj is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonGetBoolFromOjectTest001, TestSize.Level1)
{
    bool v = true;
    EXPECT_FALSE(JSON_GetBoolFromOject(nullptr, KEY_BOOL, &v));
}

/*
 * @tc.name: JsonGetBoolFromOjectTest002
 * @tc.desc: get rejects a null key
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonGetBoolFromOjectTest002, TestSize.Level1)
{
    JsonObj *obj = JSON_CreateObject();
    ASSERT_NE(nullptr, obj);
    bool v = false;
    EXPECT_FALSE(JSON_GetBoolFromOject(obj, nullptr, &v));
    JSON_Delete(obj);
}

/*
 * @tc.name: JsonGetBoolFromOjectTest003
 * @tc.desc: get rejects a null output pointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonGetBoolFromOjectTest003, TestSize.Level1)
{
    JsonObj *obj = JSON_CreateObject();
    ASSERT_NE(nullptr, obj);
    EXPECT_FALSE(JSON_GetBoolFromOject(obj, KEY_BOOL, nullptr));
    JSON_Delete(obj);
}

/*
 * @tc.name: JsonGetBoolFromOjectTest004
 * @tc.desc: get rejects an object whose context is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonGetBoolFromOjectTest004, TestSize.Level1)
{
    JsonObj nullObj = MakeNullContextObj();
    bool v = false;
    EXPECT_FALSE(JSON_GetBoolFromOject(&nullObj, KEY_BOOL, &v));
}

/*
 * @tc.name: JsonGetBoolFromOjectTest005
 * @tc.desc: get fails with a type mismatch (string stored, bool requested)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonGetBoolFromOjectTest005, TestSize.Level1)
{
    JsonObj *obj = JSON_CreateObject();
    ASSERT_NE(nullptr, obj);
    EXPECT_TRUE(JSON_AddStringToObject(obj, KEY_STR, "v"));
    bool v = false;
    EXPECT_FALSE(JSON_GetBoolFromOject(obj, KEY_STR, &v));
    JSON_Delete(obj);
}

/*
 * @tc.name: JsonGetBoolFromOjectTest006
 * @tc.desc: get fails when the key does not exist
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonGetBoolFromOjectTest006, TestSize.Level1)
{
    JsonObj *obj = JSON_CreateObject();
    ASSERT_NE(nullptr, obj);
    bool v = false;
    EXPECT_FALSE(JSON_GetBoolFromOject(obj, KEY_MISSING, &v));
    JSON_Delete(obj);
}

// ---------------------------------------------------------------------------
// JSON_AddInt16ToObject / JSON_GetInt16FromOject
// ---------------------------------------------------------------------------

/*
 * @tc.name: JsonAddInt16ToObjectTest001
 * @tc.desc: add a positive int16 and read it back
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonAddInt16ToObjectTest001, TestSize.Level1)
{
    JsonObj *obj = JSON_CreateObject();
    ASSERT_NE(nullptr, obj);
    EXPECT_TRUE(JSON_AddInt16ToObject(obj, KEY_INT, VAL_INT16));
    int16_t v = 0;
    EXPECT_TRUE(JSON_GetInt16FromOject(obj, KEY_INT, &v));
    EXPECT_EQ(VAL_INT16, v);
    JSON_Delete(obj);
}

/*
 * @tc.name: JsonAddInt16ToObjectTest002
 * @tc.desc: add boundary values INT16_MIN / INT16_MAX and zero
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonAddInt16ToObjectTest002, TestSize.Level1)
{
    JsonObj *obj = JSON_CreateObject();
    ASSERT_NE(nullptr, obj);
    EXPECT_TRUE(JSON_AddInt16ToObject(obj, "min", INT16_MIN));
    EXPECT_TRUE(JSON_AddInt16ToObject(obj, "max", INT16_MAX));
    EXPECT_TRUE(JSON_AddInt16ToObject(obj, "zero", static_cast<int16_t>(0)));
    int16_t v = 0;
    EXPECT_TRUE(JSON_GetInt16FromOject(obj, "min", &v));
    EXPECT_EQ(INT16_MIN, v);
    EXPECT_TRUE(JSON_GetInt16FromOject(obj, "max", &v));
    EXPECT_EQ(INT16_MAX, v);
    EXPECT_TRUE(JSON_GetInt16FromOject(obj, "zero", &v));
    EXPECT_EQ(0, v);
    JSON_Delete(obj);
}

/*
 * @tc.name: JsonAddInt16ToObjectTest003
 * @tc.desc: add rejects null obj / null key / null context
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonAddInt16ToObjectTest003, TestSize.Level1)
{
    EXPECT_FALSE(JSON_AddInt16ToObject(nullptr, KEY_INT, VAL_INT16));
    JsonObj *obj = JSON_CreateObject();
    ASSERT_NE(nullptr, obj);
    EXPECT_FALSE(JSON_AddInt16ToObject(obj, nullptr, VAL_INT16));
    JSON_Delete(obj);
    JsonObj nullObj = MakeNullContextObj();
    EXPECT_FALSE(JSON_AddInt16ToObject(&nullObj, KEY_INT, VAL_INT16));
}

/*
 * @tc.name: JsonGetInt16FromOjectTest001
 * @tc.desc: get rejects a null output pointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonGetInt16FromOjectTest001, TestSize.Level1)
{
    JsonObj *obj = JSON_CreateObject();
    ASSERT_NE(nullptr, obj);
    EXPECT_FALSE(JSON_GetInt16FromOject(obj, KEY_INT, nullptr));
    JSON_Delete(obj);
}

/*
 * @tc.name: JsonGetInt16FromOjectTest002
 * @tc.desc: get rejects null obj / null key (template guard)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonGetInt16FromOjectTest002, TestSize.Level1)
{
    int16_t v = 0;
    EXPECT_FALSE(JSON_GetInt16FromOject(nullptr, KEY_INT, &v));
    JsonObj *obj = JSON_CreateObject();
    ASSERT_NE(nullptr, obj);
    EXPECT_FALSE(JSON_GetInt16FromOject(obj, nullptr, &v));
    JSON_Delete(obj);
}

/*
 * @tc.name: JsonGetInt16FromOjectTest003
 * @tc.desc: get rejects an object whose context is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonGetInt16FromOjectTest003, TestSize.Level1)
{
    JsonObj nullObj = MakeNullContextObj();
    int16_t v = 0;
    EXPECT_FALSE(JSON_GetInt16FromOject(&nullObj, KEY_INT, &v));
}

/*
 * @tc.name: JsonGetInt16FromOjectTest004
 * @tc.desc: get fails with a type mismatch and on a missing key
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonGetInt16FromOjectTest004, TestSize.Level1)
{
    JsonObj *obj = JSON_CreateObject();
    ASSERT_NE(nullptr, obj);
    EXPECT_TRUE(JSON_AddStringToObject(obj, KEY_STR, "v"));
    int16_t v = 0;
    EXPECT_FALSE(JSON_GetInt16FromOject(obj, KEY_STR, &v));
    EXPECT_FALSE(JSON_GetInt16FromOject(obj, KEY_MISSING, &v));
    JSON_Delete(obj);
}

// ---------------------------------------------------------------------------
// JSON_AddInt32ToObject / JSON_GetInt32FromOject
// ---------------------------------------------------------------------------

/*
 * @tc.name: JsonAddInt32ToObjectTest001
 * @tc.desc: add a typical int32 and read it back
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonAddInt32ToObjectTest001, TestSize.Level1)
{
    JsonObj *obj = JSON_CreateObject();
    ASSERT_NE(nullptr, obj);
    EXPECT_TRUE(JSON_AddInt32ToObject(obj, KEY_INT, VAL_INT32));
    int32_t v = 0;
    EXPECT_TRUE(JSON_GetInt32FromOject(obj, KEY_INT, &v));
    EXPECT_EQ(VAL_INT32, v);
    JSON_Delete(obj);
}

/*
 * @tc.name: JsonAddInt32ToObjectTest002
 * @tc.desc: add boundary values INT32_MIN / INT32_MAX and a negative value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonAddInt32ToObjectTest002, TestSize.Level1)
{
    JsonObj *obj = JSON_CreateObject();
    ASSERT_NE(nullptr, obj);
    EXPECT_TRUE(JSON_AddInt32ToObject(obj, "min", INT32_MIN));
    EXPECT_TRUE(JSON_AddInt32ToObject(obj, "max", INT32_MAX));
    EXPECT_TRUE(JSON_AddInt32ToObject(obj, "neg", VAL_INT32_NEG));
    int32_t v = 0;
    EXPECT_TRUE(JSON_GetInt32FromOject(obj, "min", &v));
    EXPECT_EQ(INT32_MIN, v);
    EXPECT_TRUE(JSON_GetInt32FromOject(obj, "max", &v));
    EXPECT_EQ(INT32_MAX, v);
    EXPECT_TRUE(JSON_GetInt32FromOject(obj, "neg", &v));
    EXPECT_EQ(VAL_INT32_NEG, v);
    JSON_Delete(obj);
}

/*
 * @tc.name: JsonAddInt32ToObjectTest003
 * @tc.desc: add rejects null obj / null key / null context
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonAddInt32ToObjectTest003, TestSize.Level1)
{
    EXPECT_FALSE(JSON_AddInt32ToObject(nullptr, KEY_INT, VAL_INT32));
    JsonObj *obj = JSON_CreateObject();
    ASSERT_NE(nullptr, obj);
    EXPECT_FALSE(JSON_AddInt32ToObject(obj, nullptr, VAL_INT32));
    JSON_Delete(obj);
    JsonObj nullObj = MakeNullContextObj();
    EXPECT_FALSE(JSON_AddInt32ToObject(&nullObj, KEY_INT, VAL_INT32));
}

/*
 * @tc.name: JsonGetInt32FromOjectTest001
 * @tc.desc: get rejects a null output pointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonGetInt32FromOjectTest001, TestSize.Level1)
{
    JsonObj *obj = JSON_CreateObject();
    ASSERT_NE(nullptr, obj);
    EXPECT_FALSE(JSON_GetInt32FromOject(obj, KEY_INT, nullptr));
    JSON_Delete(obj);
}

/*
 * @tc.name: JsonGetInt32FromOjectTest002
 * @tc.desc: get rejects null obj / null key (template guard)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonGetInt32FromOjectTest002, TestSize.Level1)
{
    int32_t v = 0;
    EXPECT_FALSE(JSON_GetInt32FromOject(nullptr, KEY_INT, &v));
    JsonObj *obj = JSON_CreateObject();
    ASSERT_NE(nullptr, obj);
    EXPECT_FALSE(JSON_GetInt32FromOject(obj, nullptr, &v));
    JSON_Delete(obj);
}

/*
 * @tc.name: JsonGetInt32FromOjectTest003
 * @tc.desc: get rejects an object whose context is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonGetInt32FromOjectTest003, TestSize.Level1)
{
    JsonObj nullObj = MakeNullContextObj();
    int32_t v = 0;
    EXPECT_FALSE(JSON_GetInt32FromOject(&nullObj, KEY_INT, &v));
}

/*
 * @tc.name: JsonGetInt32FromOjectTest004
 * @tc.desc: get fails with a type mismatch and on a missing key
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonGetInt32FromOjectTest004, TestSize.Level1)
{
    JsonObj *obj = JSON_CreateObject();
    ASSERT_NE(nullptr, obj);
    EXPECT_TRUE(JSON_AddStringToObject(obj, KEY_STR, "v"));
    int32_t v = 0;
    EXPECT_FALSE(JSON_GetInt32FromOject(obj, KEY_STR, &v));
    EXPECT_FALSE(JSON_GetInt32FromOject(obj, KEY_MISSING, &v));
    JSON_Delete(obj);
}

// ---------------------------------------------------------------------------
// JSON_AddInt64ToObject / JSON_GetInt64FromOject
// ---------------------------------------------------------------------------

/*
 * @tc.name: JsonAddInt64ToObjectTest001
 * @tc.desc: add a large int64 and read it back
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonAddInt64ToObjectTest001, TestSize.Level1)
{
    JsonObj *obj = JSON_CreateObject();
    ASSERT_NE(nullptr, obj);
    EXPECT_TRUE(JSON_AddInt64ToObject(obj, KEY_INT, VAL_INT64));
    int64_t v = 0;
    EXPECT_TRUE(JSON_GetInt64FromOject(obj, KEY_INT, &v));
    EXPECT_EQ(VAL_INT64, v);
    JSON_Delete(obj);
}

/*
 * @tc.name: JsonAddInt64ToObjectTest002
 * @tc.desc: add boundary values INT64_MIN / INT64_MAX
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonAddInt64ToObjectTest002, TestSize.Level1)
{
    JsonObj *obj = JSON_CreateObject();
    ASSERT_NE(nullptr, obj);
    EXPECT_TRUE(JSON_AddInt64ToObject(obj, "min", INT64_MIN));
    EXPECT_TRUE(JSON_AddInt64ToObject(obj, "max", INT64_MAX));
    int64_t v = 0;
    EXPECT_TRUE(JSON_GetInt64FromOject(obj, "min", &v));
    EXPECT_EQ(INT64_MIN, v);
    EXPECT_TRUE(JSON_GetInt64FromOject(obj, "max", &v));
    EXPECT_EQ(INT64_MAX, v);
    JSON_Delete(obj);
}

/*
 * @tc.name: JsonAddInt64ToObjectTest003
 * @tc.desc: add rejects null obj / null key / null context
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonAddInt64ToObjectTest003, TestSize.Level1)
{
    EXPECT_FALSE(JSON_AddInt64ToObject(nullptr, KEY_INT, VAL_INT64));
    JsonObj *obj = JSON_CreateObject();
    ASSERT_NE(nullptr, obj);
    EXPECT_FALSE(JSON_AddInt64ToObject(obj, nullptr, VAL_INT64));
    JSON_Delete(obj);
    JsonObj nullObj = MakeNullContextObj();
    EXPECT_FALSE(JSON_AddInt64ToObject(&nullObj, KEY_INT, VAL_INT64));
}

/*
 * @tc.name: JsonGetInt64FromOjectTest001
 * @tc.desc: get rejects a null output pointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonGetInt64FromOjectTest001, TestSize.Level1)
{
    JsonObj *obj = JSON_CreateObject();
    ASSERT_NE(nullptr, obj);
    EXPECT_FALSE(JSON_GetInt64FromOject(obj, KEY_INT, nullptr));
    JSON_Delete(obj);
}

/*
 * @tc.name: JsonGetInt64FromOjectTest002
 * @tc.desc: get rejects null obj / null key (template guard)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonGetInt64FromOjectTest002, TestSize.Level1)
{
    int64_t v = 0;
    EXPECT_FALSE(JSON_GetInt64FromOject(nullptr, KEY_INT, &v));
    JsonObj *obj = JSON_CreateObject();
    ASSERT_NE(nullptr, obj);
    EXPECT_FALSE(JSON_GetInt64FromOject(obj, nullptr, &v));
    JSON_Delete(obj);
}

/*
 * @tc.name: JsonGetInt64FromOjectTest003
 * @tc.desc: get rejects an object whose context is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonGetInt64FromOjectTest003, TestSize.Level1)
{
    JsonObj nullObj = MakeNullContextObj();
    int64_t v = 0;
    EXPECT_FALSE(JSON_GetInt64FromOject(&nullObj, KEY_INT, &v));
}

/*
 * @tc.name: JsonGetInt64FromOjectTest004
 * @tc.desc: get fails with a type mismatch and on a missing key
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonGetInt64FromOjectTest004, TestSize.Level1)
{
    JsonObj *obj = JSON_CreateObject();
    ASSERT_NE(nullptr, obj);
    EXPECT_TRUE(JSON_AddStringToObject(obj, KEY_STR, "v"));
    int64_t v = 0;
    EXPECT_FALSE(JSON_GetInt64FromOject(obj, KEY_STR, &v));
    EXPECT_FALSE(JSON_GetInt64FromOject(obj, KEY_MISSING, &v));
    JSON_Delete(obj);
}

// ---------------------------------------------------------------------------
// JSON_AddStringToObject / JSON_GetStringFromObject
// ---------------------------------------------------------------------------

/*
 * @tc.name: JsonAddStringToObjectTest001
 * @tc.desc: add a normal string and read it back
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonAddStringToObjectTest001, TestSize.Level1)
{
    JsonObj *obj = JSON_CreateObject();
    ASSERT_NE(nullptr, obj);
    EXPECT_TRUE(JSON_AddStringToObject(obj, KEY_STR, "value"));
    char buf[BUF_SIZE_LARGE] = {0};
    EXPECT_TRUE(JSON_GetStringFromObject(obj, KEY_STR, buf, sizeof(buf)));
    EXPECT_STREQ("value", buf);
    JSON_Delete(obj);
}

/*
 * @tc.name: JsonAddStringToObjectTest002
 * @tc.desc: add an empty string
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonAddStringToObjectTest002, TestSize.Level1)
{
    JsonObj *obj = JSON_CreateObject();
    ASSERT_NE(nullptr, obj);
    EXPECT_TRUE(JSON_AddStringToObject(obj, KEY_STR, ""));
    char buf[BUF_SIZE_SMALL] = {0};
    EXPECT_TRUE(JSON_GetStringFromObject(obj, KEY_STR, buf, sizeof(buf)));
    EXPECT_STREQ("", buf);
    JSON_Delete(obj);
}

/*
 * @tc.name: JsonAddStringToObjectTest003
 * @tc.desc: add rejects null obj / null key / null value / null context
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonAddStringToObjectTest003, TestSize.Level1)
{
    EXPECT_FALSE(JSON_AddStringToObject(nullptr, KEY_STR, "v"));
    JsonObj *obj = JSON_CreateObject();
    ASSERT_NE(nullptr, obj);
    EXPECT_FALSE(JSON_AddStringToObject(obj, nullptr, "v"));
    EXPECT_FALSE(JSON_AddStringToObject(obj, KEY_STR, nullptr));
    JSON_Delete(obj);
    JsonObj nullObj = MakeNullContextObj();
    EXPECT_FALSE(JSON_AddStringToObject(&nullObj, KEY_STR, "v"));
}

/*
 * @tc.name: JsonGetStringFromObjectTest001
 * @tc.desc: get rejects null obj / null key / null value / null context
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonGetStringFromObjectTest001, TestSize.Level1)
{
    char buf[BUF_SIZE_SMALL] = {0};
    EXPECT_FALSE(JSON_GetStringFromObject(nullptr, KEY_STR, buf, sizeof(buf)));
    JsonObj *obj = JSON_CreateObject();
    ASSERT_NE(nullptr, obj);
    EXPECT_FALSE(JSON_GetStringFromObject(obj, nullptr, buf, sizeof(buf)));
    EXPECT_FALSE(JSON_GetStringFromObject(obj, KEY_STR, nullptr, sizeof(buf)));
    JSON_Delete(obj);
    JsonObj nullObj = MakeNullContextObj();
    EXPECT_FALSE(JSON_GetStringFromObject(&nullObj, KEY_STR, buf, sizeof(buf)));
}

/*
 * @tc.name: JsonGetStringFromObjectTest002
 * @tc.desc: get fails with a type mismatch (number stored, string requested)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonGetStringFromObjectTest002, TestSize.Level1)
{
    JsonObj *obj = JSON_CreateObject();
    ASSERT_NE(nullptr, obj);
    EXPECT_TRUE(JSON_AddInt32ToObject(obj, KEY_INT, VAL_INT32));
    char buf[BUF_SIZE_SMALL] = {0};
    EXPECT_FALSE(JSON_GetStringFromObject(obj, KEY_INT, buf, sizeof(buf)));
    JSON_Delete(obj);
}

/*
 * @tc.name: JsonGetStringFromObjectTest003
 * @tc.desc: get fails when the key does not exist
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonGetStringFromObjectTest003, TestSize.Level1)
{
    JsonObj *obj = JSON_CreateObject();
    ASSERT_NE(nullptr, obj);
    char buf[BUF_SIZE_SMALL] = {0};
    EXPECT_FALSE(JSON_GetStringFromObject(obj, KEY_MISSING, buf, sizeof(buf)));
    JSON_Delete(obj);
}

/*
 * @tc.name: JsonGetStringFromObjectTest004
 * @tc.desc: get fails when the destination buffer is too small (strcpy_s fail)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonGetStringFromObjectTest004, TestSize.Level1)
{
    JsonObj *obj = JSON_CreateObject();
    ASSERT_NE(nullptr, obj);
    EXPECT_TRUE(JSON_AddStringToObject(obj, KEY_STR, "value"));
    char buf[BUF_SIZE_LARGE] = {0};
    // destination sizes deliberately too small to hold "value"
    EXPECT_FALSE(JSON_GetStringFromObject(obj, KEY_STR, buf, DST_SIZE_TOO_SMALL_ZERO));
    EXPECT_FALSE(JSON_GetStringFromObject(obj, KEY_STR, buf, DST_SIZE_TOO_SMALL_PARTIAL));
    JSON_Delete(obj);
}

// ---------------------------------------------------------------------------
// JSON_AddStringArrayToObject / JSON_GetStringArrayFromOject
// ---------------------------------------------------------------------------

/*
 * @tc.name: JsonAddStringArrayToObjectTest001
 * @tc.desc: add a multi-element string array and read it back
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonAddStringArrayToObjectTest001, TestSize.Level1)
{
    JsonObj *obj = JSON_CreateObject();
    ASSERT_NE(nullptr, obj);
    const char *arr[] = { "a", "bb", "ccc" };
    EXPECT_TRUE(JSON_AddStringArrayToObject(obj, KEY_ARR, arr, ArraySize(arr)));
    char *out[ARRAY_CAP_LARGE] = { 0 };
    int32_t len = ARRAY_CAP_LARGE;
    EXPECT_TRUE(JSON_GetStringArrayFromOject(obj, KEY_ARR, out, &len));
    EXPECT_EQ(static_cast<int32_t>(ArraySize(arr)), len);
    ASSERT_GE(ARRAY_CAP_LARGE, len);
    EXPECT_STREQ("a", out[0]);
    EXPECT_STREQ("bb", out[1]);
    EXPECT_STREQ("ccc", out[2]);
    for (int32_t i = 0; i < len; ++i) {
        SoftBusFree(out[i]);
    }
    JSON_Delete(obj);
}

/*
 * @tc.name: JsonAddStringArrayToObjectTest002
 * @tc.desc: add a single-element array
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonAddStringArrayToObjectTest002, TestSize.Level1)
{
    JsonObj *obj = JSON_CreateObject();
    ASSERT_NE(nullptr, obj);
    const char *arr[] = { "only" };
    EXPECT_TRUE(JSON_AddStringArrayToObject(obj, KEY_ARR, arr, ArraySize(arr)));
    char *out[ARRAY_CAP_SMALL] = { 0 };
    int32_t len = ARRAY_CAP_SMALL;
    EXPECT_TRUE(JSON_GetStringArrayFromOject(obj, KEY_ARR, out, &len));
    EXPECT_EQ(static_cast<int32_t>(ArraySize(arr)), len);
    SoftBusFree(out[0]);
    JSON_Delete(obj);
}

/*
 * @tc.name: JsonAddStringArrayToObjectTest003
 * @tc.desc: add rejects null value / null obj / null key / len <= 0 / null context
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonAddStringArrayToObjectTest003, TestSize.Level1)
{
    const char *arr[] = { "a" };
    EXPECT_FALSE(JSON_AddStringArrayToObject(nullptr, KEY_ARR, arr, ArraySize(arr)));
    JsonObj *obj = JSON_CreateObject();
    ASSERT_NE(nullptr, obj);
    EXPECT_FALSE(JSON_AddStringArrayToObject(obj, nullptr, arr, ArraySize(arr)));
    EXPECT_FALSE(JSON_AddStringArrayToObject(obj, KEY_ARR, nullptr, ArraySize(arr)));
    EXPECT_FALSE(JSON_AddStringArrayToObject(obj, KEY_ARR, arr, 0));
    EXPECT_FALSE(JSON_AddStringArrayToObject(obj, KEY_ARR, arr, -1));
    JSON_Delete(obj);
    JsonObj nullObj = MakeNullContextObj();
    EXPECT_FALSE(JSON_AddStringArrayToObject(&nullObj, KEY_ARR, arr, ArraySize(arr)));
}

/*
 * @tc.name: JsonGetStringArrayFromOjectTest001
 * @tc.desc: get rejects null value / null obj / null key / null len
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonGetStringArrayFromOjectTest001, TestSize.Level1)
{
    char *out[ARRAY_CAP_SMALL] = { 0 };
    int32_t len = ARRAY_CAP_SMALL;
    EXPECT_FALSE(JSON_GetStringArrayFromOject(nullptr, KEY_ARR, out, &len));
    JsonObj *obj = JSON_CreateObject();
    ASSERT_NE(nullptr, obj);
    EXPECT_FALSE(JSON_GetStringArrayFromOject(obj, nullptr, out, &len));
    EXPECT_FALSE(JSON_GetStringArrayFromOject(obj, KEY_ARR, nullptr, &len));
    len = ARRAY_CAP_SMALL;
    EXPECT_FALSE(JSON_GetStringArrayFromOject(obj, KEY_ARR, out, nullptr));
    JSON_Delete(obj);
}

/*
 * @tc.name: JsonGetStringArrayFromOjectTest002
 * @tc.desc: get rejects *len <= 0
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonGetStringArrayFromOjectTest002, TestSize.Level1)
{
    JsonObj *obj = JSON_CreateObject();
    ASSERT_NE(nullptr, obj);
    const char *arr[] = { "a" };
    EXPECT_TRUE(JSON_AddStringArrayToObject(obj, KEY_ARR, arr, ArraySize(arr)));
    char *out[ARRAY_CAP_SMALL] = { 0 };
    int32_t len = 0;  // non-positive capacity hint
    EXPECT_FALSE(JSON_GetStringArrayFromOject(obj, KEY_ARR, out, &len));
    len = -1;
    EXPECT_FALSE(JSON_GetStringArrayFromOject(obj, KEY_ARR, out, &len));
    JSON_Delete(obj);
}

/*
 * @tc.name: JsonGetStringArrayFromOjectTest003
 * @tc.desc: get rejects an object whose context is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonGetStringArrayFromOjectTest003, TestSize.Level1)
{
    JsonObj nullObj = MakeNullContextObj();
    char *out[ARRAY_CAP_SMALL] = { 0 };
    int32_t len = ARRAY_CAP_SMALL;
    EXPECT_FALSE(JSON_GetStringArrayFromOject(&nullObj, KEY_ARR, out, &len));
}

/*
 * @tc.name: JsonGetStringArrayFromOjectTest004
 * @tc.desc: get fails when the stored value is not an array (type mismatch)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonGetStringArrayFromOjectTest004, TestSize.Level1)
{
    JsonObj *obj = JSON_CreateObject();
    ASSERT_NE(nullptr, obj);
    EXPECT_TRUE(JSON_AddStringToObject(obj, KEY_STR, "v"));
    char *out[ARRAY_CAP_SMALL] = { 0 };
    int32_t len = ARRAY_CAP_SMALL;
    EXPECT_FALSE(JSON_GetStringArrayFromOject(obj, KEY_STR, out, &len));
    JSON_Delete(obj);
}

/*
 * @tc.name: JsonGetStringArrayFromOjectTest005
 * @tc.desc: get fails when the key does not exist
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonGetStringArrayFromOjectTest005, TestSize.Level1)
{
    JsonObj *obj = JSON_CreateObject();
    ASSERT_NE(nullptr, obj);
    char *out[ARRAY_CAP_SMALL] = { 0 };
    int32_t len = ARRAY_CAP_SMALL;
    EXPECT_FALSE(JSON_GetStringArrayFromOject(obj, KEY_MISSING, out, &len));
    JSON_Delete(obj);
}

/*
 * @tc.name: JsonGetStringArrayFromOjectTest006
 * @tc.desc: get fails when the provided length is smaller than the array size
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonGetStringArrayFromOjectTest006, TestSize.Level1)
{
    JsonObj *obj = JSON_CreateObject();
    ASSERT_NE(nullptr, obj);
    const char *arr[] = { "a", "b", "c" };
    EXPECT_TRUE(JSON_AddStringArrayToObject(obj, KEY_ARR, arr, ArraySize(arr)));
    char *out[ARRAY_CAP_LARGE] = { 0 };
    int32_t len = ARRAY_LEN_TOO_SMALL;  // smaller than the stored array
    EXPECT_FALSE(JSON_GetStringArrayFromOject(obj, KEY_ARR, out, &len));
    JSON_Delete(obj);
}

/*
 * @tc.name: JsonGetStringArrayFromOjectTest007
 * @tc.desc: get fails when an array element is not a string (numeric array)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonGetStringArrayFromOjectTest007, TestSize.Level1)
{
    const char *text = "{\"arr\":[1,2,3]}";
    JsonObj *obj = JSON_Parse(text, strlen(text));
    ASSERT_NE(nullptr, obj);
    char *out[ARRAY_CAP_LARGE] = { 0 };
    int32_t len = ARRAY_CAP_LARGE;
    EXPECT_FALSE(JSON_GetStringArrayFromOject(obj, "arr", out, &len));
    JSON_Delete(obj);
}

/*
 * @tc.name: JsonGetStringArrayFromOjectTest008
 * @tc.desc: get fills exactly when provided length equals the array size
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonGetStringArrayFromOjectTest008, TestSize.Level1)
{
    JsonObj *obj = JSON_CreateObject();
    ASSERT_NE(nullptr, obj);
    const char *arr[] = { "x", "y" };
    EXPECT_TRUE(JSON_AddStringArrayToObject(obj, KEY_ARR, arr, ArraySize(arr)));
    char *out[ARRAY_CAP_LARGE] = { 0 };
    int32_t len = static_cast<int32_t>(ArraySize(arr));  // exactly the array size
    EXPECT_TRUE(JSON_GetStringArrayFromOject(obj, KEY_ARR, out, &len));
    EXPECT_EQ(static_cast<int32_t>(ArraySize(arr)), len);
    for (int32_t i = 0; i < len; ++i) {
        SoftBusFree(out[i]);
    }
    JSON_Delete(obj);
}

// ---------------------------------------------------------------------------
// JSON_AddBytesToObject / JSON_GetBytesFromObject
// ---------------------------------------------------------------------------

/*
 * @tc.name: JsonAddBytesToObjectTest001
 * @tc.desc: add a byte buffer and read it back
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonAddBytesToObjectTest001, TestSize.Level1)
{
    JsonObj *obj = JSON_CreateObject();
    ASSERT_NE(nullptr, obj);
    EXPECT_TRUE(JSON_AddBytesToObject(obj, KEY_BYTES, const_cast<uint8_t *>(BYTES_PAYLOAD), ArraySize(BYTES_PAYLOAD)));
    uint8_t buf[BUF_SIZE_MEDIUM] = { 0 };
    uint32_t size = 0;
    EXPECT_TRUE(JSON_GetBytesFromObject(obj, KEY_BYTES, buf, sizeof(buf), &size));
    EXPECT_EQ(static_cast<uint32_t>(ArraySize(BYTES_PAYLOAD)), size);
    EXPECT_EQ(0, memcmp(buf, BYTES_PAYLOAD, ArraySize(BYTES_PAYLOAD)));
    JSON_Delete(obj);
}

/*
 * @tc.name: JsonAddBytesToObjectTest002
 * @tc.desc: add rejects null obj / null key / null value / size == 0 / null context
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonAddBytesToObjectTest002, TestSize.Level1)
{
    uint8_t data[] = { 1, 2 };
    EXPECT_FALSE(JSON_AddBytesToObject(nullptr, KEY_BYTES, data, ArraySize(data)));
    JsonObj *obj = JSON_CreateObject();
    ASSERT_NE(nullptr, obj);
    EXPECT_FALSE(JSON_AddBytesToObject(obj, nullptr, data, ArraySize(data)));
    EXPECT_FALSE(JSON_AddBytesToObject(obj, KEY_BYTES, nullptr, ArraySize(data)));
    EXPECT_FALSE(JSON_AddBytesToObject(obj, KEY_BYTES, data, 0));
    JSON_Delete(obj);
    JsonObj nullObj = MakeNullContextObj();
    EXPECT_FALSE(JSON_AddBytesToObject(&nullObj, KEY_BYTES, data, ArraySize(data)));
}

/*
 * @tc.name: JsonGetBytesFromObjectTest001
 * @tc.desc: get rejects null obj / null key / null value / bufLen == 0 / null size
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonGetBytesFromObjectTest001, TestSize.Level1)
{
    uint8_t buf[BUF_SIZE_SMALL] = { 0 };
    uint32_t size = 0;
    EXPECT_FALSE(JSON_GetBytesFromObject(nullptr, KEY_BYTES, buf, sizeof(buf), &size));
    JsonObj *obj = JSON_CreateObject();
    ASSERT_NE(nullptr, obj);
    EXPECT_FALSE(JSON_GetBytesFromObject(obj, nullptr, buf, sizeof(buf), &size));
    EXPECT_FALSE(JSON_GetBytesFromObject(obj, KEY_BYTES, nullptr, sizeof(buf), &size));
    EXPECT_FALSE(JSON_GetBytesFromObject(obj, KEY_BYTES, buf, 0, &size));
    EXPECT_FALSE(JSON_GetBytesFromObject(obj, KEY_BYTES, buf, sizeof(buf), nullptr));
    JSON_Delete(obj);
}

/*
 * @tc.name: JsonGetBytesFromObjectTest002
 * @tc.desc: get rejects an object whose context is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonGetBytesFromObjectTest002, TestSize.Level1)
{
    JsonObj nullObj = MakeNullContextObj();
    uint8_t buf[BUF_SIZE_SMALL] = { 0 };
    uint32_t size = 0;
    EXPECT_FALSE(JSON_GetBytesFromObject(&nullObj, KEY_BYTES, buf, sizeof(buf), &size));
}

/*
 * @tc.name: JsonGetBytesFromObjectTest003
 * @tc.desc: get fails when the key does not exist (count <= 0)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonGetBytesFromObjectTest003, TestSize.Level1)
{
    JsonObj *obj = JSON_CreateObject();
    ASSERT_NE(nullptr, obj);
    uint8_t buf[BUF_SIZE_SMALL] = { 0 };
    uint32_t size = 0;
    EXPECT_FALSE(JSON_GetBytesFromObject(obj, KEY_MISSING, buf, sizeof(buf), &size));
    JSON_Delete(obj);
}

/*
 * @tc.name: JsonGetBytesFromObjectTest004
 * @tc.desc: get fails when the stored value is not an array (type mismatch)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonGetBytesFromObjectTest004, TestSize.Level1)
{
    JsonObj *obj = JSON_CreateObject();
    ASSERT_NE(nullptr, obj);
    EXPECT_TRUE(JSON_AddStringToObject(obj, KEY_STR, "v"));
    uint8_t buf[BUF_SIZE_SMALL] = { 0 };
    uint32_t size = 0;
    EXPECT_FALSE(JSON_GetBytesFromObject(obj, KEY_STR, buf, sizeof(buf), &size));
    JSON_Delete(obj);
}

/*
 * @tc.name: JsonGetBytesFromObjectTest005
 * @tc.desc: get fails when the destination buffer is smaller than the payload
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonGetBytesFromObjectTest005, TestSize.Level1)
{
    JsonObj *obj = JSON_CreateObject();
    ASSERT_NE(nullptr, obj);
    EXPECT_TRUE(JSON_AddBytesToObject(obj, KEY_BYTES, const_cast<uint8_t *>(BYTES_PAYLOAD), ArraySize(BYTES_PAYLOAD)));
    uint8_t buf[BUF_SIZE_MEDIUM] = { 0 };
    uint32_t size = 0;
    EXPECT_FALSE(JSON_GetBytesFromObject(obj, KEY_BYTES, buf, BYTES_BUFLEN_TOO_SMALL, &size));  // bufLen < size
    JSON_Delete(obj);
}

// ---------------------------------------------------------------------------
// JSON_IsArrayExist
// ---------------------------------------------------------------------------

/*
 * @tc.name: JsonIsArrayExistTest001
 * @tc.desc: returns true when the key holds an array
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonIsArrayExistTest001, TestSize.Level1)
{
    JsonObj *obj = JSON_CreateObject();
    ASSERT_NE(nullptr, obj);
    const char *arr[] = { "a" };
    EXPECT_TRUE(JSON_AddStringArrayToObject(obj, KEY_ARR, arr, ArraySize(arr)));
    EXPECT_TRUE(JSON_IsArrayExist(obj, KEY_ARR));
    JSON_Delete(obj);
}

/*
 * @tc.name: JsonIsArrayExistTest002
 * @tc.desc: returns false when the key exists but is not an array
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonIsArrayExistTest002, TestSize.Level1)
{
    JsonObj *obj = JSON_CreateObject();
    ASSERT_NE(nullptr, obj);
    EXPECT_TRUE(JSON_AddStringToObject(obj, KEY_STR, "v"));
    EXPECT_FALSE(JSON_IsArrayExist(obj, KEY_STR));
    JSON_Delete(obj);
}

/*
 * @tc.name: JsonIsArrayExistTest003
 * @tc.desc: returns false when the key does not exist
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonIsArrayExistTest003, TestSize.Level1)
{
    JsonObj *obj = JSON_CreateObject();
    ASSERT_NE(nullptr, obj);
    EXPECT_FALSE(JSON_IsArrayExist(obj, KEY_MISSING));
    JSON_Delete(obj);
}

/*
 * @tc.name: JsonIsArrayExistTest004
 * @tc.desc: rejects null obj / null key / null context
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonIsArrayExistTest004, TestSize.Level1)
{
    EXPECT_FALSE(JSON_IsArrayExist(nullptr, KEY_ARR));
    JsonObj *obj = JSON_CreateObject();
    ASSERT_NE(nullptr, obj);
    EXPECT_FALSE(JSON_IsArrayExist(obj, nullptr));
    JSON_Delete(obj);
    JsonObj nullObj = MakeNullContextObj();
    EXPECT_FALSE(JSON_IsArrayExist(&nullObj, KEY_ARR));
}

/*
 * @tc.name: JsonIsArrayExistTest005
 * @tc.desc: an array parsed from JSON text is also detected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonIsArrayExistTest005, TestSize.Level1)
{
    const char *text = "{\"arr\":[1,2,3],\"s\":\"v\"}";
    JsonObj *obj = JSON_Parse(text, strlen(text));
    ASSERT_NE(nullptr, obj);
    EXPECT_TRUE(JSON_IsArrayExist(obj, "arr"));
    EXPECT_FALSE(JSON_IsArrayExist(obj, "s"));
    JSON_Delete(obj);
}

// ---------------------------------------------------------------------------
// Round-trip / integration scenarios
// ---------------------------------------------------------------------------

/*
 * @tc.name: JsonRoundTripTest001
 * @tc.desc: add mixed types, print, parse back, and verify every field
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonRoundTripTest001, TestSize.Level1)
{
    JsonObj *src = JSON_CreateObject();
    ASSERT_NE(nullptr, src);
    EXPECT_TRUE(JSON_AddBoolToObject(src, "b", true));
    EXPECT_TRUE(JSON_AddInt16ToObject(src, "i16", RT_INT16));
    EXPECT_TRUE(JSON_AddInt32ToObject(src, "i32", RT_INT32));
    EXPECT_TRUE(JSON_AddInt64ToObject(src, "i64", RT_INT64));
    EXPECT_TRUE(JSON_AddStringToObject(src, "s", "softbus"));
    EXPECT_TRUE(JSON_AddBytesToObject(src, "by", const_cast<uint8_t *>(BYTES_PAYLOAD_ALT), ArraySize(BYTES_PAYLOAD_ALT)));

    char *dump = JSON_PrintUnformatted(src);
    ASSERT_NE(nullptr, dump);
    JsonObj *dst = JSON_Parse(dump, strlen(dump));
    ASSERT_NE(nullptr, dst);
    JSON_Free(dump);

    bool b = false;
    EXPECT_TRUE(JSON_GetBoolFromOject(dst, "b", &b));
    EXPECT_EQ(true, b);
    int16_t i16 = 0;
    EXPECT_TRUE(JSON_GetInt16FromOject(dst, "i16", &i16));
    EXPECT_EQ(RT_INT16, i16);
    int32_t i32 = 0;
    EXPECT_TRUE(JSON_GetInt32FromOject(dst, "i32", &i32));
    EXPECT_EQ(RT_INT32, i32);
    int64_t i64 = 0;
    EXPECT_TRUE(JSON_GetInt64FromOject(dst, "i64", &i64));
    EXPECT_EQ(RT_INT64, i64);
    char s[BUF_SIZE_MEDIUM] = { 0 };
    EXPECT_TRUE(JSON_GetStringFromObject(dst, "s", s, sizeof(s)));
    EXPECT_STREQ("softbus", s);
    uint8_t out[BUF_SIZE_SMALL] = { 0 };
    uint32_t outSize = 0;
    EXPECT_TRUE(JSON_GetBytesFromObject(dst, "by", out, sizeof(out), &outSize));
    EXPECT_EQ(static_cast<uint32_t>(ArraySize(BYTES_PAYLOAD_ALT)), outSize);

    JSON_Delete(src);
    JSON_Delete(dst);
}

/*
 * @tc.name: JsonOverwriteKeyTest001
 * @tc.desc: adding an existing key with a different type overwrites it
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonOverwriteKeyTest001, TestSize.Level1)
{
    JsonObj *obj = JSON_CreateObject();
    ASSERT_NE(nullptr, obj);
    EXPECT_TRUE(JSON_AddInt32ToObject(obj, KEY_STR, RT_OVERWRITE_INT));
    EXPECT_TRUE(JSON_AddStringToObject(obj, KEY_STR, "text"));
    char buf[BUF_SIZE_MEDIUM] = { 0 };
    EXPECT_TRUE(JSON_GetStringFromObject(obj, KEY_STR, buf, sizeof(buf)));
    EXPECT_STREQ("text", buf);
    int32_t i = 0;
    EXPECT_FALSE(JSON_GetInt32FromOject(obj, KEY_STR, &i));  // no longer a number
    JSON_Delete(obj);
}

/*
 * @tc.name: JsonNullContextExhaustiveTest001
 * @tc.desc: every mutating/reading API rejects a null-context object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusJsonTest, JsonNullContextExhaustiveTest001, TestSize.Level1)
{
    JsonObj nullObj = MakeNullContextObj();
    int16_t i16 = 0;
    int32_t i32 = 0;
    int64_t i64 = 0;
    bool b = false;
    char buf[BUF_SIZE_SMALL] = { 0 };
    char *out[ARRAY_CAP_SMALL] = { 0 };
    int32_t len = ARRAY_CAP_SMALL;
    uint8_t bytes[ARRAY_CAP_SMALL] = { 0 };
    uint32_t size = 0;

    EXPECT_FALSE(JSON_AddBoolToObject(&nullObj, KEY_BOOL, true));
    EXPECT_FALSE(JSON_AddInt16ToObject(&nullObj, KEY_INT, VAL_INT16));
    EXPECT_FALSE(JSON_AddInt32ToObject(&nullObj, KEY_INT, VAL_INT32));
    EXPECT_FALSE(JSON_AddInt64ToObject(&nullObj, KEY_INT, VAL_INT64));
    EXPECT_FALSE(JSON_AddStringToObject(&nullObj, KEY_STR, "v"));
    EXPECT_FALSE(JSON_AddBytesToObject(&nullObj, KEY_BYTES, bytes, ARRAY_CAP_SMALL));
    const char *arr[] = { "a" };
    EXPECT_FALSE(JSON_AddStringArrayToObject(&nullObj, KEY_ARR, arr, ArraySize(arr)));

    EXPECT_FALSE(JSON_GetBoolFromOject(&nullObj, KEY_BOOL, &b));
    EXPECT_FALSE(JSON_GetInt16FromOject(&nullObj, KEY_INT, &i16));
    EXPECT_FALSE(JSON_GetInt32FromOject(&nullObj, KEY_INT, &i32));
    EXPECT_FALSE(JSON_GetInt64FromOject(&nullObj, KEY_INT, &i64));
    EXPECT_FALSE(JSON_GetStringFromObject(&nullObj, KEY_STR, buf, sizeof(buf)));
    EXPECT_FALSE(JSON_GetBytesFromObject(&nullObj, KEY_BYTES, bytes, ARRAY_CAP_SMALL, &size));
    EXPECT_FALSE(JSON_GetStringArrayFromOject(&nullObj, KEY_ARR, out, &len));
    EXPECT_FALSE(JSON_IsArrayExist(&nullObj, KEY_ARR));
    EXPECT_EQ(nullptr, JSON_PrintUnformatted(&nullObj));
}
