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

#include "softbus_rc_collection.h"

#include <gtest/gtest.h>

#include "softbus_conn_common_mock.h"

using namespace testing::ext;
using namespace testing;

extern "C" {
struct DummyObject {
    SOFT_BUS_RC_OBJECT_BASE;
    int32_t payload;
};
}

namespace OHOS::SoftBus {
class SoftbusRcTest : public testing::Test {
public:
    static void SetUpTestCase() { }

    static void TearDownTestCase() { }

    void SetUp() override { }

    void TearDown() override { }
};

/*
 * @tc.name: ConstructDestructTest
 * @tc.desc: construct and destruct test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusRcTest, ConstructDestructTest, TestSize.Level1)
{
    ConnCommonTestMock mock;

    auto ret = SoftBusRcCollectionConstruct(nullptr, nullptr, nullptr);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = SoftBusRcCollectionConstruct("nullptr-collection", nullptr, nullptr);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);

    SoftBusRcCollection foo = {};
    ret = SoftBusRcCollectionConstruct("foo-collection", &foo, nullptr);
    ASSERT_EQ(ret, SOFTBUS_OK);
    SoftBusRcCollectionDestruct(&foo);

    SoftBusRcCollection bar = {};
    ret = SoftBusRcCollectionConstruct("bar-collection", &bar, ConnCommonTestMock::idGenerator_);
    ASSERT_EQ(ret, SOFTBUS_OK);
    SoftBusRcCollectionDestruct(&bar);
}

/*
 * @tc.name: ObjectOperationTest
 * @tc.desc: save, remove and get operation test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusRcTest, ObjectOperationTest, TestSize.Level1)
{
    ConnCommonTestMock mock;
    EXPECT_CALL(mock, IdGeneratorHook).Times(1).WillRepeatedly(([](const SoftBusRcObject *object, uint16_t index) {
        return (uint32_t)index;
    }));
    EXPECT_CALL(mock, FreeObjectHook).Times(0);

    SoftBusRcCollection collection = {};
    auto ret = SoftBusRcCollectionConstruct("foo-collection", &collection, ConnCommonTestMock::idGenerator_);
    ASSERT_EQ(ret, SOFTBUS_OK);

    auto arf = std::make_shared<DummyObject>();
    auto foo = arf.get();
    ret =
        SoftBusRcObjectConstruct("foo-object", reinterpret_cast<SoftBusRcObject *>(foo), ConnCommonTestMock::freeHook_);
    EXPECT_EQ(ret, SOFTBUS_OK);
    const int32_t payload = 100;
    foo->payload = payload;
    ret = SoftBusRcSave(&collection, reinterpret_cast<SoftBusRcObject *>(foo));
    EXPECT_EQ(ret, SOFTBUS_OK);

    auto object = SoftBusRcGetById(&collection, foo->id);
    EXPECT_EQ(object, reinterpret_cast<SoftBusRcObject *>(foo));
    object->Dereference(&object);
    EXPECT_EQ(object, nullptr);

    SoftBusRcObjectMatcher matcher = [](const SoftBusRcObject *object, const void *arg) {
        return ((const DummyObject *)object)->payload == *(const int32_t *)(arg);
    };
    object = SoftBusRcGetCommon(&collection, matcher, &payload);
    EXPECT_EQ(object, reinterpret_cast<SoftBusRcObject *>(foo));
    object->Dereference(&object);
    EXPECT_EQ(object, nullptr);

    SoftBusRcRemove(&collection, reinterpret_cast<SoftBusRcObject *>(foo));
    object = SoftBusRcGetById(&collection, foo->id);
    EXPECT_EQ(object, nullptr);
    // verify expectations of FreeObjectHook, which should never be called, as object is reference by 'foo'
    testing::Mock::VerifyAndClearExpectations(&mock);

    // only release object after last dereference call
    EXPECT_CALL(mock, FreeObjectHook).Times(1).WillRepeatedly([](SoftBusRcObject *object) {
        SoftBusRcObjectDestruct(object);
    });
    foo->Dereference(reinterpret_cast<SoftBusRcObject **>(&foo));
    EXPECT_EQ(foo, nullptr);
    testing::Mock::VerifyAndClearExpectations(&mock);

    SoftBusRcCollectionDestruct(&collection);
}

/*
 * @tc.name: ReleaseObjectWhenDestructTest
 * @tc.desc: release object, which is not removed, when collection destruct
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusRcTest, ReleaseObjectInDestructProgressTest, TestSize.Level1)
{
    ConnCommonTestMock mock;
    EXPECT_CALL(mock, IdGeneratorHook).WillRepeatedly([](const SoftBusRcObject *object, uint16_t index) {
        return (uint32_t)index;
    });
    EXPECT_CALL(mock, FreeObjectHook).Times(0);

    SoftBusRcCollection collection = {};
    auto ret = SoftBusRcCollectionConstruct("bar-collection", &collection, ConnCommonTestMock::idGenerator_);
    ASSERT_EQ(ret, SOFTBUS_OK);

    auto arb = std::make_shared<DummyObject>();
    auto bar = arb.get();
    ret = SoftBusRcObjectConstruct(
        "bar-object ", reinterpret_cast<SoftBusRcObject *>(bar), ConnCommonTestMock::freeHook_);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = SoftBusRcSave(&collection, reinterpret_cast<SoftBusRcObject *>(bar));
    ASSERT_EQ(ret, SOFTBUS_OK);
    // object will deference in connection destruct
    SoftBusRcCollectionDestruct(&collection);
    // verify expectations of FreeObjectHook, which should never be called, as object is reference by 'foo'
    testing::Mock::VerifyAndClearExpectations(&mock);

    // object will deference in destruct
    EXPECT_CALL(mock, FreeObjectHook).Times(1).WillRepeatedly([](SoftBusRcObject *object) {
        SoftBusRcObjectDestruct(object);
    });
    bar->Dereference(reinterpret_cast<SoftBusRcObject **>(&bar));
    EXPECT_EQ(bar, nullptr);
}

} // namespace OHOS::SoftBus