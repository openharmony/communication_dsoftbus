/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "br_proxy_storage.h"

#include <gtest/gtest.h>
#include <cstring>
#include <securec.h>
#include "softbus_adapter_file.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::SoftBus {

class TransBrProxyStorageTest : public testing::Test {
public:
    static constexpr char const *testFilePath = "./trans_br_proxy_storage_test.txt";

    static void SetUpTestCase() { }
    static void TearDownTestCase() { }
    void SetUp() override { }
    void TearDown() override
    {
        (void)SoftBusRemoveFile(testFilePath);
    }
};

void ConstructBrProxyStorageInstance(TransBrProxyStorage &instance)
{
    instance.filepath = TransBrProxyStorageTest::testFilePath;
    (void)SoftBusMutexInit(&instance.mutex, NULL);
    (void)memset_s(&instance.info, sizeof(TransBrProxyStorageInfo), 0, sizeof(TransBrProxyStorageInfo));
    instance.info.userId = -1;
    instance.info.appIndex = -1;
    instance.info.uid = -1;
    instance.loaded = false;
}

void DestructBrProxyStorageInstance(TransBrProxyStorage &instance)
{
    (void)SoftBusMutexDestroy(&instance.mutex);
    (void)memset_s(&instance, sizeof(TransBrProxyStorage), 0, sizeof(TransBrProxyStorage));
}

void ConstructStorageTestInfo(TransBrProxyStorageInfo &info)
{
    (void)memset_s(&info, sizeof(TransBrProxyStorageInfo), 0, sizeof(TransBrProxyStorageInfo));
    (void)strncpy_s(info.bundleName, NAME_MAX_LEN, "com.ohos.softbus.test", NAME_MAX_LEN - 1);
    (void)strncpy_s(info.abilityName, NAME_MAX_LEN, "BrProxyStorageTestAbility", NAME_MAX_LEN - 1);
    info.appIndex = 888; // 888:for test case
    info.userId = 1001; // 1001:for test case
    info.uid = 2002; // 2002:for test case
}

bool CheckStorageInfoEqual(const TransBrProxyStorageInfo &src, const TransBrProxyStorageInfo &dst)
{
    if (strcmp(src.bundleName, dst.bundleName) != 0) {
        return false;
    }
    if (strcmp(src.abilityName, dst.abilityName) != 0) {
        return false;
    }
    if (src.appIndex != dst.appIndex || src.userId != dst.userId || src.uid != dst.uid) {
        return false;
    }
    return true;
}

/**
 * @tc.name: GetInstance
 * @tc.desc: GetInstance, test global unique instance getter for TransBrProxyStorage.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransBrProxyStorageTest, GetInstance, TestSize.Level1)
{
    auto instance = TransBrProxyStorageGetInstance();
    EXPECT_NE(instance, nullptr);
    auto instance2 = TransBrProxyStorageGetInstance();
    EXPECT_EQ(instance, instance2);
}

/**
 * @tc.name: NullCheck
 * @tc.desc: NullCheck, test null instance/info to prevent crashing for all interfaces.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransBrProxyStorageTest, NullCheck, TestSize.Level1)
{
    TransBrProxyStorageInfo info;
    (void)memset_s(&info, sizeof(TransBrProxyStorageInfo), 0, sizeof(TransBrProxyStorageInfo));
    bool ret = TransBrProxyStorageRead(nullptr, &info);
    EXPECT_FALSE(ret);
    auto instance = TransBrProxyStorageGetInstance();
    ret = TransBrProxyStorageRead(instance, nullptr);
    EXPECT_FALSE(ret);
    EXPECT_NO_FATAL_FAILURE(TransBrProxyStorageWrite(nullptr, &info));
    EXPECT_NO_FATAL_FAILURE(TransBrProxyStorageWrite(instance, nullptr));
    EXPECT_NO_FATAL_FAILURE(TransBrProxyStorageClear(nullptr));
}

/**
 * @tc.name: StorageReadWrite
 * @tc.desc: StorageReadWrite, test normal read and write operation for storage info.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransBrProxyStorageTest, StorageReadWrite, TestSize.Level1)
{
    TransBrProxyStorage instance;
    (void)memset_s(&instance, sizeof(TransBrProxyStorage), 0, sizeof(TransBrProxyStorage));
    ConstructBrProxyStorageInstance(instance);
    TransBrProxyStorageInfo writeInfo;
    (void)memset_s(&writeInfo, sizeof(TransBrProxyStorageInfo), 0, sizeof(TransBrProxyStorageInfo));
    ConstructStorageTestInfo(writeInfo);
    TransBrProxyStorageInfo readInfo;
    (void)memset_s(&readInfo, sizeof(TransBrProxyStorageInfo), 0, sizeof(TransBrProxyStorageInfo));

    EXPECT_NO_FATAL_FAILURE(TransBrProxyStorageWrite(&instance, &writeInfo));
    bool ret = TransBrProxyStorageRead(&instance, &readInfo);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CheckStorageInfoEqual(writeInfo, readInfo));

    DestructBrProxyStorageInstance(instance);
}

/**
 * @tc.name: StoragePersistence
 * @tc.desc: StoragePersistence, test storage info persistence to file and reload effective.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransBrProxyStorageTest, StoragePersistence, TestSize.Level1)
{
    TransBrProxyStorage instance1;
    (void)memset_s(&instance1, sizeof(TransBrProxyStorage), 0, sizeof(TransBrProxyStorage));
    ConstructBrProxyStorageInstance(instance1);
    TransBrProxyStorageInfo writeInfo;
    (void)memset_s(&writeInfo, sizeof(TransBrProxyStorageInfo), 0, sizeof(TransBrProxyStorageInfo));
    ConstructStorageTestInfo(writeInfo);
    EXPECT_NO_FATAL_FAILURE(TransBrProxyStorageWrite(&instance1, &writeInfo));
    DestructBrProxyStorageInstance(instance1);

    TransBrProxyStorage instance2;
    (void)memset_s(&instance2, sizeof(TransBrProxyStorage), 0, sizeof(TransBrProxyStorage));
    ConstructBrProxyStorageInstance(instance2);
    TransBrProxyStorageInfo readInfo;
    (void)memset_s(&readInfo, sizeof(TransBrProxyStorageInfo), 0, sizeof(TransBrProxyStorageInfo));
    bool ret = TransBrProxyStorageRead(&instance2, &readInfo);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CheckStorageInfoEqual(writeInfo, readInfo));

    DestructBrProxyStorageInstance(instance2);
}

/**
 * @tc.name: StorageClear
 * @tc.desc: StorageClear, test clear storage info and delete persistence file.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransBrProxyStorageTest, StorageClear, TestSize.Level1)
{
    TransBrProxyStorage instance;
    (void)memset_s(&instance, sizeof(TransBrProxyStorage), 0, sizeof(TransBrProxyStorage));
    ConstructBrProxyStorageInstance(instance);
    TransBrProxyStorageInfo writeInfo;
    (void)memset_s(&writeInfo, sizeof(TransBrProxyStorageInfo), 0, sizeof(TransBrProxyStorageInfo));
    ConstructStorageTestInfo(writeInfo);
    EXPECT_NO_FATAL_FAILURE(TransBrProxyStorageWrite(&instance, &writeInfo));

    EXPECT_NO_FATAL_FAILURE(TransBrProxyStorageClear(&instance));
    TransBrProxyStorageInfo readInfo;
    (void)memset_s(&readInfo, sizeof(TransBrProxyStorageInfo), 0, sizeof(TransBrProxyStorageInfo));
    bool ret = TransBrProxyStorageRead(&instance, &readInfo);
    EXPECT_TRUE(ret);
    EXPECT_EQ(readInfo.userId, 0);
    EXPECT_EQ(readInfo.appIndex, 0);
    EXPECT_EQ(readInfo.uid, 0);
    EXPECT_STREQ(readInfo.bundleName, "");
    EXPECT_STREQ(readInfo.abilityName, "");

    TransBrProxyStorage newInstance;
    (void)memset_s(&newInstance, sizeof(TransBrProxyStorage), 0, sizeof(TransBrProxyStorage));
    ConstructBrProxyStorageInstance(newInstance);
    TransBrProxyStorageInfo newReadInfo;
    (void)memset_s(&newReadInfo, sizeof(TransBrProxyStorageInfo), 0, sizeof(TransBrProxyStorageInfo));
    ret = TransBrProxyStorageRead(&newInstance, &newReadInfo);
    EXPECT_FALSE(ret);
    EXPECT_EQ(newReadInfo.uid, 0);
    EXPECT_STREQ(newReadInfo.bundleName, "");

    DestructBrProxyStorageInstance(instance);
    DestructBrProxyStorageInstance(newInstance);
}

/**
 * @tc.name: StorageFieldIntegrity
 * @tc.desc: StorageFieldIntegrity, test all fields (include uid) integrity after read/write.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransBrProxyStorageTest, StorageFieldIntegrity, TestSize.Level1)
{
    auto instance = TransBrProxyStorageGetInstance();
    ASSERT_NE(instance, nullptr);

    TransBrProxyStorageInfo testInfoArr[2];
    (void)strncpy_s(testInfoArr[0].bundleName, NAME_MAX_LEN, "com.ohos.softbus.arr1", NAME_MAX_LEN - 1);
    (void)strncpy_s(testInfoArr[0].abilityName, NAME_MAX_LEN, "Arr1TestAbility", NAME_MAX_LEN - 1);
    testInfoArr[0].appIndex = 1;
    testInfoArr[0].userId = 100;
    testInfoArr[0].uid = 200;
    (void)strncpy_s(testInfoArr[1].bundleName, NAME_MAX_LEN, "com.ohos.softbus.arr2", NAME_MAX_LEN - 1);
    (void)strncpy_s(testInfoArr[1].abilityName, NAME_MAX_LEN, "Arr2TestAbility", NAME_MAX_LEN - 1);
    testInfoArr[1].appIndex = 99999;
    testInfoArr[1].userId = 0;
    testInfoArr[1].uid = 99999;

    for (auto &writeInfo : testInfoArr) {
        TransBrProxyStorageInfo readInfo;
        EXPECT_NO_FATAL_FAILURE(TransBrProxyStorageWrite(instance, &writeInfo));
        bool ret = TransBrProxyStorageRead(instance, &readInfo);
        EXPECT_TRUE(ret);
        EXPECT_TRUE(CheckStorageInfoEqual(writeInfo, readInfo)) << "field check failed for uid: " << writeInfo.uid;
    }

    EXPECT_NO_FATAL_FAILURE(TransBrProxyStorageClear(instance));
}

/**
 * @tc.name: StorageDefaultValue
 * @tc.desc: StorageDefaultValue, test default value of storage info when no file exists.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransBrProxyStorageTest, StorageDefaultValue, TestSize.Level1)
{
    TransBrProxyStorage instance;
    ConstructBrProxyStorageInstance(instance);
    TransBrProxyStorageInfo readInfo;
    bool ret = TransBrProxyStorageRead(&instance, &readInfo);
    EXPECT_FALSE(ret);

    EXPECT_STREQ(readInfo.bundleName, "");
    EXPECT_STREQ(readInfo.abilityName, "");
    EXPECT_EQ(readInfo.appIndex, 0);
    EXPECT_EQ(readInfo.userId, 0);
    EXPECT_EQ(readInfo.uid, 0);
    EXPECT_FALSE(instance.loaded);

    DestructBrProxyStorageInstance(instance);
}

} // namespace OHOS::SoftBus