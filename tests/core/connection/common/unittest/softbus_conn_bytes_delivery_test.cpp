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

#include "softbus_conn_bytes_delivery.h"

#include <random>

#include <gtest/gtest.h>

#include "conn_log.h"
#include "softbus_adapter_timer.h"

#include "softbus_conn_common_mock.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS::SoftBus {
class ConnBytesDeliveryTest : public testing::Test {
public:
    static void SetUpTestCase() { }

    static void TearDownTestCase() { }

    void SetUp() override { }

    void TearDown() override { }
};

/*
 * @tc.name: CreateDestroyDeliveryTest
 * @tc.desc: test create and destroy delivery instance
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBytesDeliveryTest, CreateDestoryDeliveryTest, TestSize.Level1)
{
    ConnBytesDelivery *delivery = ConnCreateBytesDelivery(NULL);
    ASSERT_EQ(delivery, nullptr);

    struct ConnBytesDeliveryConfig config = {
        .name = "test_deliver",
        .unitNum = 1 << 3,
        .waitTimeoutMs = 500,
        .idleTimeoutMs = 500,
        .errorRetryWaitMs = 100,
        .handler = nullptr,
    };
    delivery = ConnCreateBytesDelivery(&config);
    ASSERT_EQ(delivery, nullptr);

    ConnBytesHandler noopHandler = [](uint32_t connectionId, uint8_t *data, uint32_t length,
                                       struct ConnBytesAddition addition) {};
    config.handler = noopHandler;
    delivery = ConnCreateBytesDelivery(&config);
    ASSERT_NE(delivery, nullptr);
    ConnDestroyBytesDelivery(delivery);
}

/*
 * @tc.name: DeliverTest
 * @tc.desc: test deliver bytes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBytesDeliveryTest, DeliverTest, TestSize.Level1)
{
    ConnCommonTestMock mock;
    struct ConnBytesDeliveryConfig config = {
        .name = "test_deliver",
        .unitNum = 2,
        .waitTimeoutMs = 500,
        .idleTimeoutMs = 500,
        .errorRetryWaitMs = 100,
        .handler = ConnCommonTestMock::bytesHandler_,
    };
    ConnBytesDelivery *delivery = ConnCreateBytesDelivery(&config);
    ASSERT_NE(delivery, nullptr);

    auto got = std::vector<std::pair<uint32_t, int64_t>>();
    EXPECT_CALL(mock, BytesHandlerHook)
        .WillRepeatedly([&got](uint32_t id, const uint8_t *data, uint32_t length, struct ConnBytesAddition addition) {
            auto p = std::pair<uint32_t, int64_t>(id, addition.seq);
            got.push_back(p);
        });

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distSeq(0, 1000);
    auto delivered = std::vector<std::pair<uint32_t, int64_t>>();
    for (int i = 0; i < 10; i++) {
        int64_t seq = distSeq(gen);
        auto p = std::pair<uint32_t, int64_t>(i, seq);
        delivered.push_back(p);

        auto ret = ConnDeliver(delivery, i, nullptr, 0, {0, 0, 0, seq});
        CONN_LOGI(CONN_TEST, "delivery done, connection id=%{public}u, L/P/F/M/S=0/0/0/0/%{public}ld, ret=%{public}d",
            i, seq, ret);
        EXPECT_EQ(ret, SOFTBUS_OK) << "the " << i << "th deliver failed";
    }

    // delivery task should keep running util idle timeout, check it here
    int32_t interval = 100;
    for (int32_t duration = 0; duration < config.idleTimeoutMs; duration += interval) {
        if (!ConnIsDeliveryTaskRunning(delivery)) {
            ADD_FAILURE() << "duration " << duration << "ms check delivery task is not running";
        }
        SoftBusSleepMs(interval);
    }
    SoftBusSleepMs(interval);
    EXPECT_FALSE(ConnIsDeliveryTaskRunning(delivery));

    EXPECT_EQ(got.size(), delivered.size());
    for (int i = 0; i < got.size() && i < delivered.size(); i++) {
        EXPECT_EQ(got[i].first, delivered[i].first) << "the " << i << "th id is not equal";
        EXPECT_EQ(got[i].second, delivered[i].second) << "the " << i << "th seq is not equal";
    }
    ConnDestroyBytesDelivery(delivery);
}
} // namespace OHOS::SoftBus