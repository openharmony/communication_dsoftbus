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
#include <cstdio>
#include <cstring>
#include <gtest/gtest.h>
#include <securec.h>
#include "common_list.h"
#include "interface_info.h"
#include "resource_manager.h"
#include "negotiate_message.h"
#include "link_info.h"
#include "wifi_config_info.h"
#include "wifi_direct_intent.h"
#include "inner_link.h"
#include "info_container.h"
#include "wifi_direct_p2p_adapter.h"
#include "wifi_direct_protocol.h"
#include "wifi_direct_protocol_factory.h"
#include "wifi_direct_defines.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_feature_config.h"
#include "softbus_log.h"

#define ZERO_NUM 0
#define ONE_NUM 1
#define LENGTH_HEADER 2
#define THIRD_NUM 3
#define FOUR_NUM 4
#define LENGTH_NUM 16

using namespace testing::ext;
namespace OHOS {
class WifiDirectDataTest : public testing::Test {
public:
    WifiDirectDataTest()
    {}
    ~WifiDirectDataTest()
    {}
    static void SetUpTestCase();
    static void TearDownTestCase() {}
    void SetUp() override {}
    void TearDown() override {}
};

void WifiDirectDataTest::SetUpTestCase()
{

}

// interface_info.c
/*
* @tc.name: testGetKeySize001
* @tc.desc: test GetKeySize
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testGetKeySize001, TestSize.Level1)
{
    struct InterfaceInfo* self = InterfaceInfoNew();
    size_t ret = self->getKeySize();
    InterfaceInfoDelete(self);
    EXPECT_EQ(ret, II_KEY_MAX);
}

/*
* @tc.name: testGetContainerName001
* @tc.desc: test GetContainerName
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testGetContainerName001, TestSize.Level1)
{
    struct InterfaceInfo* self = InterfaceInfoNew();
    const char* ret = self->getContainerName();
    string str1(ret);
    InterfaceInfoDelete(self);
    EXPECT_TRUE(str1 == "InterfaceInfo");
}

/*
* @tc.name: testGetName001
* @tc.desc: test GetName
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testGetName001, TestSize.Level1)
{
    struct InterfaceInfo* self = InterfaceInfoNew();
    self->putName(self, "testname");
    char* ret = self->getName(self);
    string str1(ret);
    InterfaceInfoDelete(self);
    EXPECT_TRUE(str1 == "testname");
}

/*
* @tc.name: testPutName001
* @tc.desc: test PutName
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testPutName001, TestSize.Level1)
{
    struct InterfaceInfo* self = InterfaceInfoNew();
    self->putName(self, "testname");
    char* ret = self->getName(self);
    string str1(ret);
    InterfaceInfoDelete(self);
    EXPECT_TRUE(str1 == "testname");
}

/*
* @tc.name: testGetIpString001
* @tc.desc: test GetIpString
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testGetIpString001, TestSize.Level1)
{
    struct InterfaceInfo* self = InterfaceInfoNew();
    string str = "127.0.0.1";
    self->putIpString(self, const_cast<char*>(str.c_str()));
    int32_t ret = self->getIpString(self, const_cast<char*>(str.c_str()), str.size());
    InterfaceInfoDelete(self);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
}

/*
* @tc.name: testPutIpString001
* @tc.desc: test PutIpString
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testPutIpString001, TestSize.Level1)
{
    struct InterfaceInfo* self = InterfaceInfoNew();
    string str = "127.0.0.1";
    self->putIpString(self, const_cast<char*>(str.c_str()));
    int32_t ret = self->getIpString(self, const_cast<char*>(str.c_str()), str.size());
    InterfaceInfoDelete(self);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
}

/*
* @tc.name: testIncreaseRefCount001
* @tc.desc: test IncreaseRefCount and decreaseRefCount
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testIncreaseRefCount001, TestSize.Level1)
{
    struct InterfaceInfo* self = InterfaceInfoNew();
    self->putInt(self, II_KEY_REUSE_COUNT, ZERO_NUM);
    int count = ZERO_NUM;
    self->increaseRefCount(self);
    count += ONE_NUM;
    self->decreaseRefCount(self);
    count -= ONE_NUM;
    InterfaceInfoDelete(self);
    EXPECT_TRUE(count == ZERO_NUM);
}

/*
* @tc.name: testMarshalling001
* @tc.desc: test InterfaceInfo Marshalling
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testMarshalling001, TestSize.Level1)
{
    struct InterfaceInfo* self = InterfaceInfoNew();
    struct WifiDirectProtocol *protocol = GetWifiDirectProtocolFactory()->createProtocol(WIFI_DIRECT_PROTOCOL_TLV);
    self->keyProperties->tag = ONE_NUM;
    self->keyProperties->content = nullptr;
    self->keyProperties->type = STRING;
    self->keyProperties->flag = ONE_NUM;
    bool ret = self->marshalling(self, protocol);
    InterfaceInfoDelete(self);
    EXPECT_TRUE(ret == true);
}

/*
* @tc.name: testMarshalling001
* @tc.desc: test InterfaceInfo Marshalling
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testMarshalling002, TestSize.Level1)
{
    struct InterfaceInfo* self = InterfaceInfoNew();
    struct WifiDirectProtocol *protocol = GetWifiDirectProtocolFactory()->createProtocol(WIFI_DIRECT_PROTOCOL_TLV);
    self->keyProperties->tag = ONE_NUM;
    self->keyProperties->content = nullptr;
    self->keyProperties->type = INT;
    self->keyProperties->flag = ONE_NUM;
    bool ret = self->marshalling(self, protocol);
    InterfaceInfoDelete(self);
    EXPECT_TRUE(ret == true);
}

/*
* @tc.name: testMarshalling001
* @tc.desc: test InterfaceInfo Marshalling
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testMarshalling003, TestSize.Level1)
{
    struct InterfaceInfo* self = InterfaceInfoNew();
    struct WifiDirectProtocol *protocol = GetWifiDirectProtocolFactory()->createProtocol(WIFI_DIRECT_PROTOCOL_TLV);
    self->keyProperties->tag = ONE_NUM;
    self->keyProperties->content = nullptr;
    self->keyProperties->type = BOOLEAN;
    self->keyProperties->flag = ONE_NUM;
    bool ret = self->marshalling(self, protocol);
    InterfaceInfoDelete(self);
    EXPECT_TRUE(ret == true);
}

/*
* @tc.name: testMarshalling001
* @tc.desc: test InterfaceInfo Marshalling
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testMarshalling004, TestSize.Level1)
{
    struct InterfaceInfo* self = InterfaceInfoNew();
    struct WifiDirectProtocol *protocol = GetWifiDirectProtocolFactory()->createProtocol(WIFI_DIRECT_PROTOCOL_TLV);
    self->keyProperties->tag = ONE_NUM;
    self->keyProperties->content = nullptr;
    self->keyProperties->type = AUTH_CONNECTION;
    self->keyProperties->flag = ONE_NUM;
    bool ret = self->marshalling(self, protocol);
    InterfaceInfoDelete(self);
    EXPECT_TRUE(ret == true);
}

/*
* @tc.name: testMarshalling001
* @tc.desc: test InterfaceInfo Marshalling
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testMarshalling005, TestSize.Level1)
{
    struct InterfaceInfo* self = InterfaceInfoNew();
    struct WifiDirectProtocol *protocol = GetWifiDirectProtocolFactory()->createProtocol(WIFI_DIRECT_PROTOCOL_TLV);
    self->keyProperties->tag = ONE_NUM;
    self->keyProperties->content = nullptr;
    self->keyProperties->type = BYTE_ARRAY;
    self->keyProperties->flag = ONE_NUM;
    bool ret = self->marshalling(self, protocol);
    InterfaceInfoDelete(self);
    EXPECT_TRUE(ret == true);
}

/*
* @tc.name: testUnmarshalling001
* @tc.desc: test InterfaceInfo Unmarshalling
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testUnmarshalling001, TestSize.Level1)
{
    struct InterfaceInfo* self = InterfaceInfoNew();
    struct WifiDirectProtocol *protocol = GetWifiDirectProtocolFactory()->createProtocol(WIFI_DIRECT_PROTOCOL_TLV);
    self->keyProperties->tag = ONE_NUM;
    self->keyProperties->content = nullptr;
    self->keyProperties->type = AUTH_CONNECTION;
    self->keyProperties->flag = ONE_NUM;
    self->marshalling(self, protocol);
    bool ret = self->unmarshalling(self, protocol);
    InterfaceInfoDelete(self);
    EXPECT_TRUE(ret == true);
}

/*
* @tc.name: testUnmarshalling002
* @tc.desc: test InterfaceInfo Unmarshalling
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testUnmarshalling002, TestSize.Level1)
{
    struct InterfaceInfo* self = InterfaceInfoNew();
    struct WifiDirectProtocol *protocol = GetWifiDirectProtocolFactory()->createProtocol(WIFI_DIRECT_PROTOCOL_TLV);
    self->keyProperties->tag = ONE_NUM;
    self->keyProperties->content = nullptr;
    self->keyProperties->type = STRING;
    self->keyProperties->flag = ONE_NUM;
    self->marshalling(self, protocol);
    bool ret = self->unmarshalling(self, protocol);
    InterfaceInfoDelete(self);
    EXPECT_TRUE(ret == true);
}

/*
* @tc.name: testUnmarshalling003
* @tc.desc: test InterfaceInfo Unmarshalling
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testUnmarshalling003, TestSize.Level1)
{
    struct InterfaceInfo* self = InterfaceInfoNew();
    struct WifiDirectProtocol *protocol = GetWifiDirectProtocolFactory()->createProtocol(WIFI_DIRECT_PROTOCOL_TLV);
    self->keyProperties->tag = ONE_NUM;
    self->keyProperties->content = nullptr;
    self->keyProperties->type = INT;
    self->keyProperties->flag = ONE_NUM;
    self->marshalling(self, protocol);
    bool ret = self->unmarshalling(self, protocol);
    InterfaceInfoDelete(self);
    EXPECT_TRUE(ret == true);
}

/*
* @tc.name: testUnmarshalling004
* @tc.desc: test InterfaceInfo Unmarshalling
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testUnmarshalling004, TestSize.Level1)
{
    struct InterfaceInfo* self = InterfaceInfoNew();
    struct WifiDirectProtocol *protocol = GetWifiDirectProtocolFactory()->createProtocol(WIFI_DIRECT_PROTOCOL_TLV);
    self->keyProperties->tag = ONE_NUM;
    self->keyProperties->content = nullptr;
    self->keyProperties->type = BOOLEAN;
    self->keyProperties->flag = ONE_NUM;
    self->marshalling(self, protocol);
    bool ret = self->unmarshalling(self, protocol);
    InterfaceInfoDelete(self);
    EXPECT_TRUE(ret == true);
}

/*
* @tc.name: testUnmarshalling005
* @tc.desc: test InterfaceInfo Unmarshalling
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testUnmarshalling005, TestSize.Level1)
{
    struct InterfaceInfo* self = InterfaceInfoNew();
    struct WifiDirectProtocol *protocol = GetWifiDirectProtocolFactory()->createProtocol(WIFI_DIRECT_PROTOCOL_TLV);
    self->keyProperties->tag = ONE_NUM;
    self->keyProperties->content = nullptr;
    self->keyProperties->type = BYTE_ARRAY;
    self->keyProperties->flag = ONE_NUM;
    self->marshalling(self, protocol);
    bool ret = self->unmarshalling(self, protocol);
    InterfaceInfoDelete(self);
    EXPECT_TRUE(ret == true);
}

/*
* @tc.name: testInterfaceInfoDestructor001
* @tc.desc: test InterfaceInfoDestructor
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testInterfaceInfoDestructor001, TestSize.Level1)
{
    struct InterfaceInfo* self = InterfaceInfoNew();
    bool ret = true;
    self->keyProperties->tag = ONE_NUM;
    self->keyProperties->content = nullptr;
    self->keyProperties->type = INT;
    self->keyProperties->flag = CONTAINER_ARRAY_FLAG;
    self->destructor(self);
    InterfaceInfoDelete(self);
    EXPECT_TRUE(ret == true);
}

// resource_manager.c
/*
 * @tc.name: testInitWifiDirectInfoTest001
 * @tc.desc: test InitWifiDirectInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectDataTest, testInitWifiDirectInfoTest001, TestSize.Level1)
{
    auto ret = GetResourceManager()->initWifiDirectInfo();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: testNotifyInterfaceInfoChange001
 * @tc.desc: test NotifyInterfaceInfoChange
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectDataTest, testNotifyInterfaceInfoChange001, TestSize.Level1)
{
    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo("p2p0");
    bool ret = true;
    GetResourceManager()->notifyInterfaceInfoChange(info);
    EXPECT_TRUE(ret == true);
}

/*
 * @tc.name: testGetInterfaceInfoTest001
 * @tc.desc: test getInterfaceInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectDataTest, testGetInterfaceInfoTest001, TestSize.Level1)
{
    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo("666");
    EXPECT_EQ(info, NULL);
}
/*
* @tc.name: testIsInterfaceAvailable001
* @tc.desc: test IsInterfaceAvailable
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testIsInterfaceAvailable001, TestSize.Level1)
{
    ResourceManager* self = GetResourceManager();
    const char *interface = "isEnable";
    bool ret = self->isInterfaceAvailable(interface);
    EXPECT_TRUE(ret == false);
}

/*
* @tc.name: testIsInterfaceAvailable002
* @tc.desc: test IsInterfaceAvailable
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testIsInterfaceAvailable002, TestSize.Level1)
{
    ResourceManager* self = GetResourceManager();
    const char *interface = "registerListener";
    bool ret = self->isInterfaceAvailable(interface);
    EXPECT_TRUE(ret == false);
}

// link_info.c

/*
* @tc.name: testGetKeySize001
* @tc.desc: test GetKeySize
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testLinkInfoGetKeySize001, TestSize.Level1)
{
    struct LinkInfo *linkInfo = LinkInfoNew();
    size_t ret = linkInfo->getKeySize();
    LinkInfoDelete(linkInfo);
    EXPECT_EQ(ret, LI_KEY_MAX);
}

/*
* @tc.name: testGetContainerName001
* @tc.desc: test GetContainerName
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testLinkInfoGetContainerName001, TestSize.Level1)
{
    struct LinkInfo *linkInfo = LinkInfoNew();
    const char* ret = linkInfo->getContainerName();
    string str1(ret);
    LinkInfoDelete(linkInfo);
    EXPECT_TRUE(str1 == "LinkInfo");
}

/*
* @tc.name: testMarshalling001
* @tc.desc: test Marshalling
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testLinkInfoMarshalling001, TestSize.Level1)
{
    struct LinkInfo *linkInfo = LinkInfoNew();
    struct WifiDirectProtocol *protocol = GetWifiDirectProtocolFactory()->createProtocol(WIFI_DIRECT_PROTOCOL_TLV);
    linkInfo->keyProperties->tag = ONE_NUM;
    linkInfo->keyProperties->content = nullptr;
    linkInfo->keyProperties->type = BOOLEAN;
    linkInfo->keyProperties->flag = ONE_NUM;
    bool ret = linkInfo->marshalling(linkInfo, protocol);
    LinkInfoDelete(linkInfo);
    EXPECT_TRUE(ret == true);
}

/*
* @tc.name: testMarshalling002
* @tc.desc: test Marshalling
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testLinkInfoMarshalling002, TestSize.Level1)
{
    struct LinkInfo *linkInfo = LinkInfoNew();
    struct WifiDirectProtocol *protocol = GetWifiDirectProtocolFactory()->createProtocol(WIFI_DIRECT_PROTOCOL_TLV);
    linkInfo->keyProperties->tag = ONE_NUM;
    linkInfo->keyProperties->content = nullptr;
    linkInfo->keyProperties->type = STRING;
    linkInfo->keyProperties->flag = ONE_NUM;
    bool ret = linkInfo->marshalling(linkInfo, protocol);
    LinkInfoDelete(linkInfo);
    EXPECT_TRUE(ret == true);
}

/*
* @tc.name: testMarshalling003
* @tc.desc: test Marshalling
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testLinkInfoMarshalling003, TestSize.Level1)
{
    struct LinkInfo *linkInfo = LinkInfoNew();
    struct WifiDirectProtocol *protocol = GetWifiDirectProtocolFactory()->createProtocol(WIFI_DIRECT_PROTOCOL_TLV);
    linkInfo->keyProperties->tag = ONE_NUM;
    linkInfo->keyProperties->content = nullptr;
    linkInfo->keyProperties->type = INT;
    linkInfo->keyProperties->flag = ONE_NUM;
    bool ret = linkInfo->marshalling(linkInfo, protocol);
    LinkInfoDelete(linkInfo);
    EXPECT_TRUE(ret == true);
}

/*
* @tc.name: testMarshalling004
* @tc.desc: test Marshalling
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testLinkInfoMarshalling004, TestSize.Level1)
{
    struct LinkInfo *linkInfo = LinkInfoNew();
    struct WifiDirectProtocol *protocol = GetWifiDirectProtocolFactory()->createProtocol(WIFI_DIRECT_PROTOCOL_TLV);
    linkInfo->keyProperties->tag = ONE_NUM;
    linkInfo->keyProperties->content = nullptr;
    linkInfo->keyProperties->type = IPV4_INFO;
    linkInfo->keyProperties->flag = ONE_NUM;
    bool ret = linkInfo->marshalling(linkInfo, protocol);
    LinkInfoDelete(linkInfo);
    EXPECT_TRUE(ret == true);
}

/*
* @tc.name: testMarshalling005
* @tc.desc: test Marshalling
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testLinkInfoMarshalling005, TestSize.Level1)
{
    struct LinkInfo *linkInfo = LinkInfoNew();
    struct WifiDirectProtocol *protocol = GetWifiDirectProtocolFactory()->createProtocol(WIFI_DIRECT_PROTOCOL_TLV);
    linkInfo->keyProperties->tag = ONE_NUM;
    linkInfo->keyProperties->content = nullptr;
    linkInfo->keyProperties->type = IPV4_INFO_ARRAY;
    linkInfo->keyProperties->flag = ONE_NUM;
    bool ret = linkInfo->marshalling(linkInfo, protocol);
    LinkInfoDelete(linkInfo);
    EXPECT_TRUE(ret == true);
}

/*
* @tc.name: testUnmarshalling001
* @tc.desc: test Unmarshalling
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testLinkInfoUnmarshalling001, TestSize.Level1)
{
    struct LinkInfo *linkInfo = LinkInfoNew();
    struct WifiDirectProtocol *protocol = GetWifiDirectProtocolFactory()->createProtocol(WIFI_DIRECT_PROTOCOL_TLV);
    linkInfo->keyProperties->tag = ONE_NUM;
    linkInfo->keyProperties->content = nullptr;
    linkInfo->keyProperties->type = IPV4_INFO_ARRAY;
    linkInfo->keyProperties->flag = ONE_NUM;
    linkInfo->marshalling(linkInfo, protocol);
    bool ret = linkInfo->unmarshalling(linkInfo, protocol);
    LinkInfoDelete(linkInfo);
    EXPECT_TRUE(ret == true);
}

/*
* @tc.name: testUnmarshalling002
* @tc.desc: test Unmarshalling
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testLinkInfoUnmarshalling002, TestSize.Level1)
{
    struct LinkInfo *linkInfo = LinkInfoNew();
    struct WifiDirectProtocol *protocol = GetWifiDirectProtocolFactory()->createProtocol(WIFI_DIRECT_PROTOCOL_TLV);
    linkInfo->keyProperties->tag = ONE_NUM;
    linkInfo->keyProperties->content = nullptr;
    linkInfo->keyProperties->type = INT;
    linkInfo->keyProperties->flag = ONE_NUM;
    linkInfo->marshalling(linkInfo, protocol);
    bool ret = linkInfo->unmarshalling(linkInfo, protocol);
    LinkInfoDelete(linkInfo);
    EXPECT_TRUE(ret == true);
}

/*
* @tc.name: testUnmarshalling003
* @tc.desc: test Unmarshalling
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testLinkInfoUnmarshalling003, TestSize.Level1)
{
    struct LinkInfo *linkInfo = LinkInfoNew();
    struct WifiDirectProtocol *protocol = GetWifiDirectProtocolFactory()->createProtocol(WIFI_DIRECT_PROTOCOL_TLV);
    linkInfo->keyProperties->tag = ONE_NUM;
    linkInfo->keyProperties->content = nullptr;
    linkInfo->keyProperties->type = BOOLEAN;
    linkInfo->keyProperties->flag = ONE_NUM;
    linkInfo->marshalling(linkInfo, protocol);
    bool ret = linkInfo->unmarshalling(linkInfo, protocol);
    LinkInfoDelete(linkInfo);
    EXPECT_TRUE(ret == true);
}

/*
* @tc.name: testUnmarshalling004
* @tc.desc: test Unmarshalling
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testLinkInfoUnmarshalling004, TestSize.Level1)
{
    struct LinkInfo *linkInfo = LinkInfoNew();
    struct WifiDirectProtocol *protocol = GetWifiDirectProtocolFactory()->createProtocol(WIFI_DIRECT_PROTOCOL_TLV);
    linkInfo->keyProperties->tag = ONE_NUM;
    linkInfo->keyProperties->content = nullptr;
    linkInfo->keyProperties->type = STRING;
    linkInfo->keyProperties->flag = ONE_NUM;
    linkInfo->marshalling(linkInfo, protocol);
    bool ret = linkInfo->unmarshalling(linkInfo, protocol);
    LinkInfoDelete(linkInfo);
    EXPECT_TRUE(ret == true);
}

/*
* @tc.name: testUnmarshalling005
* @tc.desc: test Unmarshalling
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testLinkInfoUnmarshalling005, TestSize.Level1)
{
    struct LinkInfo *linkInfo = LinkInfoNew();
    struct WifiDirectProtocol *protocol = GetWifiDirectProtocolFactory()->createProtocol(WIFI_DIRECT_PROTOCOL_TLV);
    linkInfo->keyProperties->tag = ONE_NUM;
    linkInfo->keyProperties->content = nullptr;
    linkInfo->keyProperties->type = IPV4_INFO;
    linkInfo->keyProperties->flag = ONE_NUM;
    linkInfo->marshalling(linkInfo, protocol);
    bool ret = linkInfo->unmarshalling(linkInfo, protocol);
    LinkInfoDelete(linkInfo);
    EXPECT_TRUE(ret == true);
}

// negotiate_message.c

/*
* @tc.name: testGetKeySize001
* @tc.desc: test GetKeySize
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testNegotiateMessageGetKeySize001, TestSize.Level1)
{
    struct NegotiateMessage* self = NegotiateMessageNew();
    size_t ret = self->getKeySize();
    NegotiateMessageDelete(self);
    EXPECT_EQ(ret, NM_KEY_MAX);
}

/*
* @tc.name: testGetContainerName001
* @tc.desc: test GetContainerName
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testNegotiateMessageGetContainerName001, TestSize.Level1)
{
    struct NegotiateMessage* self = NegotiateMessageNew();
    const char* ret = self->getContainerName();
    string str1(ret);
    NegotiateMessageDelete(self);
    EXPECT_TRUE(str1 == "NegotiateMessage");
}

/*
* @tc.name: testMarshalling001
* @tc.desc: test Marshalling
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testNegotiateMessageMarshalling001, TestSize.Level1)
{
    struct NegotiateMessage* self = NegotiateMessageNew();
    struct WifiDirectProtocol *protocol = GetWifiDirectProtocolFactory()->createProtocol(WIFI_DIRECT_PROTOCOL_TLV);
    self->keyProperties->tag = ONE_NUM;
    self->keyProperties->content = nullptr;
    self->keyProperties->type = BOOLEAN;
    self->keyProperties->flag = ONE_NUM;
    bool ret = self->marshalling(self, protocol);
    NegotiateMessageDelete(self);
    EXPECT_TRUE(ret == true);
}

/*
* @tc.name: testMarshalling002
* @tc.desc: test Marshalling
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testNegotiateMessageMarshalling002, TestSize.Level1)
{
    struct NegotiateMessage* self = NegotiateMessageNew();
    struct WifiDirectProtocol *protocol = GetWifiDirectProtocolFactory()->createProtocol(WIFI_DIRECT_PROTOCOL_TLV);
    self->keyProperties->tag = ONE_NUM;
    self->keyProperties->content = nullptr;
    self->keyProperties->type = INT;
    self->keyProperties->flag = ONE_NUM;
    bool ret = self->marshalling(self, protocol);
    NegotiateMessageDelete(self);
    EXPECT_TRUE(ret == true);
}

/*
* @tc.name: testMarshalling003
* @tc.desc: test Marshalling
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testNegotiateMessageMarshalling003, TestSize.Level1)
{
    struct NegotiateMessage* self = NegotiateMessageNew();
    struct WifiDirectProtocol *protocol = GetWifiDirectProtocolFactory()->createProtocol(WIFI_DIRECT_PROTOCOL_TLV);
    self->keyProperties->tag = ONE_NUM;
    self->keyProperties->content = nullptr;
    self->keyProperties->type = STRING;
    self->keyProperties->flag = ONE_NUM;
    bool ret = self->marshalling(self, protocol);
    NegotiateMessageDelete(self);
    EXPECT_TRUE(ret == true);
}

/*
* @tc.name: testMarshalling004
* @tc.desc: test Marshalling
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testNegotiateMessageMarshalling004, TestSize.Level1)
{
    struct NegotiateMessage* self = NegotiateMessageNew();
    struct WifiDirectProtocol *protocol = GetWifiDirectProtocolFactory()->createProtocol(WIFI_DIRECT_PROTOCOL_TLV);
    self->keyProperties->tag = ONE_NUM;
    self->keyProperties->content = nullptr;
    self->keyProperties->type = IPV4_INFO_ARRAY;
    self->keyProperties->flag = ONE_NUM;
    bool ret = self->marshalling(self, protocol);
    NegotiateMessageDelete(self);
    EXPECT_TRUE(ret == true);
}

/*
* @tc.name: testMarshalling005
* @tc.desc: test Marshalling
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testNegotiateMessageMarshalling005, TestSize.Level1)
{
    struct NegotiateMessage* self = NegotiateMessageNew();
    struct WifiDirectProtocol *protocol = GetWifiDirectProtocolFactory()->createProtocol(WIFI_DIRECT_PROTOCOL_TLV);
    self->keyProperties->tag = ONE_NUM;
    self->keyProperties->content = nullptr;
    self->keyProperties->type = LINK_INFO;
    self->keyProperties->flag = ONE_NUM;
    bool ret = self->marshalling(self, protocol);
    NegotiateMessageDelete(self);
    EXPECT_TRUE(ret == true);
}

/*
* @tc.name: testMarshalling006
* @tc.desc: test Marshalling
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testNegotiateMessageMarshalling006, TestSize.Level1)
{
    struct NegotiateMessage* self = NegotiateMessageNew();
    struct WifiDirectProtocol *protocol = GetWifiDirectProtocolFactory()->createProtocol(WIFI_DIRECT_PROTOCOL_TLV);
    self->keyProperties->tag = ONE_NUM;
    self->keyProperties->content = nullptr;
    self->keyProperties->type = INTERFACE_INFO_ARRAY;
    self->keyProperties->flag = ONE_NUM;
    bool ret = self->marshalling(self, protocol);
    NegotiateMessageDelete(self);
    EXPECT_TRUE(ret == true);
}

/*
* @tc.name: testUnmarshalling001
* @tc.desc: test Unmarshalling
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testNegotiateMessageUnmarshalling001, TestSize.Level1)
{
    struct NegotiateMessage* self = NegotiateMessageNew();
    struct WifiDirectProtocol *protocol = GetWifiDirectProtocolFactory()->createProtocol(WIFI_DIRECT_PROTOCOL_TLV);
    self->keyProperties->tag = ONE_NUM;
    self->keyProperties->content = nullptr;
    self->keyProperties->type = BOOLEAN;
    self->keyProperties->flag = ONE_NUM;
    self->marshalling(self, protocol);
    bool ret = self->unmarshalling(self, protocol);
    NegotiateMessageDelete(self);
    EXPECT_TRUE(ret == true);
}

/*
* @tc.name: testUnmarshalling002
* @tc.desc: test Unmarshalling
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testNegotiateMessageUnmarshalling002, TestSize.Level1)
{
    struct NegotiateMessage* self = NegotiateMessageNew();
    struct WifiDirectProtocol *protocol = GetWifiDirectProtocolFactory()->createProtocol(WIFI_DIRECT_PROTOCOL_TLV);
    self->keyProperties->tag = ONE_NUM;
    self->keyProperties->content = nullptr;
    self->keyProperties->type = INT;
    self->keyProperties->flag = ONE_NUM;
    self->marshalling(self, protocol);
    bool ret = self->unmarshalling(self, protocol);
    NegotiateMessageDelete(self);
    EXPECT_TRUE(ret == true);
}

/*
* @tc.name: testUnmarshalling003
* @tc.desc: test Unmarshalling
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testNegotiateMessageUnmarshalling003, TestSize.Level1)
{
    struct NegotiateMessage* self = NegotiateMessageNew();
    struct WifiDirectProtocol *protocol = GetWifiDirectProtocolFactory()->createProtocol(WIFI_DIRECT_PROTOCOL_TLV);
    self->keyProperties->tag = ONE_NUM;
    self->keyProperties->content = nullptr;
    self->keyProperties->type = IPV4_INFO_ARRAY;
    self->keyProperties->flag = ONE_NUM;
    self->marshalling(self, protocol);
    bool ret = self->unmarshalling(self, protocol);
    NegotiateMessageDelete(self);
    EXPECT_TRUE(ret == true);
}

/*
* @tc.name: testUnmarshalling004
* @tc.desc: test Unmarshalling
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testNegotiateMessageUnmarshalling004, TestSize.Level1)
{
    struct NegotiateMessage* self = NegotiateMessageNew();
    struct WifiDirectProtocol *protocol = GetWifiDirectProtocolFactory()->createProtocol(WIFI_DIRECT_PROTOCOL_TLV);
    self->keyProperties->tag = ONE_NUM;
    self->keyProperties->content = nullptr;
    self->keyProperties->type = STRING;
    self->keyProperties->flag = ONE_NUM;
    self->marshalling(self, protocol);
    bool ret = self->unmarshalling(self, protocol);
    NegotiateMessageDelete(self);
    EXPECT_TRUE(ret == true);
}

/*
* @tc.name: testUnmarshalling005
* @tc.desc: test Unmarshalling
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testNegotiateMessageUnmarshalling005, TestSize.Level1)
{
    struct NegotiateMessage* self = NegotiateMessageNew();
    struct WifiDirectProtocol *protocol = GetWifiDirectProtocolFactory()->createProtocol(WIFI_DIRECT_PROTOCOL_TLV);
    self->keyProperties->tag = ONE_NUM;
    self->keyProperties->content = nullptr;
    self->keyProperties->type = INTERFACE_INFO_ARRAY;
    self->keyProperties->flag = ONE_NUM;
    self->marshalling(self, protocol);
    bool ret = self->unmarshalling(self, protocol);
    NegotiateMessageDelete(self);
    EXPECT_TRUE(ret == true);
}

/*
* @tc.name: testUnmarshalling006
* @tc.desc: test Unmarshalling
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testNegotiateMessageUnmarshalling006, TestSize.Level1)
{
    struct NegotiateMessage* self = NegotiateMessageNew();
    struct WifiDirectProtocol *protocol = GetWifiDirectProtocolFactory()->createProtocol(WIFI_DIRECT_PROTOCOL_TLV);
    self->keyProperties->tag = ONE_NUM;
    self->keyProperties->content = nullptr;
    self->keyProperties->type = LINK_INFO;
    self->keyProperties->flag = ONE_NUM;
    self->marshalling(self, protocol);
    bool ret = self->unmarshalling(self, protocol);
    NegotiateMessageDelete(self);
    EXPECT_TRUE(ret == true);
}

// wifi_config_info.c

/*
* @tc.name: testGetKeySize001
* @tc.desc: test GetKeySize
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testWifiConfigInfoGetKeySize001, TestSize.Level1)
{
    struct WifiConfigInfo configInfo;
    size_t configSize = WIFI_CFG_INFO_MAX_LEN;
    uint8_t config[WIFI_CFG_INFO_MAX_LEN] = {0};
    GetWifiDirectP2pAdapter()->getSelfWifiConfigInfoV2(config, &configSize);
    WifiConfigInfoConstruct(&configInfo, config + LENGTH_HEADER, configSize - LENGTH_HEADER);
    size_t ret = configInfo.getKeySize();
    EXPECT_EQ(ret, WC_KEY_MAX);
}

/*
* @tc.name: testGetContainerName001
* @tc.desc: test GetContainerName
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testWifiConfigInfoGetContainerName001, TestSize.Level1)
{
    struct WifiConfigInfo configInfo;
    size_t configSize = WIFI_CFG_INFO_MAX_LEN;
    uint8_t config[WIFI_CFG_INFO_MAX_LEN] = {0};
    GetWifiDirectP2pAdapter()->getSelfWifiConfigInfoV2(config, &configSize);
    WifiConfigInfoConstruct(&configInfo, config + LENGTH_HEADER, configSize - LENGTH_HEADER);
    const char* ret = configInfo.getContainerName();
    string str1(ret);
    EXPECT_TRUE(str1 == "WifiConfigInfo");
}

/*
* @tc.name: testUnmarshalling001
* @tc.desc: test Unmarshalling
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testWifiConfigInfoUnmarshalling001, TestSize.Level1)
{

    struct WifiConfigInfo configInfo;
    size_t configSize = WIFI_CFG_INFO_MAX_LEN;
    uint8_t config[WIFI_CFG_INFO_MAX_LEN] = {0};
    GetWifiDirectP2pAdapter()->getSelfWifiConfigInfoV2(config, &configSize);
    WifiConfigInfoConstruct(&configInfo, config + LENGTH_HEADER, configSize - LENGTH_HEADER);
    struct WifiDirectProtocol *protocol = GetWifiDirectProtocolFactory()->createProtocol(WIFI_DIRECT_PROTOCOL_TLV);
    configInfo.keyProperties->tag = ONE_NUM;
    configInfo.keyProperties->content = nullptr;
    configInfo.keyProperties->type = INT;
    configInfo.keyProperties->flag = ONE_NUM;
    bool ret = configInfo.unmarshalling(&configInfo, protocol);
    EXPECT_TRUE(ret == true);
}

/*
* @tc.name: testUnmarshalling002
* @tc.desc: test Unmarshalling
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testWifiConfigInfoUnmarshalling002, TestSize.Level1)
{
    struct WifiConfigInfo configInfo;
    size_t configSize = WIFI_CFG_INFO_MAX_LEN;
    uint8_t config[WIFI_CFG_INFO_MAX_LEN] = {0};
    GetWifiDirectP2pAdapter()->getSelfWifiConfigInfoV2(config, &configSize);
    WifiConfigInfoConstruct(&configInfo, config + LENGTH_HEADER, configSize - LENGTH_HEADER);
    struct WifiDirectProtocol *protocol = GetWifiDirectProtocolFactory()->createProtocol(WIFI_DIRECT_PROTOCOL_TLV);
    configInfo.keyProperties->tag = ONE_NUM;
    configInfo.keyProperties->content = nullptr;
    configInfo.keyProperties->type = INT_ARRAY;
    configInfo.keyProperties->flag = ONE_NUM;
    bool ret = configInfo.unmarshalling(&configInfo, protocol);
    EXPECT_TRUE(ret == true);
}

/*
* @tc.name: testUnmarshalling003
* @tc.desc: test Unmarshalling
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testWifiConfigInfoUnmarshalling003, TestSize.Level1)
{
    struct WifiConfigInfo configInfo;
    size_t configSize = WIFI_CFG_INFO_MAX_LEN;
    uint8_t config[WIFI_CFG_INFO_MAX_LEN] = {0};
    GetWifiDirectP2pAdapter()->getSelfWifiConfigInfoV2(config, &configSize);
    WifiConfigInfoConstruct(&configInfo, config + LENGTH_HEADER, configSize - LENGTH_HEADER);
    struct WifiDirectProtocol *protocol = GetWifiDirectProtocolFactory()->createProtocol(WIFI_DIRECT_PROTOCOL_TLV);
    configInfo.keyProperties->tag = ONE_NUM;
    configInfo.keyProperties->content = nullptr;
    configInfo.keyProperties->type = STRING;
    configInfo.keyProperties->flag = ONE_NUM;
    bool ret = configInfo.unmarshalling(&configInfo, protocol);
    EXPECT_TRUE(ret == true);
}

/*
* @tc.name: testUnmarshalling004
* @tc.desc: test Unmarshalling
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testWifiConfigInfoUnmarshalling004, TestSize.Level1)
{
    struct WifiConfigInfo configInfo;
    size_t configSize = WIFI_CFG_INFO_MAX_LEN;
    uint8_t config[WIFI_CFG_INFO_MAX_LEN] = {0};
    GetWifiDirectP2pAdapter()->getSelfWifiConfigInfoV2(config, &configSize);
    WifiConfigInfoConstruct(&configInfo, config + LENGTH_HEADER, configSize - LENGTH_HEADER);
    struct WifiDirectProtocol *protocol = GetWifiDirectProtocolFactory()->createProtocol(WIFI_DIRECT_PROTOCOL_TLV);
    configInfo.keyProperties->tag = ONE_NUM;
    configInfo.keyProperties->content = nullptr;
    configInfo.keyProperties->type = LONG;
    configInfo.keyProperties->flag = ONE_NUM;
    bool ret = configInfo.unmarshalling(&configInfo, protocol);
    EXPECT_TRUE(ret == true);
}

/*
* @tc.name: testUnmarshalling005
* @tc.desc: test Unmarshalling
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testWifiConfigInfoUnmarshalling005, TestSize.Level1)
{
    struct WifiConfigInfo configInfo;
    size_t configSize = WIFI_CFG_INFO_MAX_LEN;
    uint8_t config[WIFI_CFG_INFO_MAX_LEN] = {0};
    GetWifiDirectP2pAdapter()->getSelfWifiConfigInfoV2(config, &configSize);
    WifiConfigInfoConstruct(&configInfo, config + LENGTH_HEADER, configSize - LENGTH_HEADER);
    struct WifiDirectProtocol *protocol = GetWifiDirectProtocolFactory()->createProtocol(WIFI_DIRECT_PROTOCOL_TLV);
    configInfo.keyProperties->tag = ONE_NUM;
    configInfo.keyProperties->content = nullptr;
    configInfo.keyProperties->type = INTERFACE_INFO_ARRAY;
    configInfo.keyProperties->flag = ONE_NUM;
    bool ret = configInfo.unmarshalling(&configInfo, protocol);
    EXPECT_TRUE(ret == true);
}

/*
* @tc.name: testUnmarshalling006
* @tc.desc: test Unmarshalling
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testWifiConfigInfoUnmarshalling006, TestSize.Level1)
{
    struct WifiConfigInfo configInfo;
    size_t configSize = WIFI_CFG_INFO_MAX_LEN;
    uint8_t config[WIFI_CFG_INFO_MAX_LEN] = {0};
    GetWifiDirectP2pAdapter()->getSelfWifiConfigInfoV2(config, &configSize);
    WifiConfigInfoConstruct(&configInfo, config + LENGTH_HEADER, configSize - LENGTH_HEADER);
    struct WifiDirectProtocol *protocol = GetWifiDirectProtocolFactory()->createProtocol(WIFI_DIRECT_PROTOCOL_TLV);
    configInfo.keyProperties->tag = ONE_NUM;
    configInfo.keyProperties->content = nullptr;
    configInfo.keyProperties->type = BYTE;
    configInfo.keyProperties->flag = ONE_NUM;
    bool ret = configInfo.unmarshalling(&configInfo, protocol);
    EXPECT_TRUE(ret == true);
}

// wifi_direct_intent.c

/*
* @tc.name: testGetKeySize001
* @tc.desc: test GetKeySize
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testWifiDirectIntentGetKeySize001, TestSize.Level1)
{
    struct WifiDirectIntent* self = WifiDirectIntentNew();
    size_t ret = self->getKeySize();
    WifiDirectIntentDelete(self);
    EXPECT_EQ(ret, INTENT_KEY_MAX);
}

// inner_link.c

/*
* @tc.name: testGetKeySize001
* @tc.desc: test GetKeySize
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testInnerLinkGetKeySize001, TestSize.Level1)
{
    struct InnerLink* self = InnerLinkNew();
    size_t ret = self->getKeySize();
    InnerLinkDelete(self);
    EXPECT_EQ(ret, IL_KEY_MAX);
}

/*
* @tc.name: testGetContainerName001
* @tc.desc: test GetContainerName
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testInnerLinkGetContainerName001, TestSize.Level1)
{
    struct InnerLink* self = InnerLinkNew();
    const char* ret = self->getContainerName();
    string str1(ret);
    InnerLinkDelete(self);
    EXPECT_TRUE(str1 == "InnerLink");
}

/*
* @tc.name: testMarshalling001
* @tc.desc: test Marshalling
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testInnerLinkMarshalling001, TestSize.Level1)
{
    struct InnerLink* self = InnerLinkNew();
    struct WifiDirectProtocol *protocol = GetWifiDirectProtocolFactory()->createProtocol(WIFI_DIRECT_PROTOCOL_TLV);
    self->keyProperties->tag = ONE_NUM;
    self->keyProperties->content = nullptr;
    self->keyProperties->type = BOOLEAN;
    self->keyProperties->flag = ONE_NUM;
    bool ret = self->marshalling(self, protocol);
    InnerLinkDelete(self);
    EXPECT_TRUE(ret == true);
}

/*
* @tc.name: testMarshalling002
* @tc.desc: test Marshalling
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testInnerLinkMarshalling002, TestSize.Level1)
{
    struct InnerLink* self = InnerLinkNew();
    struct WifiDirectProtocol *protocol = GetWifiDirectProtocolFactory()->createProtocol(WIFI_DIRECT_PROTOCOL_TLV);
    self->keyProperties->tag = ONE_NUM;
    self->keyProperties->content = nullptr;
    self->keyProperties->type = IPV4_INFO_ARRAY;
    self->keyProperties->flag = ONE_NUM;
    bool ret = self->marshalling(self, protocol);
    InnerLinkDelete(self);
    EXPECT_TRUE(ret == true);
}

/*
* @tc.name: testMarshalling003
* @tc.desc: test Marshalling
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testInnerLinkMarshalling003, TestSize.Level1)
{
    struct InnerLink* self = InnerLinkNew();
    struct WifiDirectProtocol *protocol = GetWifiDirectProtocolFactory()->createProtocol(WIFI_DIRECT_PROTOCOL_TLV);
    self->keyProperties->tag = ONE_NUM;
    self->keyProperties->content = nullptr;
    self->keyProperties->type = STRING;
    self->keyProperties->flag = ONE_NUM;
    bool ret = self->marshalling(self, protocol);
    InnerLinkDelete(self);
    EXPECT_TRUE(ret == true);
}

/*
* @tc.name: testMarshalling004
* @tc.desc: test Marshalling
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testInnerLinkMarshalling004, TestSize.Level1)
{
    struct InnerLink* self = InnerLinkNew();
    struct WifiDirectProtocol *protocol = GetWifiDirectProtocolFactory()->createProtocol(WIFI_DIRECT_PROTOCOL_TLV);
    self->keyProperties->tag = ONE_NUM;
    self->keyProperties->content = nullptr;
    self->keyProperties->type = IPV4_INFO;
    self->keyProperties->flag = ONE_NUM;
    bool ret = self->marshalling(self, protocol);
    InnerLinkDelete(self);
    EXPECT_TRUE(ret == true);
}

/*
* @tc.name: testMarshalling005
* @tc.desc: test Marshalling
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testInnerLinkMarshalling005, TestSize.Level1)
{
    struct InnerLink* self = InnerLinkNew();
    struct WifiDirectProtocol *protocol = GetWifiDirectProtocolFactory()->createProtocol(WIFI_DIRECT_PROTOCOL_TLV);
    self->keyProperties->tag = ONE_NUM;
    self->keyProperties->content = nullptr;
    self->keyProperties->type = LONG;
    self->keyProperties->flag = ONE_NUM;
    bool ret = self->marshalling(self, protocol);
    InnerLinkDelete(self);
    EXPECT_TRUE(ret == true);
}

/*
* @tc.name: testUnmarshalling001
* @tc.desc: test Unmarshalling
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testInnerLinkUnmarshalling001, TestSize.Level1)
{
    struct InnerLink* self = InnerLinkNew();
    struct WifiDirectProtocol *protocol = GetWifiDirectProtocolFactory()->createProtocol(WIFI_DIRECT_PROTOCOL_TLV);
    self->keyProperties->tag = ONE_NUM;
    self->keyProperties->content = nullptr;
    self->keyProperties->type = LONG;
    self->keyProperties->flag = ONE_NUM;
    self->marshalling(self, protocol);
    bool ret = self->unmarshalling(self, protocol);
    InnerLinkDelete(self);
    EXPECT_TRUE(ret == true);
}

/*
* @tc.name: testUnmarshalling002
* @tc.desc: test Unmarshalling
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testInnerLinkUnmarshalling002, TestSize.Level1)
{
    struct InnerLink* self = InnerLinkNew();
    struct WifiDirectProtocol *protocol = GetWifiDirectProtocolFactory()->createProtocol(WIFI_DIRECT_PROTOCOL_TLV);
    self->keyProperties->tag = ONE_NUM;
    self->keyProperties->content = nullptr;
    self->keyProperties->type = BOOLEAN;
    self->keyProperties->flag = ONE_NUM;
    self->marshalling(self, protocol);
    bool ret = self->unmarshalling(self, protocol);
    InnerLinkDelete(self);
    EXPECT_TRUE(ret == true);
}

/*
* @tc.name: testUnmarshalling003
* @tc.desc: test Unmarshalling
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testInnerLinkUnmarshalling003, TestSize.Level1)
{
    struct InnerLink* self = InnerLinkNew();
    struct WifiDirectProtocol *protocol = GetWifiDirectProtocolFactory()->createProtocol(WIFI_DIRECT_PROTOCOL_TLV);
    self->keyProperties->tag = ONE_NUM;
    self->keyProperties->content = nullptr;
    self->keyProperties->type = IPV4_INFO_ARRAY;
    self->keyProperties->flag = ONE_NUM;
    self->marshalling(self, protocol);
    bool ret = self->unmarshalling(self, protocol);
    InnerLinkDelete(self);
    EXPECT_TRUE(ret == true);
}

/*
* @tc.name: testUnmarshalling004
* @tc.desc: test Unmarshalling
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testInnerLinkUnmarshalling004, TestSize.Level1)
{
    struct InnerLink* self = InnerLinkNew();
    struct WifiDirectProtocol *protocol = GetWifiDirectProtocolFactory()->createProtocol(WIFI_DIRECT_PROTOCOL_TLV);
    self->keyProperties->tag = ONE_NUM;
    self->keyProperties->content = nullptr;
    self->keyProperties->type = IPV4_INFO;
    self->keyProperties->flag = ONE_NUM;
    self->marshalling(self, protocol);
    bool ret = self->unmarshalling(self, protocol);
    InnerLinkDelete(self);
    EXPECT_TRUE(ret == true);
}

/*
* @tc.name: testUnmarshalling005
* @tc.desc: test Unmarshalling
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testInnerLinkUnmarshalling005, TestSize.Level1)
{
    struct InnerLink* self = InnerLinkNew();
    struct WifiDirectProtocol *protocol = GetWifiDirectProtocolFactory()->createProtocol(WIFI_DIRECT_PROTOCOL_TLV);
    self->keyProperties->tag = ONE_NUM;
    self->keyProperties->content = nullptr;
    self->keyProperties->type = STRING;
    self->keyProperties->flag = ONE_NUM;
    self->marshalling(self, protocol);
    bool ret = self->unmarshalling(self, protocol);
    InnerLinkDelete(self);
    EXPECT_TRUE(ret == true);
}

/*
* @tc.name: testGetLink001
* @tc.desc: test GetLink
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testInnerLinkGetLink001, TestSize.Level1)
{
    struct InnerLink* self = InnerLinkNew();
    struct WifiDirectLink wifiLink;
    (void)memset_s(&wifiLink, sizeof(wifiLink), ZERO_NUM, sizeof(wifiLink));
    wifiLink.linkId = ONE_NUM;
    wifiLink.connectType = WIFI_DIRECT_CONNECT_TYPE_WIFI_DIRECT;
    const char str[] = "127.0.0.1";
    strcpy_s(wifiLink.localIp, sizeof(LENGTH_NUM), str);
    const char str1[] = "7.182.56.32";
    strcpy_s(wifiLink.remoteIp, sizeof(LENGTH_NUM), str1);
    int32_t requestId = LENGTH_HEADER;
    int32_t pid = THIRD_NUM;
    int32_t ret = self->getLink(self, requestId, pid, &wifiLink);
    InnerLinkDelete(self);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
}

/*
* @tc.name: testGetLocalIpString001
* @tc.desc: test GetLocalIpString and putLocalIpString
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testInnerLinkGetLocalIpString001, TestSize.Level1)
{
    struct InnerLink* self = InnerLinkNew();
    string str = "127.0.0.1";
    self->putLocalIpString(self, const_cast<char*>(str.c_str()));
    int32_t ret = self->getLocalIpString(self, const_cast<char*>(str.c_str()), str.size());
    InnerLinkDelete(self);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
}

/*
* @tc.name: testGetRemoteIpString001
* @tc.desc: test GetRemoteIpString and  putLocalIpString
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testInnerLinkGetRemoteIpString001, TestSize.Level1)
{
    struct InnerLink* self = InnerLinkNew();
    string str = "127.0.0.1";
    self->putRemoteIpString(self, const_cast<char*>(str.c_str()));
    int32_t ret = self->getRemoteIpString(self, const_cast<char*>(str.c_str()), str.size());
    InnerLinkDelete(self);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
}

/*
* @tc.name: testIncreaseReference001
* @tc.desc: test IncreaseReference and  DecreaseReference and getReference
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testInnerLinkIncreaseReference001, TestSize.Level1)
{
    struct InnerLink* self = InnerLinkNew();
    self->reference = ZERO_NUM;
    self->increaseReference(self);
    self->decreaseReference(self);
    int32_t ret = self->getReference(self);
    InnerLinkDelete(self);
    EXPECT_TRUE(ret == ZERO_NUM);
}

/*
* @tc.name: testAddId001
* @tc.desc: test AddId and  ContainId and RemoveId
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testInnerLinkAddId001, TestSize.Level1)
{
    struct InnerLink* self = InnerLinkNew();
    int32_t linkId = ONE_NUM;
    int32_t requestId = LENGTH_HEADER;
    int32_t pid = THIRD_NUM;
    self->addId(self, linkId, requestId, pid);
    bool ret = self->containId(self, linkId);
    if (ret) {
        self->removeId(self, linkId);
    }
    InnerLinkDelete(self);
    EXPECT_TRUE(ret == true);
}

// info_container.c

/*
* @tc.name: testPutInt001
* @tc.desc: test PutInt and PutBoolean
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testInfoContainerPutInt001, TestSize.Level1)
{
    struct InterfaceInfo* self = InterfaceInfoNew();
    struct InfoContainerKeyProperty keyProperty;
    keyProperty.tag = ONE_NUM;
    keyProperty.content = nullptr;
    keyProperty.type = INT;
    keyProperty.flag = ONE_NUM;
    InfoContainerConstructor((struct InfoContainer *)self, &keyProperty, LI_KEY_MAX);
    struct InfoContainer *container = (struct InfoContainer *)self;
    size_t key = LENGTH_HEADER;
    int32_t value = THIRD_NUM;
    bool ret = true;
    container->putInt(container, key, value);
    container->putBoolean(container, key, ret);
    InterfaceInfoDelete(self);
    EXPECT_EQ(ret, true);
}

/*
* @tc.name: testGet001
* @tc.desc: test Get
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testInfoContainerGet001, TestSize.Level1)
{
    struct InterfaceInfo* self = InterfaceInfoNew();
    struct InfoContainerKeyProperty keyProperty;
    keyProperty.tag = ONE_NUM;
    keyProperty.content = nullptr;
    keyProperty.type = INT;
    keyProperty.flag = ONE_NUM;
    InfoContainerConstructor((struct InfoContainer *)self, &keyProperty, LI_KEY_MAX);
    struct InfoContainer *container = (struct InfoContainer *)self;
    size_t key = LENGTH_HEADER;
    size_t size = FOUR_NUM;
    size_t count = THIRD_NUM;
    container->get(container,key, &size, &count);
    InterfaceInfoDelete(self);
    EXPECT_EQ(key, LENGTH_HEADER);
}

/*
* @tc.name: testGetBoolean001
* @tc.desc: test GetBoolean
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testInfoContainerGetBoolean001, TestSize.Level1)
{
    struct InterfaceInfo* self = InterfaceInfoNew();
    struct InfoContainerKeyProperty keyProperty;
    keyProperty.tag = ONE_NUM;
    keyProperty.content = nullptr;
    keyProperty.type = INT;
    keyProperty.flag = ONE_NUM;
    InfoContainerConstructor((struct InfoContainer *)self, &keyProperty, LI_KEY_MAX);
    struct InfoContainer *container = (struct InfoContainer *)self;
    size_t key = LENGTH_HEADER;
    bool ret = true;
    bool defaultValue = false;
    container->putBoolean(container, key, ret);
    bool ans = container->getBoolean(container, key, defaultValue);
    InterfaceInfoDelete(self);
    EXPECT_EQ(ans, true);
}

/*
* @tc.name: testGetInt001
* @tc.desc: test GetInt
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testInfoContainerGetInt001, TestSize.Level1)
{
    struct InterfaceInfo* self = InterfaceInfoNew();
    struct InfoContainerKeyProperty keyProperty;
    keyProperty.tag = ONE_NUM;
    keyProperty.content = nullptr;
    keyProperty.type = INT;
    keyProperty.flag = ONE_NUM;
    InfoContainerConstructor((struct InfoContainer *)self, &keyProperty, LI_KEY_MAX);
    struct InfoContainer *container = (struct InfoContainer *)self;
    size_t key = LENGTH_HEADER;
    int32_t ret = THIRD_NUM;
    int32_t defaultValue = false;
    container->putInt(container, key, ret);
    int32_t ans = container->getInt(container, key, defaultValue);
    InterfaceInfoDelete(self);
    EXPECT_EQ(ans, THIRD_NUM);
}

/*
* @tc.name: testGetString001
* @tc.desc: test GetString
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testInfoContainerGetString001, TestSize.Level1)
{
    struct InterfaceInfo* self = InterfaceInfoNew();
    struct InfoContainerKeyProperty keyProperty;
    keyProperty.tag = ONE_NUM;
    keyProperty.content = nullptr;
    keyProperty.type = INT;
    keyProperty.flag = ONE_NUM;
    InfoContainerConstructor((struct InfoContainer *)self, &keyProperty, LI_KEY_MAX);
    struct InfoContainer *container = (struct InfoContainer *)self;
    size_t key = LENGTH_HEADER;
    const char *defaultValue = "abcdefg";
    const char *value = "ABCDEFG";
    container->putString(container, key, value);
    char *ret = container->getString(container, key, defaultValue);
    InterfaceInfoDelete(self);
    EXPECT_EQ(*ret, *value);
}

/*
* @tc.name: testGetRawData001
* @tc.desc: test GetRawData
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testInfoContainerGetRawData001, TestSize.Level1)
{
    struct InterfaceInfo* self = InterfaceInfoNew();
    struct InfoContainerKeyProperty keyProperty;
    keyProperty.tag = ONE_NUM;
    keyProperty.content = nullptr;
    keyProperty.type = INT;
    keyProperty.flag = ONE_NUM;
    InfoContainerConstructor((struct InfoContainer *)self, &keyProperty, LI_KEY_MAX);
    struct InfoContainer *container = (struct InfoContainer *)self;
    size_t key = LENGTH_HEADER;
    const char *value = "ABC";
    container->putRawData(container, key, (void*)value, sizeof(value));
    const char *defaultValue =  "abcd";
    void *ret = container->getRawData(container, key, nullptr, (void*)defaultValue);
    const char* charPtr = static_cast<const char*>(ret);
    InterfaceInfoDelete(self);
    EXPECT_EQ(*charPtr, *value);
}

/*
* @tc.name: testRemove001
* @tc.desc: test Remove
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testInfoContainerRemove001, TestSize.Level1)
{
    struct InterfaceInfo* self = InterfaceInfoNew();
    struct InfoContainer *container = (struct InfoContainer *)self;
    container->keyProperties->tag = ONE_NUM;
    container->keyProperties->content = nullptr;
    container->keyProperties->type = INT;
    container->keyProperties->flag = CONTAINER_FLAG;
    size_t key = ONE_NUM;
    container->remove(container, key);
    InterfaceInfoDelete(self);
    EXPECT_TRUE(key == ONE_NUM);
}

/*
* @tc.name: testRemove002
* @tc.desc: test Remove
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testInfoContainerRemove002, TestSize.Level1)
{
    struct InterfaceInfo* self = InterfaceInfoNew();
    struct InfoContainer *container = (struct InfoContainer *)self;
    container->keyProperties->tag = ONE_NUM;
    container->keyProperties->content = nullptr;
    container->keyProperties->type = STRING;
    container->keyProperties->flag = CONTAINER_ARRAY_FLAG;
    size_t key = LENGTH_HEADER;
    container->remove(container, key);
    InterfaceInfoDelete(self);
    EXPECT_TRUE(key == LENGTH_HEADER);
}

/*
* @tc.name: testRemove003
* @tc.desc: test Remove
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testInfoContainerRemove003, TestSize.Level1)
{
    struct InterfaceInfo* self = InterfaceInfoNew();
    struct InfoContainer *container = (struct InfoContainer *)self;
    container->keyProperties->tag = ONE_NUM;
    container->keyProperties->content = nullptr;
    container->keyProperties->type = STRING;
    container->keyProperties->flag = DEVICE_ID_FLAG;
    size_t key = THIRD_NUM;
    container->remove(container, key);
    InterfaceInfoDelete(self);
    EXPECT_TRUE(key == THIRD_NUM);
}

/*
* @tc.name: testDump001
* @tc.desc: test Dump
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testInfoContainerDump001, TestSize.Level1)
{
    struct InterfaceInfo* self = InterfaceInfoNew();
    struct InfoContainer *container = (struct InfoContainer *)self;
    container->keyProperties->tag = ONE_NUM;
    container->keyProperties->content = nullptr;
    container->keyProperties->type = INT;
    container->keyProperties->flag = DEVICE_ID_FLAG;
    size_t key = ONE_NUM;
    container->dump(container);
    InterfaceInfoDelete(self);
    EXPECT_TRUE(key == ONE_NUM);
}

/*
* @tc.name: testDump002
* @tc.desc: test Dump
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testInfoContainerDump002, TestSize.Level1)
{
    struct InterfaceInfo* self = InterfaceInfoNew();
    struct InfoContainer *container = (struct InfoContainer *)self;
    container->keyProperties->tag = ONE_NUM;
    container->keyProperties->content = nullptr;
    container->keyProperties->type = INT;
    container->keyProperties->flag = CONTAINER_ARRAY_FLAG;
    size_t key = ONE_NUM;
    container->dump(container);
    InterfaceInfoDelete(self);
    EXPECT_TRUE(key == ONE_NUM);
}

/*
* @tc.name: testDump003
* @tc.desc: test Dump
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testInfoContainerDump003, TestSize.Level1)
{
    struct InterfaceInfo* self = InterfaceInfoNew();
    struct InfoContainer *container = (struct InfoContainer *)self;
    container->keyProperties->tag = ONE_NUM;
    container->keyProperties->content = nullptr;
    container->keyProperties->type = INT;
    container->keyProperties->flag = CONTAINER_FLAG;
    size_t key = ONE_NUM;
    container->dump(container);
    InterfaceInfoDelete(self);
    EXPECT_TRUE(key == ONE_NUM);
}

/*
* @tc.name: testDump004
* @tc.desc: test Dump
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testInfoContainerDump004, TestSize.Level1)
{
    struct InterfaceInfo* self = InterfaceInfoNew();
    struct InfoContainer *container = (struct InfoContainer *)self;
    container->keyProperties->tag = ONE_NUM;
    container->keyProperties->content = nullptr;
    container->keyProperties->type = INT;
    container->keyProperties->flag = DUMP_FLAG;
    size_t key = ONE_NUM;
    container->dump(container);
    InterfaceInfoDelete(self);
    EXPECT_TRUE(key == ONE_NUM);
}

/*
* @tc.name: testInfoContainerDestructor001
* @tc.desc: test InfoContainerDestructor
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testInfoContainerDestructor001, TestSize.Level1)
{
    struct InterfaceInfo* self = InterfaceInfoNew();
    struct InfoContainer *container = (struct InfoContainer *)self;
    container->keyProperties->tag = ONE_NUM;
    container->keyProperties->content = nullptr;
    container->keyProperties->type = INT;
    container->keyProperties->flag = CONTAINER_FLAG;
    size_t max = FOUR_NUM;
    InfoContainerDestructor(container, max);
    InterfaceInfoDelete(self);
    EXPECT_TRUE(max == FOUR_NUM);
}

/*
* @tc.name: testInfoContainerDestructor002
* @tc.desc: test InfoContainerDestructor
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDataTest, testInfoContainerDestructor002, TestSize.Level1)
{
    struct InterfaceInfo* self = InterfaceInfoNew();
    struct InfoContainer *container = (struct InfoContainer *)self;
    container->keyProperties->tag = ONE_NUM;
    container->keyProperties->content = nullptr;
    container->keyProperties->type = INT;
    container->keyProperties->flag = CONTAINER_ARRAY_FLAG;
    size_t max = THIRD_NUM;
    InfoContainerDestructor(container, max);
    InterfaceInfoDelete(self);
    EXPECT_TRUE(max == THIRD_NUM);
}
}