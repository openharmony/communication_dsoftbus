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

#ifndef AUTH_HICHAIN_ADAPTER_STRUCT_H
#define AUTH_HICHAIN_ADAPTER_STRUCT_H

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

typedef enum {
   AUTH_GROUP_ACCOUNT = 0x001,
   AUTH_GROUP_P2P = 0x100,
   AUTH_GROUP_MESH = 0x101,
   AUTH_GROUP_COMPATIBLE = 0x200,
} HichainGroup;

typedef enum {
   ID_TYPE_UNKNOWN = 0,
   ID_TYPE_DEVID,
   ID_TYPE_UID,
} TrustedRelationIdType;

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
#endif /* AUTH_HICHAIN_ADAPTER_STRUCT_H */