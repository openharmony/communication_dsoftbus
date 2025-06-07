/*
* Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

/**
* @file softbus_ble_gatt_public.h
* @brief ble stack adapter
*
* @since 4.1
* @version 1.0
*/

#ifndef SOFTBUS_BLE_GATT_H
#define SOFTBUS_BLE_GATT_H

#ifdef __cplusplus
extern "C"{
#endif

#define GATT_SCAN_MAX_NUM           4

#define CHANEL_LP                   0
#define CHANEL_STEADY               1
#define CHANEL_SHARE                2
#define CHANEL_UNSTEADY             3
#define CHANEL_UNKNOW               1999

void SoftbusBleAdapterInit(void);
void SoftbusBleAdapterDeInit(void);

#ifdef __cplusplus
}
#endif

#endif /* SOFTBUS_BLE_GATT_H */