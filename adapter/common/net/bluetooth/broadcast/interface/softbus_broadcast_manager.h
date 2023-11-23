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

/**
 * @file softbus_broadcast_manager.h
 * @brief
 *
 * @since 1.0
 * @version 1.0
 */

#ifndef SOFTBUS_BROADCAST_MANAGER_H
#define SOFTBUS_BROADCAST_MANAGER_H

#include "softbus_broadcast_type.h"

#ifdef __cplusplus
extern "C"{
#endif

/**
 * @brief Defines the broadcast callback function.
 *
 * @since 1.0
 * @version 1.0
 */
typedef struct {
    void (*OnStartBroadcastingCallback)(int32_t bcId, int32_t status);
    void (*OnStopBroadcastingCallback)(int32_t bcId, int32_t status);
    void (*OnUpdateBroadcastingCallback)(int32_t bcId, int32_t status);
    void (*OnSetBroadcastingCallback)(int32_t bcId, int32_t status);
} BroadcastCallback;

/**
 * @brief Defines the broadcast scan callback function.
 *
 * @since 1.0
 * @version 1.0
 */
typedef struct {
    void (*OnStartScanCallback)(int32_t listenerId, int32_t status);
    void (*OnStopScanCallback)(int32_t listenerId, int32_t status);
    void (*OnReportScanDataCallback)(int32_t listenerId, const BroadcastReportInfo *reportInfo);
} ScanCallback;

/**
 * @brief init broadcast manager.
 *
 * @return Returns <b>0</b> If the broadcast management initialization fails;
 * returns any other value if the request fails.
 * @since 1.0
 * @version 1.0
 */
int32_t InitBroadcastMgr(void);

/**
 * @brief init broadcast manager.
 *
 * @return Returns <b>SOFTBUS_OK</b> If the broadcast management deinitialization fails;
 * returns any other value if the request fails.
 * @since 1.0
 * @version 1.0
 */
int32_t DeInitBroadcastMgr(void);

/**
 * @brief Register the service to the broadcast manager.
 *
 * @param type Indicates the service type {@link BaseServiceType}.
 * @param bcId Indicates the service broadcast ID.
 * @param cb Indicates the service broadcast callback {@link BroadcastCallback}.
 *
 * @return Returns <b>SOFTBUS_OK</b> if the service register is successful.
 * returns any other value if the register fails.
 *
 * @since 1.0
 * @version 1.0
 */
int32_t RegisterBroadcaster(enum BaseServiceType type, int32_t *bcId, const BroadcastCallback *cb);

/**
 * @brief UnRegister the service to the broadcast manager.
 *
 * @param bcId Indicates the service broadcast ID.
 *
 * @return Returns <b>SOFTBUS_OK</b> if the service unregister is successful.
 * returns any other value if the unregister fails.
 *
 * @since 1.0
 * @version 1.0
 */
int32_t UnRegisterBroadcaster(int32_t bcId);

/**
 * @brief Register the service listener to the broadcast manager.
 *
 * @param type Indicates the service type {@link BaseServiceType}.
 * @param listenerId Indicates the service listener ID.
 * @param cb Indicates the service listener callback {@link ScanCallback}.
 *
 * @return Returns <b>SOFTBUS_OK</b> if the service register is successful.
 * returns any other value if the register fails.
 *
 * @since 1.0
 * @version 1.0
 */
int32_t RegisterScanListener(enum BaseServiceType type, int32_t *listenerId, const ScanCallback *cb);

/**
 * @brief UnRegister the service listener to the broadcast manager.
 *
 * @param listenerId Indicates the service listener ID.
 *
 * @return Returns <b>SOFTBUS_OK</b> if the service unregister is successful.
 * returns any other value if the unregister fails.
 *
 * @since 1.0
 * @version 1.0
 */
int32_t UnRegisterScanListener(int32_t listenerId);

/**
 * @brief The service enable broadcast
 *
 * @param bcId Indicates the service broadcast ID.
 * @param param Indicates the pointer to the service parameter information. For details, see {@link BroadcastParam}.
 * @param bcData Indicates the pointer to the service advertising data. For details, see {@link BroadcastData}.
 * @param rspData Indicates the pointer to the service broadcast respond data. For details, see {@link BroadcastData}.
 *
 * @return Returns <b>SOFTBUS_OK</b> if the service starts the broadcast successfully.
 * returns any other value if the unregister fails.
 *
 * @since 1.0
 * @version 1.0
 */
int32_t StartBroadcasting(int32_t bcId, const BroadcastParam *param, const BroadcastData *bcData,
    const BroadcastData *rspData);

/**
 * @brief The service update broadcast data and parameters.
 *
 * @param bcId Indicates the service broadcast ID.
 * @param param Indicates the pointer to the service parameter information. For details, see {@link BroadcastParam}.
 * @param bcData Indicates the pointer to the service advertising data. For details, see {@link BroadcastData}.
 * @param rspData Indicates the pointer to the service broadcast respond data. For details, see {@link BroadcastData}.
 *
 * @return Returns <b>SOFTBUS_OK</b> if the service updates the broadcast successfully.
 * returns any other value if the service fails to update the broadcast.
 *
 * @since 1.0
 * @version 1.0
 */
int32_t UpdateBroadcasting(int32_t bcId, const BroadcastParam *param, const BroadcastData *bcData,
    const BroadcastData *rspData);

/**
 * @brief The service stop broadcast
 *
 * @param bcId Indicates the service broadcast ID.
 *
 * @return Returns <b>SOFTBUS_OK</b> if the service stop the broadcast successfully.
 * returns any other value if the service fails to stop the broadcast.
 *
 * @since 1.0
 * @version 1.0
 */
int32_t StopBroadcasting(int32_t bcId);

/**
 * @brief The service enable broadcast scanning
 *
 * @param listenerId Indicates the service listener ID.
 * @param param Indicates the broadcast scan parameter {@link BcScanParams}
 *
 * @return Returns <b>SOFTBUS_OK</b> if the service start to scan the broadcast successfully.
 * returns any other value if the service fails to scan the broadcast.
 *
 * @since 1.0
 * @version 1.0
 */
int32_t StartScan(int32_t listenerId, const BcScanParams *param);

/**
 * @brief The service stop broadcast scanning
 *
 * @param listenerId Indicates the service listener ID.
 *
 * @return Returns <b>SOFTBUS_OK</b> if the service stop to scan the broadcast successfully.
 * returns any other value if the service fails to stop scanning the broadcast.
 *
 * @since 1.0
 * @version 1.0
 */
int32_t StopScan(int32_t listenerId);

/**
 * @brief Set the Scan Filter object
 *
 * @param listenerId Indicates the service listener ID.
 * @param scanFilter Indicates the broadcast scan filter parameter {@link BcScanFilter}
 * @param filterNum Indicates the number of the filter parameter
 *
 * @return Returns <b>SOFTBUS_OK</b> if the service set the Scan Filter successfully.
 * returns any other value if the service fails to set the Scan Filter.
 *
 * @since 1.0
 * @version 1.0
 */
int32_t SetScanFilter(int32_t listenerId, const BcScanFilter *scanFilter, uint8_t filterNum);

/**
 * @brief Get the Scan Filter object
 *
 * @param listenerId Indicates the service listener ID.
 * @param scanFilter Indicates the broadcast scan filter parameter {@link BcScanFilter}
 * @param filterNum Indicates the number of the filter parameter
 *
 * @return Returns <b>SOFTBUS_OK</b> if the service get the Scan Filter successfully.
 * returns any other value if the service fails to get the Scan Filter.
 *
 * @since 1.0
 * @version 1.0
 */
int32_t GetScanFilter(int32_t listenerId, const BcScanFilter *scanFilter, uint8_t *filterNum);

/**
 * @brief Check whether available resources are available by using the bcid
 *
 * @param bcId Indicates the service broadcast ID, when the service register successfully
 * @param status Indicates the status of available broadcast resources
 *
 * @return Returns <b>SOFTBUS_OK</b> if the service query status successfully.
 * returns any other value if the service fails to query status.
 *
 * @since 1.0
 * @version 1.0
 */
int32_t QueryBroadcastStatus(int32_t bcId, int32_t *status);

#ifdef __cplusplus
}
#endif

#endif /* SOFTBUS_BROADCAST_MANAGER_H */
