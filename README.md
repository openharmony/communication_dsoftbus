# DSoftBus


## Introduction

DSoftBus implements unified distributed communications between near-field devices and provides APIs for device discovery, connection, networking, and data transmission, regardless of the link type. It provides the following capabilities:

-   Device discovery and connection in various communication modes, such as WLAN and Bluetooth.
-   Unified device networking and topology management, and device information provisioning for data transmission.
-   Channel setup for transmitting messages, bytes, streams, and files.

You can use the APIs provided by DSoftBus to implement fast communication between devices without caring about the communication details, which facilitating deployment and running of services across platforms.

## Architecture

![](figures/dsoftbus-architecture.png)

**Figure 1** DSoftBus architecture 

## Directory Structure

The DSoftBus directory structure is as follows:

```text
//foundation/communication/dsoftbus
├── adapter               # Adaptation code
├── components            # Dependent component code
├── core                  # Core code
│   ├── adapter           # Adaptation code
│   ├── authentication    # Authentication code
│   ├── bus_center        # Networking code
│   ├── common            # Common code
│   ├── connection        # Connection code
│   ├── discovery         # Discovery code
│   ├── frame             # Framework code
│   └── transmission      # Transmission code
├── interfaces            # External APIs
├── sdk                   # Service process code
│   ├── bus_center        # Networking code
│   ├── discovery         # Discovery code
│   ├── frame             # Framework code
│   └── transmission      # Transmission code
├── tests                 # Test code
└── tools                 # Tool code
```

## Constraints

-   Connections can be set up only between the devices in the same LAN or between near-field devices.
-   Before setting up a connection between two devices, you must bind the devices. For details about the binding process, see the Security subsystem readme file.
-   After data transmission is complete, the service needs to close the session to release resources.

## Usage

### Usage Guidelines

>**NOTE**
>
>- The permissions ohos.permission.DISTRIBUTED_DATASYNC and ohos.permission.DISTRIBUTED_SOFTBUS_CENTER are required for remote procedure calls (RPCs) across devices.
>- To make a mobile phone visible to other devices, choose **Settings** > **Super Device** > **This device** > **Visible to**, and select **All nearby devices**.

**1. Discovery**

-   **Publishing process**

1.  Publish a service of your application.

    ```C
    // Callback for service publishing.
    typedef struct {
        /** Callback used to return the publish result. */
        void (*OnPublishResult)(int publishId, PublishResult reason);
    } IPublishCb;
    
    // Publish a service.
    int32_t PublishLNN(const char *pkgName, const PublishInfo *info, const IPublishCb *cb);
    ```

2.  Unpublish a service of your application.

    ```C
    // Unpublish a service.
    int32_t StopPublishLNN(const char *pkgName, int32_t publishId);
    ```


-   **Discovery process**

1.  Discover a device.

    ```C
    // Callbacks for device discovery.
    typedef struct {
        /** Callback invoked when a device is found. */
        void (*OnDeviceFound)(const DeviceInfo *device);
        /** Callback invoked to return the device discovery result. */
        void (*OnDiscoverResult)(int32_t refreshId, RefreshResult reason);
    } IRefreshCallback;
    
    // Start device discovery.
    int32_t RefreshLNN(const char *pkgName, const SubscribeInfo *info, const IRefreshCallback *cb);
    ```

2.  DSoftBus notifies the service of the device information via the callback once a device is found.
3.  Stop device discovery.

    ```C
    // Stop the discovery.
    int32_t StopRefreshLNN(const char *pkgName, int32_t refreshId);
    ```

**2. Networking**

1.  Initiate a connection request with the address of the target device and the connection callback.

    ```C
    // Address to connect to.
    typedef struct {
        ConnectionAddrType type;
        union {
            struct BrAddr {
                char brMac[BT_MAC_LEN];
            } br;
            struct BleAddr {
                char bleMac[BT_MAC_LEN];
                uint8_t udidHash[UDID_HASH_LEN];
            } ble;
            struct IpAddr {
                char ip[IP_STR_MAX_LEN];
                uint16_t port; 
            } ip;
        } info;
        char peerUid[MAX_ACCOUNT_HASH_LEN];
    } ConnectionAddr;
    
    // Address type.
    typedef enum {
        CONNECTION_ADDR_WLAN = 0,
        CONNECTION_ADDR_BR,
        CONNECTION_ADDR_BLE,
        CONNECTION_ADDR_ETH,
        CONNECTION_ADDR_MAX
    } ConnectionAddrType;
    
    // Callback invoked to return the connection result.
    typedef void (*OnJoinLNNResult)(ConnectionAddr *addr, const char *networkId, int32_t retCode);
    
    // Initiate a connection request.
    int32_t JoinLNN(const char *pkgName, ConnectionAddr *target, OnJoinLNNResult cb);
    ```

2.  Wait for the connection result. If DSoftBus accepts the connection request, a callback is invoked to return the result. In the return value, if **retCode** is **0**, the connection is successful, and the **addr** parameter matches the **target** parameter in **JoinLNN()**. In this case, the value of **networkId** is valid and will be used in the data transmission and disconnection APIs. If the value of **retCode** is not **0**, the connection fails, and the value of **networkId** is invalid.
3.  Transmit data using transmission APIs.
4.  Initiate a disconnection request with the **networkId** and the callback.

    ```C
    // Callback invoked to return the disconnection result.
    typedef void (*OnLeaveLNNResult)(const char *networkId, int32_t retCode);
    
    // Initiate a disconnection request.
    int32_t LeaveLNN(const char *pkgName, const char *networkId, OnLeaveLNNResult cb);
    ```

5.  Wait until the disconnection is complete. The **networkId** parameter in **OnLeaveLNNResult()** matches **networkId** in **LeaveLNN()**. If **retCode** is **0**, the disconnection is successful; otherwise, the disconnection fails. If the disconnection is successful, **networkId** becomes invalid and can no longer be used.
6.  Register and unregister callbacks for device state changes.

    ```C
    // Device state events.
    #define EVENT_NODE_STATE_ONLINE 0x1
    #define EVENT_NODE_STATE_OFFLINE 0x02
    #define EVENT_NODE_STATE_INFO_CHANGED 0x04
    #define EVENT_NODE_STATUS_CHANGED 0x08
    #define EVENT_NODE_STATE_MASK 0xF
    
    // Device information.
    typedef struct {
        char networkId[NETWORK_ID_BUF_LEN];
        char deviceName[DEVICE_NAME_BUF_LEN];
        uint16_t deviceTypeId;
    } NodeBasicInfo;
    
    // Device state event callbacks.
    typedef struct {
        uint32_t events; // Networking event mask.
        void (*onNodeOnline)(NodeBasicInfo *info);   // Called when the device gets online.
        void (*onNodeOffline)(NodeBasicInfo *info);  // Called when the device gets offline.
        void (*onNodeBasicInfoChanged)(NodeBasicInfoType type, NodeBasicInfo *info); // Called when the device information changes.
        void (*onNodeStatusChanged)(NodeStatusType type, NodeStatus *status); // Called when the device running status changes.
    } INodeStateCb;
    
    // Register the callback for device state events.
    int32_t RegNodeDeviceStateCb(const char *pkgName, INodeStateCb *callback);
    
    // Unregister the callback for device state events.
    int32_t UnregNodeDeviceStateCb(INodeStateCb *callback);
    ```

**3. Transmission**

1.  Create a **Socket** instance.

    ```C
    typedef struct {
        char *name;               // Local socket name.
        char *peerName;           // Peer socket name.
        char *peerNetworkId;      // Peer network ID.
        char *pkgName;            // Bundle name of the caller.
        TransDataType dataType;   // Type of the data to be transmitted, which must be the same as that in the sender() method.
    } SocketInfo;
    
    // Create sockets.
    int32_t Socket(SocketInfo info);
    ```

2.  Start listening for the socket on the server, and bind the socket on the client.

    ```C
    // Callbacks for the socket.
    typedef struct {
        void (*OnBind)(int32_t socket, PeerSocketInfo info);
        void (*OnShutdown)(int32_t socket, ShutdownReason reason);
        void (*OnBytes)(int32_t socket, const void *data, uint32_t dataLen);
        void (*OnMessage)(int32_t socket, const void *data, uint32_t dataLen);
        void (*OnStream)(int32_t socket, const StreamData *data, const StreamData *ext, const StreamFrameInfo *param);
        void (*OnFile)(int32_t socket, FileEvent *event);
        void (*OnQos)(int32_t socket, QoSEvent eventId, const QosTV *qos, uint32_t qosCount);
    } ISocketListener;

    typedef enum {
        QOS_TYPE_MIN_BW,           // Minimum bandwidth.
        QOS_TYPE_MAX_LATENCY,      // Maximum link setup latency.
        QOS_TYPE_MIN_LATENCY,      // Minimum link setup latency.
        QOS_TYPE_MAX_WAIT_TIMEOUT, // Maximum timeout period.
        QOS_TYPE_MAX_BUFFER,       // Maximum buffer size.
        QOS_TYPE_FIRST_PACKAGE,    // Size of the first packet.
        QOS_TYPE_MAX_IDLE_TIMEOUT, // Maximum idle time.
        QOS_TYPE_TRANS_RELIABILITY,// Transmission reliability.
        QOS_TYPE_BUTT,
    } QosType;

    typedef struct {
        QosType qos;
        int32_t value;
    } QosTV;

    // Start listening for the socket on the server.
    int32_t Listen(int32_t socket, const QosTV qos[], uint32_t qosCount, const ISocketListener *listener);

    // Bind the socket on the client.
    int32_t Bind(int32_t socket, const QosTV qos[], uint32_t qosCount, const ISocketListener *listener);
    ```

4. Send data to the peer device through the socket.

    ```C
    // Send bytes.
    int32_t SendBytes(int32_t socket, const void *data, uint32_t len);
    // Send messages.
    int32_t SendMessage(int32_t socket, const void *data, uint32_t len);
    // Send streams.
    int32_t SendStream(int32_t socket, const StreamData *data, const StreamData *ext, const StreamFrameInfo *param);
    // Send a file.
    int32_t SendFile(int32_t socket, const char *sFileList[], const char *dFileList[], uint32_t fileCnt);
    ```

5. Shut down the socket.

    ```C
    // Shut down the socket.
    void Shutdown(int32_t socket);
    ```

## Repositories Involved

[DSoftBus](https://gitee.com/openharmony/docs/blob/master/en/readme/dsoftbus.md)

**communication_dsoftbus**

[communication_bluetooth](https://gitee.com/openharmony/communication_bluetooth)

[communication_ipc](https://gitee.com/openharmony/communication_ipc)

[communication_wifi](https://gitee.com/openharmony/communication_wifi)
