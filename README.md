# communication\_dsoftbus<a name="EN-US_TOPIC_0000001103650648"></a>

-   [Introduction](#section13587125816351)
-   [Architecture](#section13587185873516)
-   [Directory Structure](#section161941989596)
-   [Constraints](#section119744591305)
-   [Usage](#section1312121216216)
    -   [Usage Guidelines](#section1698318421816)

-   [Repositories Involved](#section1371113476307)

## Introduction<a name="section13587125816351"></a>

There are various communication modes \(such as Wi-Fi and Bluetooth\), and the usage of different communication modes varies greatly and often leads to problems. In addition, the convergence, sharing, and conflict of communication links cannot be handled. DSoftBus manages unified distributed communications between near-field devices and provides APIs for device discovery, connection, networking, and data transmission, regardless of the link type. It mainly provides the following capabilities:

-   Device discovery and connection in various communication modes, such as WLAN and Bluetooth
-   Unified device networking and topology management, and device information provisioning for data transmission
-   Channel setup for transmitting messages and bytes

You can use the APIs provided by DSoftBus to implement fast communications between devices without caring about the communication details, thereby deploying and running services across platforms.

## Architecture<a name="section13587185873516"></a>

**Figure  1**  DSoftBus architecture<a name="fig4460722185514"></a>  


![](figures/dsoftbus-architecture.png)

## Directory Structure<a name="section161941989596"></a>

The main code directory structure of DSoftBus is as follows:

```
/foundation/communication/dsoftbus
├── interfaces            # APIs
├── core                  # Core code
│   ├── common            # Common code
│   ├── adapter           # Adaptation code
│   ├── authentication    # Authentication code
│   ├── bus_center        # Networking code
│   ├── connection        # Connection code
│   ├── discovery         # Discovery code
│   ├── transmission      # Transmission code
│   └── frame             # Framework code
├── sdk                   # Service process code
│   ├── bus_center        # Networking code
│   ├── discovery         # Discovery code
│   ├── transmission      # Transmission code
│   └── frame             # Framework code
└── components            # Dependent component code
```

## Constraints<a name="section119744591305"></a>

-   The devices between which you want to set up a connection must be in the same LAN.
-   Before setting up a connection between two devices, you must bind the devices. For details about the binding process, see relevant descriptions in the Security subsystem readme file.
-   A device can only be connected to another one device.

## Usage<a name="section1312121216216"></a>

### Usage Guidelines<a name="section1698318421816"></a>

>**NOTICE:** 
>To use RPC across devices, you must have the  **ohos.permission.DISTRIBUTED\_DATASYNC**  permission \(which is a dangerous one\).

**1. Discovery**

-   **Publishing process**

1.  Publish a service of your application.

    ```
    // Callbacks for service publishing
    typedef struct {
        void (*OnPublishSuccess)(int publishId); // Called when the service is published successfully.
        void (*OnPublishFail)(int publishId, PublishFailReason reason);// Called when the service fails to be published.
    } IPublishCallback;
    
    // Publish the service.
    int PublishService(const char *pkgName, const PublishInfo *info, const IPublishCallback *cb);
    ```

2.  Unpublish a service of your application.

    ```
    // Unpublish a service.
    int UnPublishService(const char *pkgName, int publishId);
    ```


-   **Discovery process**

1.  Discovery a specified device.

    ```
    // Callbacks for device discovery
    typedef struct {
        void (*OnDeviceFound)(const DeviceInfo *device); // Called when a device is found.
        void (*OnDiscoverFailed)(int subscribeId, DiscoveryFailReason failReason); // Called when the discovery fails to start.
        void (*OnDiscoverySuccess)(int subscribeId); // Called when the discovery starts successfully.
    } IDiscoveryCallback;
    
    // Start a device discovery.
    int StartDiscovery(const char *pkgName, const SubscribeInfo *info, const IDiscoveryCallback *cb);
    ```

2.  The DSoftBus notifies you of the device information via the callback once a device is found.
3.  Stop the discovery as you need.

    ```
    // Stop the discovery.
    int StopDiscovery(const char *pkgName, int subscribeId);
    ```


**2. Networking**

1.  Initiate a connection request with the address of the target device and the connection callback.

    ```
    // Address to connect to
    typedef struct {
        ConnectionAddrType type;
        union {
            struct BrAddr {
                char brMac[BT_MAC_LEN];
            } br;
            struct BleAddr {
                char bleMac[BT_MAC_LEN];
            } ble;
            struct IpAddr {
                char ip[IP_STR_MAX_LEN];
                int port;
            } ip;
        } info;
    } ConnectionAddr;
    
    // Address types
    typedef enum {
        CONNECTION_ADDR_WLAN = 0,
        CONNECTION_ADDR_BR,
        CONNECTION_ADDR_BLE,
        CONNECTION_ADDR_ETH,
        CONNECTION_ADDR_MAX
    } ConnectionAddrType;
    
    // Callback for the connection result
    typedef void (*OnJoinLNNResult)(ConnectionAddr *addr, const char *networkId, int32_t retCode);
    
    // Initiate a connection request.
    int32_t JoinLNN(ConnectionAddr *target, OnJoinLNNResult cb);
    ```

2.  Wait for the connection result. If  **JoinLNN\(\)**  returns success, the DSoftBus accepts the connection request and notifies you of the connection result through the callback. The  **addr**  parameter in the callback matches the  **target**  parameter in  **JoinLNN\(\)**. If  **retCode**  in the callback is  **0**, the connection is successful. In this case, the value of  **networkId**  is valid and will be used in the data transmission and disconnection APIs. If the value of  **retCode**  is not  **0**, the connection fails, and the value of  **networkId**  is invalid.
3.  Transmit data using transmission APIs.
4.  Initiate a disconnection request with the  **networkId**  and the callback.

    ```
    // Callback for the disconnection result
    typedef void (*OnLeaveLNNResult)(const char *networkId, int32_t retCode);
    
    // Initiate a disconnection request.
    int32_t LeaveLNN(const char *networkId, OnLeaveLNNResult cb);
    ```

5.  Wait until the disconnection is complete. The  **networkId**  parameter in  **OnLeaveLNNResult\(\)**  matches  **networkId**  in  **LeaveLNN\(\)**. If  **retCode**  in the callback is  **0**, the disconnection is successful; otherwise, the disconnection fails. If the disconnection is successful,  **networkId**  becomes invalid and can no longer be used.
6.  Register and unregister callbacks for device state changes.

    ```
    // Device state events
    #define EVENT_NODE_STATE_ONLINE 0x1
    #define EVENT_NODE_STATE_OFFLINE 0x02
    #define EVENT_NODE_STATE_INFO_CHANGED 0x04
    #define EVENT_NODE_STATE_MASK 0x07
    
    // Device information
    typedef struct {
        char networkId[NETWORK_ID_BUF_LEN];
        char deviceName[DEVICE_NAME_BUF_LEN];
        uint8_t deviceTypeId;
    } NodeBasicInfo;
    
    // Device state event callbacks
    typedef struct {
        uint32_t events; // Networking event mask
        void (*onNodeOnline)(NodeBasicInfo *info);   // Called when the device gets online.
        void (*onNodeOffline)(NodeBasicInfo *info);  // Called when the device gets offline.
        void (*onNodeBasicInfoChanged)(NodeBasicInfoType type, NodeBasicInfo *info); // Called when the device information changes.
    } INodeStateCb;
    
    // Register the callback for device state events.
    int32_t RegNodeDeviceStateCb(INodeStateCb *callback);
    
    // Unregister the callback for device state events.
    int32_t UnregNodeDeviceStateCb(INodeStateCb *callback);
    ```


**3. Transmission**

1.  Create a session server with a listener. You can use the listener to monitor events such as opening and closing a session, and receiving messages or bytes.

    ```
    // Callbacks for session management
    typedef struct {
        int (*OnSessionOpened)(int sessionId, int result);
        void (*OnSessionClosed)(int sessionId);
        void (*OnBytesReceived)(int sessionId, const void *data, unsigned int dataLen);
        void (*OnMessageReceived)(int sessionId, const void *data, unsigned int dataLen);
    } ISessionListener;
    
    // Create a session server.
    int CreateSessionServer(const char *pkgName, const char *sessionName, const ISessionListener* listener);
    ```

2.  Open a session for sending and receiving data.

    ```
    // Open a session.
    int OpenSession(const char *mySessionName, const char *peerSessionName, const char *peerDeviceId, const char *groupId, const SessionAttribute* attr);
    ```

3.  Send data to the peer device based on the session ID.

    ```
    // Send bytes.
    int SendBytes(int sessionId, const void *data, unsigned int len);
    // Send messages.
    int SendMessage(int sessionId, const void *data, unsigned int len);
    ```

4.  Close a session with a specified ID.

    ```
    // Close a session.
    void CloseSession(int sessionId);
    ```

5.  Remove the session server.

    ```
    // Remove the session server.
    int RemoveSessionServer(const char *pkgName, const char *sessionName);
    ```


## Repositories Involved<a name="section1371113476307"></a>

DSoftBus subsystem

**communication_dsoftbus**

communication_bluetooth

communication_ipc

communication_wifi
