#include <cstdint>
#include <string>
#include <vector>

class DeviceManager {
public:
    ~DeviceManager(){};

    std::string GetRemoteByIndex(uint32_t index);
    void WaitNetworkSizeMoreThan(uint32_t count);

    static DeviceManager* Instance();
    private:
    DeviceManager(){};
    std::string m_localNetworkId;
    std::vector<std::string> m_remoteList;
    static DeviceManager* m_instance;
};


