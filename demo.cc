#include <chrono>
#include <thread>
#include <tchar.h>
#include <strsafe.h>
#include <Windows.h>
#include <SetupAPI.h>
#include <stdio.h> 
#include <comdef.h>
#include <Wbemidl.h>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "Setupapi.lib")

BOOLEAN GetDevicePath2(
    _In_ LPCGUID InterfaceGuid,
    _Out_writes_(BufLen) PTCHAR DevicePath,
    _In_ size_t BufLen
)
{
    HANDLE                              hDevice = INVALID_HANDLE_VALUE;
    PSP_DEVICE_INTERFACE_DETAIL_DATA    deviceInterfaceDetailData = NULL;
    ULONG                               predictedLength = 0;
    ULONG                               requiredLength = 0;
    HDEVINFO                            hardwareDeviceInfo;
    SP_DEVICE_INTERFACE_DATA            deviceInterfaceData;
    BOOLEAN                             status = FALSE;
    HRESULT                             hr;

    hardwareDeviceInfo = SetupDiGetClassDevs(
        InterfaceGuid,
        NULL, // Define no enumerator (global)
        NULL, // Define no
        (DIGCF_PRESENT | // Only Devices present
            DIGCF_DEVICEINTERFACE)); // Function class devices.
    if (INVALID_HANDLE_VALUE == hardwareDeviceInfo)
    {
        printf("Idd device: SetupDiGetClassDevs failed, last error 0x%x\n", GetLastError());
        return FALSE;
    }

    deviceInterfaceData.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);

    if (!SetupDiEnumDeviceInterfaces(hardwareDeviceInfo,
        0, // No care about specific PDOs
        InterfaceGuid,
        0, //
        &deviceInterfaceData))
    {
        printf("Idd device: SetupDiEnumDeviceInterfaces failed, last error 0x%x\n", GetLastError());
        goto Clean0;
    }

    //
    // Allocate a function class device data structure to receive the
    // information about this particular device.
    //
    SetupDiGetDeviceInterfaceDetail(
        hardwareDeviceInfo,
        &deviceInterfaceData,
        NULL, // probing so no output buffer yet
        0, // probing so output buffer length of zero
        &requiredLength,
        NULL);//not interested in the specific dev-node

    if (ERROR_INSUFFICIENT_BUFFER != GetLastError())
    {
        printf("Idd device: SetupDiGetDeviceInterfaceDetail failed, last error 0x%x\n", GetLastError());
        goto Clean0;
    }

    predictedLength = requiredLength;
    deviceInterfaceDetailData = (PSP_DEVICE_INTERFACE_DETAIL_DATA)HeapAlloc(
        GetProcessHeap(),
        HEAP_ZERO_MEMORY,
        predictedLength
    );

    if (deviceInterfaceDetailData)
    {
        deviceInterfaceDetailData->cbSize =
            sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);
    }
    else
    {
        printf("Idd device: HeapAlloc failed, last error 0x%x\n", GetLastError());
        goto Clean0;
    }

    if (!SetupDiGetDeviceInterfaceDetail(
        hardwareDeviceInfo,
        &deviceInterfaceData,
        deviceInterfaceDetailData,
        predictedLength,
        &requiredLength,
        NULL))
    {
        printf("Idd device: SetupDiGetDeviceInterfaceDetail failed, last error 0x%x\n", GetLastError());
        goto Clean1;
    }

    hr = StringCchCopy(DevicePath, BufLen, deviceInterfaceDetailData->DevicePath);
    if (FAILED(hr))
    {
        printf("Error: StringCchCopy failed with HRESULT 0x%x", hr);
        status = FALSE;
        goto Clean1;
    }
    else
    {
        status = TRUE;
    }

Clean1:
    (VOID)HeapFree(GetProcessHeap(), 0, deviceInterfaceDetailData);
Clean0:
    (VOID)SetupDiDestroyDeviceInfoList(hardwareDeviceInfo);
    return status;
}

HANDLE DeviceOpenHandle(const GUID& devGuid)
{
    // const int maxDevPathLen = 256;
    TCHAR devicePath[256] = { 0 };
    HANDLE hDevice = INVALID_HANDLE_VALUE;
    do
    {
        if (FALSE == GetDevicePath2(
            &devGuid,
            devicePath,
            sizeof(devicePath) / sizeof(devicePath[0])))
        {
            break;
        }
        if (_tcslen(devicePath) == 0)
        {
            printf("GetDevicePath got empty device path\n");
            break;
        }

        //_tprintf(_T("Idd device: try open %s\n"), devicePath);
        hDevice = CreateFile(
            devicePath,
            GENERIC_READ | GENERIC_WRITE,
            // FILE_SHARE_READ | FILE_SHARE_WRITE,
            0,
            NULL, // no SECURITY_ATTRIBUTES structure
            OPEN_EXISTING, // No special create flags
            0, // No special attributes
            NULL
        );
        if (hDevice == INVALID_HANDLE_VALUE || hDevice == NULL)
        {
            DWORD error = GetLastError();
            printf("CreateFile failed 0x%lx\n", error);
        }
    } while (0);

    return hDevice;
}

enum VddCtlCode
{
    IOCTL_VDD_CONNECT = 0x22A008,
    IOCTL_VDD_ADD = 0x22E004,
    IOCTL_VDD_UPDATE = 0x22A00C,
};

void VddIoCtl(HANDLE vdd, VddCtlCode code)
{
    BYTE InBuffer[32]{};
    int OutBuffer = 0;
    OVERLAPPED Overlapped{};
    DWORD NumberOfBytesTransferred;

    Overlapped.hEvent = CreateEventW(NULL, NULL, NULL, NULL);
    DeviceIoControl(vdd, code, InBuffer, _countof(InBuffer), &OutBuffer, sizeof(OutBuffer), NULL, &Overlapped);
    GetOverlappedResult(vdd, &Overlapped, &NumberOfBytesTransferred, TRUE);

    if (Overlapped.hEvent && Overlapped.hEvent != INVALID_HANDLE_VALUE)
        CloseHandle(Overlapped.hEvent);
}

bool ctrlc = false;

BOOL WINAPI consoleHandler(DWORD signal) {
    if (signal == CTRL_C_EVENT) {
        ctrlc = true;
    }

    return TRUE;
}

BOOL displayPresent() {
    DISPLAY_DEVICE dd;
    dd.cb = sizeof(dd);
    return EnumDisplayDevices(0, 0, &dd, 0) == TRUE;
}

BOOL displayPresent2() {
    DISPLAY_DEVICE dd;
    dd.cb = sizeof(dd);
    int deviceIndex = 0;
    while (EnumDisplayDevices(0, deviceIndex, &dd, 0))
    {
        std::wstring deviceName = dd.DeviceName;
        int monitorIndex = 0;
        while (EnumDisplayDevices(deviceName.c_str(), monitorIndex, &dd, 0))
        {
            if (wcsncmp(dd.DeviceID, L"MONITOR\\PSCCDD", 14) != 0) {
                return TRUE;
            }
            ++monitorIndex;
        }
        ++deviceIndex;
    }
    return FALSE;
}

BOOL displayPresent3() {
    HRESULT hres;

    // Step 1: --------------------------------------------------
    // Initialize COM. ------------------------------------------

    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres))
    {
        return FALSE;                  // Program has failed.
    }

    // Step 2: --------------------------------------------------
    // Set general COM security levels --------------------------

    hres = CoInitializeSecurity(
        NULL,
        -1,                          // COM authentication
        NULL,                        // Authentication services
        NULL,                        // Reserved
        RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication 
        RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation  
        NULL,                        // Authentication info
        EOAC_NONE,                   // Additional capabilities 
        NULL                         // Reserved
    );


    if (FAILED(hres))
    {
        CoUninitialize();
        return FALSE;                    // Program has failed.
    }

    // Step 3: ---------------------------------------------------
    // Obtain the initial locator to WMI -------------------------

    IWbemLocator* pLoc = NULL;

    hres = CoCreateInstance(
        CLSID_WbemLocator,
        0,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (LPVOID*)&pLoc);

    if (FAILED(hres))
    {
        CoUninitialize();
        return FALSE;                 // Program has failed.
    }

    // Step 4: -----------------------------------------------------
    // Connect to WMI through the IWbemLocator::ConnectServer method

    IWbemServices* pSvc = NULL;

    // Connect to the root\cimv2 namespace with
    // the current user and obtain pointer pSvc
    // to make IWbemServices calls.
    hres = pLoc->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"), // Object path of WMI namespace
        NULL,                    // User name. NULL = current user
        NULL,                    // User password. NULL = current
        0,                       // Locale. NULL indicates current
        NULL,                    // Security flags.
        0,                       // Authority (for example, Kerberos)
        0,                       // Context object 
        &pSvc                    // pointer to IWbemServices proxy
    );

    if (FAILED(hres))
    {
        pLoc->Release();
        CoUninitialize();
        return FALSE;                // Program has failed.
    }


    // Step 5: --------------------------------------------------
    // Set security levels on the proxy -------------------------

    hres = CoSetProxyBlanket(
        pSvc,                        // Indicates the proxy to set
        RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx
        RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx
        NULL,                        // Server principal name 
        RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx 
        RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
        NULL,                        // client identity
        EOAC_NONE                    // proxy capabilities 
    );

    if (FAILED(hres))
    {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return FALSE;               // Program has failed.
    }

    IEnumWbemClassObject* pEnumerator = NULL;
    hres = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t("SELECT PNPDeviceID FROM Win32_DesktopMonitor"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator);

    if (FAILED(hres))
    {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return FALSE;               // Program has failed.
    }

    BOOLEAN result = FALSE;

    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;

    while (pEnumerator)
    {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1,
            &pclsObj, &uReturn);

        if (0 == uReturn)
        {
            break;
        }

        VARIANT vtProp;

        VariantInit(&vtProp);
        hr = pclsObj->Get(L"PNPDeviceID", 0, &vtProp, 0, 0);

        if (vtProp.bstrVal != NULL) {
            if (wcsncmp(vtProp.bstrVal, L"DISPLAY\\PSCCDD", 14) != 0) {
                wprintf(L"%s\n", vtProp.bstrVal);
                result = TRUE;
            }
        }

        VariantClear(&vtProp);

        pclsObj->Release();

        if (result) {
            break;
        }
    }

    // Cleanup
    // ========

    pSvc->Release();
    pLoc->Release();
    pEnumerator->Release();
    CoUninitialize();

    return result;   // Program successfully completed.
}

int main()
{
    if (!SetConsoleCtrlHandler(consoleHandler, TRUE)) {
        printf("\nERROR: Could not set control handler");
        //return 1;
    }

    const GUID PARSEC_VDD_DEVINTERFACE = \
    { 0x00b41627, 0x04c4, 0x429e, { 0xa2, 0x6e, 0x02, 0x65, 0xcf, 0x50, 0xc8, 0xfa } };


    while (!ctrlc) {

        if (!displayPresent3()) {
            BOOL dPresent = FALSE;
            int loop = 50;

            // try to get device handle with GUID
            HANDLE vdd = DeviceOpenHandle(PARSEC_VDD_DEVINTERFACE);
            if (!vdd || vdd == INVALID_HANDLE_VALUE)
            {
                printf("failed to get ParsecVDD device handle.\n");
                std::this_thread::sleep_for(std::chrono::seconds(5));
                continue;
            }

            VddIoCtl(vdd, IOCTL_VDD_CONNECT);
            VddIoCtl(vdd, IOCTL_VDD_UPDATE);
            VddIoCtl(vdd, IOCTL_VDD_ADD);
            VddIoCtl(vdd, IOCTL_VDD_UPDATE);

            //BOOL test = displayPresent2();

            while (!ctrlc && !dPresent)
            {
                // update each 100ms
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                VddIoCtl(vdd, IOCTL_VDD_UPDATE);

                if (loop > 0) {
                    loop--;
                }
                else {
                    dPresent = displayPresent3();
                    loop = 50;
                }
            }

            // disconnect
            VddIoCtl(vdd, IOCTL_VDD_CONNECT);
            CloseHandle(vdd);
        }
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }

    return 0;
}