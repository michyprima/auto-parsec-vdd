# auto-parsec-vdd
This is a fork of parsec-vdd.

As you may know, VNC servers and Sunshine do not work without a monitor connected to the graphics card.

This solves this problem polling for the monitor status and attaching a virtual monitor when no real monitor is found. This program also works without an active session and as such can be launched from a variety of environments including the task scheduler.


Full credits to nomi-san as I only added the monitor detection routine and the auto attach/detach logic.
#
<img align="left" src="https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcSxBsVvpMSFpgenJxcoNf9IYCxhAL9EbkFPYMsJV3BMoHFfLKE9ZBJiZDHtcTACUyr2PsA&usqp=CAU" width="240px">

# parsec-vdd
✨ Standalone **Parsec VDD**, create a virtual super display without **Parsec**, upto **4K 2160p@240hz**.<br>

<br>

![image](https://github.com/nomi-san/parsec-vdd/assets/38210249/2abc933e-29d1-420f-a35f-af865a950a93)

## About

This project demonstrates a standalone solution to create a virtual display by using [Parsec VDD](https://support.parsec.app/hc/en-us/articles/4422939339789-Overview-Prerequisites-and-Installation), without relying on the [Parsec app](https://parsec.app/).

> "**Parsec VDD** (Virtual Display Driver) is a perfect software driver developed by Parsec. It utilizes the [Idd/cx API](https://learn.microsoft.com/en-us/windows-hardware/drivers/display/indirect-display-driver-model-overview) (Indirect Display Driver) to create a virtual display on a computer. This virtual display is particularly useful in situations where a physical monitor may not be available or when additional screens are desired.

> One of the notable features of Parsec VDD is its support for a wide range of [resolutions and refresh rates](#supported-resolutions), including up to 240 Hz. This makes it well-suited for gaming, as it can provide a high-quality visual experience. It enables users to simulate the presence of additional screens or work without a physical monitor, enhancing flexibility and customization in display management."

How does it compare to other IDDs?

- There was an [usbmmidd_v2](https://www.amyuni.com/forum/viewtopic.php?t=3030), but it's built for a simple virtual display with limited resolutions and refresh rates.
- There are many open source repos, but you could not get signed drivers and perfect gaming solution.
  - https://github.com/roshkins/IddSampleDriver
  - https://github.com/fufesou/RustDeskIddDriver
  - https://github.com/douglascgh/IndirectDisplay
  - https://github.com/MolotovCherry/virtual-display-rs

If you need an application, check out this repo: https://github.com/KtzeAbyss/Easy-Virtual-Display

<br>

## Getting started

Download and install **Parsec Virtual Display Driver**, just pick one:
- [parsec-vdd-v0.37](https://builds.parsec.app/vdd/parsec-vdd-0.37.0.0.exe)
- [parsec-vdd-v0.38](https://builds.parsec.app/vdd/parsec-vdd-0.38.0.0.exe) (recommended)
- [parsec-vdd-v0.41](https://builds.parsec.app/vdd/parsec-vdd-0.41.0.0.exe)

<br>

Use this GUID interface to obtain the device handle.
```cpp
const GUID PARSEC_VDD_DEVINTERFACE = \
  { 0x00b41627, 0x04c4, 0x429e, { 0xa2, 0x6e, 0x02, 0x65, 0xcf, 0x50, 0xc8, 0xfa } };
  
HANDLE device = OpenDeviceHandle(PARSEC_VDD_DEVINTERFACE);
```

- Try this function to create your `OpenDeviceHandle(GUID)`: [fc152f42@fufesou/RustDeskIddDriver](https://github.com/fufesou/RustDeskIddDriver/blob/fc152f4282cc167b0bb32aa12c97c90788f32c3d/RustDeskIddApp/IddController.c#L722)
- Or hard code 😀 with this file path `\\?\root#display#%(DISPLAY_INDEX)#{00b41627-04c4-429e-a26e-0265cf50c8fa}`

<br>

Here's the way to control the VDD:
```cpp
enum VddCtlCode {
    IOCTL_VDD_CONNECT = 0x22A008,
    IOCTL_VDD_ADD = 0x22E004,
    IOCTL_VDD_UPDATE = 0x22A00C,
};

void VddIoCtl(HANDLE vdd, VddCtlCode code) {
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
```

And here is the pseudo-code for the VDD manipulation:

```cpp
void VddThread(HANDLE vdd, bool &running) {
    // Plug in monitor.
    VddIoCtl(vdd, IOCTL_VDD_CONNECT);
    VddIoCtl(vdd, IOCTL_VDD_UPDATE);
    VddIoCtl(vdd, IOCTL_VDD_ADD);
    VddIoCtl(vdd, IOCTL_VDD_UPDATE);
    // Keep monitor connection.
    for (running = true; running; ) {
        Sleep(100);
        VddIoCtl(vdd, IOCTL_VDD_UPDATE);
    }
}

bool PlugInMonitor(HANDLE &vdd, HANDLE &vddThread, bool &running) {
    char devpath[1024];
    for (int idx = 0; idx < 5; idx++) {
        // Hardcode device path.
        sprintf(devpath, "\\\\?\\root#display#000%d#%s", idx, "{00b41627-04c4-429e-a26e-0265cf50c8fa}");    
        vdd = CreateFileA(devpath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

        if (vdd && vdd != INVALID_HANDLE_VALUE) {
            vddThread = CreateThread(VddThread);
            return true;
        }
    }

    return false;
}

void PlugOutMonitor(HANDLE vdd, HANDLE vddThread, bool &running) {
    running = false;
    WaitForSingleObject(vddThread, INFINITE);

    // Reconnect to unplug monitor.
    VddIoCtl(vdd, IOCTL_VDD_CONNECT);
    CloseHandle(vdd);
}
```

A simple usage, see [demo.cc](./demo.cc) to learn more.

```cpp
int main()
{
    bool running;
    HANDLE vdd, vddThread;

    if (PlugInMonitor(vdd, vddThread, running)) {
        Sleep(5000);
        PlugOutMonitor(vdd, vddThread, running);
    }
}
```

<br>

## Preset display modes

All of the following display modes are set by driver default.

| Resolution   | Common name      | Aspect ratio         | Refresh rates (Hz)
| -            | :-:              | :-:                  | :-:
| 4096 x 2160  | DCI 4K           | 1.90:1 (256:135)     | 24/30/60/144/240
| 3840 x 2160  | 4K UHD           | 16:9                 | 24/30/60/144/240
| 3840 x 1600  | UltraWide        | 24:10                | 24/30/60/144/240
| 3840 x 1080  | UltraWide        | 32:9 (2x 16:9 FHD)   | 24/30/60/144/240
| 3440 x 1440  |                  | 21.5:9 (43:18)       | 24/30/60/144/240
| 3240 x 2160  |                  | 3:2                  | 60
| 3200 x 1800  | 3K               | 16:9                 | 24/30/60/144/240
| 3000 x 2000  |                  | 3:2                  | 60
| 2880 x 1800  | 2.8K             | 16:10                | 60
| 2880 x 1620  | 2.8K             | 16:9                 | 24/30/60/144/240
| 2736 x 1824  |                  |                      | 60
| 2560 x 1600  | 2K               | 16:10                | 24/30/60/144/240
| 2560 x 1440  | 2K               | 16:9                 | 24/30/60/144/240
| 2560 x 1080  | UltraWide        | 21:9                 | 24/30/60/144/240
| 2496 x 1664  |                  |                      | 60
| 2256 x 1504  |                  |                      | 60
| 2048 x 1152  |                  |                      | 60/144/240
| 1920 x 1200  | FHD              | 16:10                | 60/144/240
|**1920 x 1080**| **FHD**         | **16:9**             | 24/30/**60**/144/240
| 1800 x 1200  | FHD              | 3:2                  | 60
| 1680 x 1050  | HD+              | 16:10                | 60/144/240
| 1600 x 1200  | HD+              | 4:3                  | 24/30/60/144/240
|  1600 x 900  | HD+              | 16:9                 | 60/144/240
|  1440 x 900  | HD               | 16:10                | 60/144/240
|  1366 x 768  |                  |                      | 60/144/240
|  1280 x 800  | HD               | 16:10                | 60/144/240
|  1280 x 720  | HD               | 16:9                 | 60/144/240

Notes:
- Low GPUs, e.g GTX 1650 will not support the highest DCI 4K.
- All resolutions are compatible with 60 Hz refresh rates.

<br>

## Adapter specs

- Name: Parsec Virtual Display Adapter
- Hardware ID: `Root\Parsec\VDA`
- Adapter GUID: `{00b41627-04c4-429e-a26e-0265cf50c8fa}`
- EDID:

```
00 FF FF FF FF FF FF 00  42 63 D0 CD ED 5F 84 00
11 1E 01 04 A5 35 1E 78  3B 57 E0 A5 54 4F 9D 26
12 50 54 27 CF 00 71 4F  81 80 81 40 81 C0 81 00
95 00 B3 00 01 01 86 6F  80 A0 70 38 40 40 30 20
35 00 E0 0E 11 00 00 1A  00 00 00 FD 00 30 A5 C1
C1 29 01 0A 20 20 20 20  20 20 00 00 00 FC 00 50
61 72 73 65 63 56 44 41  0A 20 20 20 00 00 00 10
00 00 00 00 00 00 00 00  00 00 00 00 00 00 01 C6
02 03 10 00 4B 90 05 04  03 02 01 11 12 13 14 1F
8A 4D 80 A0 70 38 2C 40  30 20 35 00 E0 0E 11 00
00 1A FE 5B 80 A0 70 38  35 40 30 20 35 00 E0 0E
11 00 00 1A FC 7E 80 88  70 38 12 40 18 20 35 00
E0 0E 11 00 00 1E A4 9C  80 A0 70 38 59 40 30 20
35 00 E0 0E 11 00 00 1A  02 3A 80 18 71 38 2D 40
58 2C 45 00 E0 0E 11 00  00 1E 00 00 00 00 00 00
00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 A6
```

Visit http://www.edidreader.com/ to view it online or use an advanced tool [AW EDID Editor](https://www.analogway.com/apac/products/software-tools/aw-edid-editor/)
