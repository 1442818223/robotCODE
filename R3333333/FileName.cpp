#include <Windows.h>
#include <iostream>
#include <string>

#define ioctl_disk_customize_serial CTL_CODE(FILE_DEVICE_UNKNOWN, 0x500, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define ioctl_disk_random_serial CTL_CODE(FILE_DEVICE_UNKNOWN, 0x501, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define ioctl_disk_null_serial CTL_CODE(FILE_DEVICE_UNKNOWN, 0x502, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define ioctl_disk_random_guid CTL_CODE(FILE_DEVICE_UNKNOWN, 0x503, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define ioctl_disk_null_volumn CTL_CODE(FILE_DEVICE_UNKNOWN, 0x504, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define ioctl_disk_disable_smart CTL_CODE(FILE_DEVICE_UNKNOWN, 0x505, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define ioctl_disk_change_serial CTL_CODE(FILE_DEVICE_UNKNOWN, 0x506, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)

#define ioctl_smbois_customize CTL_CODE(FILE_DEVICE_UNKNOWN, 0x600, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)

#define ioctl_gpu_customize CTL_CODE(FILE_DEVICE_UNKNOWN, 0x700, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)

#define ioctl_arp_table_handle CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define ioctl_mac_random CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define ioctl_mac_customize CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)

typedef struct DiskData   //硬盘
{
	int disk_mode;
	char serial_buffer[100];
	char product_buffer[100];
	char product_revision_buffer[100];
	bool guid_state;
	bool volumn_state;
}*PDiskData;

typedef struct smbois     //存储与系统管理 BIOS
{
	char vendor[100]{ 0 };
	char version[100]{ 0 };
	char date[100]{ 0 };
	char manufacturer[100]{ 0 };
	char product_name[100]{ 0 };
	char serial_number[100]{ 0 };
}*Psmbois;

typedef struct gpu   //存储 GPU 的序列号
{
	char serial_buffer[100];
}*Pgpu;

typedef struct nic   //网络接口卡
{
	bool arp_table;
	int mac_mode;
	char permanent[100]{ 0 };
	char current[100]{ 0 };
}*Pnic;

void SendIoctl(HANDLE hDevice, DWORD ioctlCode, PVOID 数据, int 选择) {
	DWORD returned;

	if (选择 == 1) {
		PDiskData wd = (PDiskData)数据;
		BOOL success = DeviceIoControl(
			hDevice,
			ioctlCode,
			wd,             // 输入缓冲区
			sizeof(数据),      // 输入缓冲区大小
			nullptr,               // 输出缓冲区
			0,                     // 输出缓冲区大小
			&returned,             // 返回的字节数
			nullptr                // 重叠结构
		);
		if (success) {
			std::cout << "Successfully sent IOCTL code: " << ioctlCode << std::endl;
		}
		else {
			std::cout << "Failed to send IOCTL code: " << ioctlCode << ". Error: " << GetLastError() << std::endl;
		}
	}
	else if (选择 == 2) {

		Psmbois wd = (Psmbois)数据;
		BOOL success = DeviceIoControl(
			hDevice,
			ioctlCode,
			wd,             // 输入缓冲区
			sizeof(数据),      // 输入缓冲区大小
			nullptr,               // 输出缓冲区
			0,                     // 输出缓冲区大小
			&returned,             // 返回的字节数
			nullptr                // 重叠结构
		);
		if (success) {
			std::cout << "Successfully sent IOCTL code: " << ioctlCode << std::endl;
		}
		else {
			std::cout << "Failed to send IOCTL code: " << ioctlCode << ". Error: " << GetLastError() << std::endl;
		}
	}
	else if (选择 == 3) {
		Pgpu wd = (Pgpu)数据;
		BOOL success = DeviceIoControl(
			hDevice,
			ioctlCode,
			wd,             // 输入缓冲区
			sizeof(数据),      // 输入缓冲区大小
			nullptr,               // 输出缓冲区
			0,                     // 输出缓冲区大小
			&returned,             // 返回的字节数
			nullptr                // 重叠结构
		);
		if (success) {
			std::cout << "Successfully sent IOCTL code: " << ioctlCode << std::endl;
		}
		else {
			std::cout << "Failed to send IOCTL code: " << ioctlCode << ". Error: " << GetLastError() << std::endl;
		}
	}
	else if (选择 == 4) {
		Pnic wd = (Pnic)数据;
		BOOL success = DeviceIoControl(
			hDevice,
			ioctlCode,
			wd,             // 输入缓冲区
			sizeof(数据),      // 输入缓冲区大小
			nullptr,               // 输出缓冲区
			0,                     // 输出缓冲区大小
			&returned,             // 返回的字节数
			nullptr                // 重叠结构
		);

		if (success) {
			std::cout << "Successfully sent IOCTL code: " << ioctlCode << std::endl;
		}
		else {
			std::cout << "Failed to send IOCTL code: " << ioctlCode << ". Error: " << GetLastError() << std::endl;
		}
	}
}

int main() {
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// 获取当前工作目录
	char currentPath[MAX_PATH];
	if (GetCurrentDirectoryA(MAX_PATH, currentPath) == 0) {
		printf("获取当前目录失败\n");
		return 1;
	}

	// 构造驱动程序的完整路径
	char driverPath[MAX_PATH];
	snprintf(driverPath, sizeof(driverPath), "%s\\MMMMMu.sys", currentPath); // 假设驱动程序文件名为 12356.sys
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		// 停止服务的命令   MMMMMu这两个都是服务名
	const char* stopCmd = "sc stop MMMMMu";  // 修改为 MyDriver
	// 删除服务的命令
	const char* deleteCmd = "sc delete MMMMMu"; // 修改为 MyDriver

	// 执行停止服务命令
	int resultStop = system(stopCmd);
	if (resultStop != 0) {
		printf("停止服务失败\n");
	}

	// 执行删除服务命令
	int resultDelete = system(deleteCmd);
	if (resultDelete != 0) {
		printf("删除服务失败\n");
	}
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		// 创建服务命令     MMMMMu这两个都是服务名
	char createCmd[512];
	snprintf(createCmd, sizeof(createCmd), "sc create MMMMMu binPath= \"%s\" type= kernel start= demand", driverPath);
	int resultCreate = system(createCmd);
	if (resultCreate != 0) {
		printf("创建服务失败\n");
		return resultCreate;
	}

	// 启动服务命令
	const char* startCmd = "sc start MMMMMu";
	int resultStart = system(startCmd);
	if (resultStart != 0) {
		printf("启动服务失败\n");
		return resultStart;
	}

	printf("驱动程序已成功加载并启动。\n");

	//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	HKEY hKey;
	LONG result;

	// 打开服务的注册表项
	result = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
		TEXT("SYSTEM\\CurrentControlSet\\Services\\MMMMMu"),
		0,
		KEY_SET_VALUE,
		&hKey);

	if (result != ERROR_SUCCESS) {
		printf("无法打开注册表项，错误代码：%ld\n", result);
		return 1;
	}

	// 设置 Start 值为 1
	DWORD startValue = 1; // 1 表示自动启动
	result = RegSetValueEx(hKey,
		TEXT("Start"),
		0,
		REG_DWORD,
		(const BYTE*)&startValue,
		sizeof(startValue));

	if (result != ERROR_SUCCESS) {
		printf("无法设置 Start 值，错误代码：%ld\n", result);
		RegCloseKey(hKey);
		return 1;
	}

	printf("Start 值已成功设置为 1。\n");

	// 关闭注册表项
	RegCloseKey(hKey);


/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////	
	HANDLE hDevice = CreateFile(
		L"\\\\.\\MMMMMu",  // 设备名
		GENERIC_WRITE | GENERIC_READ,
		0,
		nullptr,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		nullptr
	);

	if (hDevice == INVALID_HANDLE_VALUE) {
		std::cerr << "Failed to open device. Error: " << GetLastError() << std::endl;
		return 1;
	}

	std::cout << "Device opened successfully." << std::endl;

	// 设置一个示例数据
	DiskData diskData;
	diskData.disk_mode = 1;
	strncpy_s(diskData.serial_buffer, "SERIAL123456789", sizeof(diskData.serial_buffer));
	strncpy_s(diskData.product_buffer, "PRODUCT_XYZ", sizeof(diskData.product_buffer));
	strncpy_s(diskData.product_revision_buffer, "REVISION_1", sizeof(diskData.product_revision_buffer));

	// 发送控制代码 ioctl_disk_customize_serial
	SendIoctl(hDevice, ioctl_disk_customize_serial, &diskData, 1);
	// 设置并发送 ioctl_disk_random_guid 控制代码
	diskData.guid_state = true;
	SendIoctl(hDevice, ioctl_disk_random_guid, &diskData, 1);
	// 设置并发送 ioctl_disk_null_volumn 控制代码
	diskData.volumn_state = true;

	SendIoctl(hDevice, ioctl_disk_null_volumn, &diskData, 1);

	/////////////////////////////////////////////////////////////////////////////////////////////////////////////

	smbois SMBOIs;

	strncpy_s(SMBOIs.vendor, sizeof(SMBOIs.vendor), "Vendor_XYZ", _TRUNCATE);
	strncpy_s(SMBOIs.version, sizeof(SMBOIs.version), "Version_1.0", _TRUNCATE);
	strncpy_s(SMBOIs.date, sizeof(SMBOIs.date), "2024-01-01", _TRUNCATE);
	strncpy_s(SMBOIs.manufacturer, sizeof(SMBOIs.manufacturer), "Manufacturer_XYZ", _TRUNCATE);
	strncpy_s(SMBOIs.product_name, sizeof(SMBOIs.product_name), "Product_ABC", _TRUNCATE);
	strncpy_s(SMBOIs.serial_number, sizeof(SMBOIs.serial_number), "SN_ABC123", _TRUNCATE);

	SendIoctl(hDevice, ioctl_smbois_customize, &SMBOIs, 2);
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////
	gpu GPUd;
	strncpy_s(GPUd.serial_buffer, sizeof(GPUd.serial_buffer), "NVD-SN-123956", _TRUNCATE);

	SendIoctl(hDevice, ioctl_gpu_customize, &GPUd, 3);
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// 创建并填充 nic 结构体
	nic NICd;
	NICd.arp_table = true;  // 设置 ARP 表状态
	NICd.mac_mode = 1;      // 设置 MAC 模式为 1（例如随机模式）

	// 示例 MAC 地址，可以更改为合适的值
	strncpy_s(NICd.permanent, sizeof(NICd.permanent), "00:1A:2B:3C:4D:5E", _TRUNCATE);
	strncpy_s(NICd.current, sizeof(NICd.current), "00:1A:2B:3C:4D:5F", _TRUNCATE);

	// 发送 ioctl_arp_table_handle 控制代码
	SendIoctl(hDevice, ioctl_arp_table_handle, &NICd, 4);

	CloseHandle(hDevice);


	system("pause");
	return 0;
}