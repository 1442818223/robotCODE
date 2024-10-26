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

typedef struct DiskData   //Ӳ��
{
	int disk_mode;
	char serial_buffer[100];
	char product_buffer[100];
	char product_revision_buffer[100];
	bool guid_state;
	bool volumn_state;
}*PDiskData;

typedef struct smbois     //�洢��ϵͳ���� BIOS
{
	char vendor[100]{ 0 };
	char version[100]{ 0 };
	char date[100]{ 0 };
	char manufacturer[100]{ 0 };
	char product_name[100]{ 0 };
	char serial_number[100]{ 0 };
}*Psmbois;

typedef struct gpu   //�洢 GPU �����к�
{
	char serial_buffer[100];
}*Pgpu;

typedef struct nic   //����ӿڿ�
{
	bool arp_table;
	int mac_mode;
	char permanent[100]{ 0 };
	char current[100]{ 0 };
}*Pnic;

void SendIoctl(HANDLE hDevice, DWORD ioctlCode, PVOID ����, int ѡ��) {
	DWORD returned;

	if (ѡ�� == 1) {
		PDiskData wd = (PDiskData)����;
		BOOL success = DeviceIoControl(
			hDevice,
			ioctlCode,
			wd,             // ���뻺����
			sizeof(����),      // ���뻺������С
			nullptr,               // ���������
			0,                     // �����������С
			&returned,             // ���ص��ֽ���
			nullptr                // �ص��ṹ
		);
		if (success) {
			std::cout << "Successfully sent IOCTL code: " << ioctlCode << std::endl;
		}
		else {
			std::cout << "Failed to send IOCTL code: " << ioctlCode << ". Error: " << GetLastError() << std::endl;
		}
	}
	else if (ѡ�� == 2) {

		Psmbois wd = (Psmbois)����;
		BOOL success = DeviceIoControl(
			hDevice,
			ioctlCode,
			wd,             // ���뻺����
			sizeof(����),      // ���뻺������С
			nullptr,               // ���������
			0,                     // �����������С
			&returned,             // ���ص��ֽ���
			nullptr                // �ص��ṹ
		);
		if (success) {
			std::cout << "Successfully sent IOCTL code: " << ioctlCode << std::endl;
		}
		else {
			std::cout << "Failed to send IOCTL code: " << ioctlCode << ". Error: " << GetLastError() << std::endl;
		}
	}
	else if (ѡ�� == 3) {
		Pgpu wd = (Pgpu)����;
		BOOL success = DeviceIoControl(
			hDevice,
			ioctlCode,
			wd,             // ���뻺����
			sizeof(����),      // ���뻺������С
			nullptr,               // ���������
			0,                     // �����������С
			&returned,             // ���ص��ֽ���
			nullptr                // �ص��ṹ
		);
		if (success) {
			std::cout << "Successfully sent IOCTL code: " << ioctlCode << std::endl;
		}
		else {
			std::cout << "Failed to send IOCTL code: " << ioctlCode << ". Error: " << GetLastError() << std::endl;
		}
	}
	else if (ѡ�� == 4) {
		Pnic wd = (Pnic)����;
		BOOL success = DeviceIoControl(
			hDevice,
			ioctlCode,
			wd,             // ���뻺����
			sizeof(����),      // ���뻺������С
			nullptr,               // ���������
			0,                     // �����������С
			&returned,             // ���ص��ֽ���
			nullptr                // �ص��ṹ
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
	// ��ȡ��ǰ����Ŀ¼
	char currentPath[MAX_PATH];
	if (GetCurrentDirectoryA(MAX_PATH, currentPath) == 0) {
		printf("��ȡ��ǰĿ¼ʧ��\n");
		return 1;
	}

	// �����������������·��
	char driverPath[MAX_PATH];
	snprintf(driverPath, sizeof(driverPath), "%s\\MMMMMu.sys", currentPath); // �������������ļ���Ϊ 12356.sys
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		// ֹͣ���������   MMMMMu���������Ƿ�����
	const char* stopCmd = "sc stop MMMMMu";  // �޸�Ϊ MyDriver
	// ɾ�����������
	const char* deleteCmd = "sc delete MMMMMu"; // �޸�Ϊ MyDriver

	// ִ��ֹͣ��������
	int resultStop = system(stopCmd);
	if (resultStop != 0) {
		printf("ֹͣ����ʧ��\n");
	}

	// ִ��ɾ����������
	int resultDelete = system(deleteCmd);
	if (resultDelete != 0) {
		printf("ɾ������ʧ��\n");
	}
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		// ������������     MMMMMu���������Ƿ�����
	char createCmd[512];
	snprintf(createCmd, sizeof(createCmd), "sc create MMMMMu binPath= \"%s\" type= kernel start= demand", driverPath);
	int resultCreate = system(createCmd);
	if (resultCreate != 0) {
		printf("��������ʧ��\n");
		return resultCreate;
	}

	// ������������
	const char* startCmd = "sc start MMMMMu";
	int resultStart = system(startCmd);
	if (resultStart != 0) {
		printf("��������ʧ��\n");
		return resultStart;
	}

	printf("���������ѳɹ����ز�������\n");

	//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	HKEY hKey;
	LONG result;

	// �򿪷����ע�����
	result = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
		TEXT("SYSTEM\\CurrentControlSet\\Services\\MMMMMu"),
		0,
		KEY_SET_VALUE,
		&hKey);

	if (result != ERROR_SUCCESS) {
		printf("�޷���ע����������룺%ld\n", result);
		return 1;
	}

	// ���� Start ֵΪ 1
	DWORD startValue = 1; // 1 ��ʾ�Զ�����
	result = RegSetValueEx(hKey,
		TEXT("Start"),
		0,
		REG_DWORD,
		(const BYTE*)&startValue,
		sizeof(startValue));

	if (result != ERROR_SUCCESS) {
		printf("�޷����� Start ֵ��������룺%ld\n", result);
		RegCloseKey(hKey);
		return 1;
	}

	printf("Start ֵ�ѳɹ�����Ϊ 1��\n");

	// �ر�ע�����
	RegCloseKey(hKey);


/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////	
	HANDLE hDevice = CreateFile(
		L"\\\\.\\MMMMMu",  // �豸��
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

	// ����һ��ʾ������
	DiskData diskData;
	diskData.disk_mode = 1;
	strncpy_s(diskData.serial_buffer, "SERIAL123456789", sizeof(diskData.serial_buffer));
	strncpy_s(diskData.product_buffer, "PRODUCT_XYZ", sizeof(diskData.product_buffer));
	strncpy_s(diskData.product_revision_buffer, "REVISION_1", sizeof(diskData.product_revision_buffer));

	// ���Ϳ��ƴ��� ioctl_disk_customize_serial
	SendIoctl(hDevice, ioctl_disk_customize_serial, &diskData, 1);
	// ���ò����� ioctl_disk_random_guid ���ƴ���
	diskData.guid_state = true;
	SendIoctl(hDevice, ioctl_disk_random_guid, &diskData, 1);
	// ���ò����� ioctl_disk_null_volumn ���ƴ���
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
	// ��������� nic �ṹ��
	nic NICd;
	NICd.arp_table = true;  // ���� ARP ��״̬
	NICd.mac_mode = 1;      // ���� MAC ģʽΪ 1���������ģʽ��

	// ʾ�� MAC ��ַ�����Ը���Ϊ���ʵ�ֵ
	strncpy_s(NICd.permanent, sizeof(NICd.permanent), "00:1A:2B:3C:4D:5E", _TRUNCATE);
	strncpy_s(NICd.current, sizeof(NICd.current), "00:1A:2B:3C:4D:5F", _TRUNCATE);

	// ���� ioctl_arp_table_handle ���ƴ���
	SendIoctl(hDevice, ioctl_arp_table_handle, &NICd, 4);

	CloseHandle(hDevice);


	system("pause");
	return 0;
}