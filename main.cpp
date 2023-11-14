#include <iostream>
#include <Windows.h>
#include <tchar.h>
#include <bitset>
#include <winioctl.h>
#include <iostream>
#include <vector>
#include <string>
#include <imagehlp.h>
using namespace std;

#define BufferLength 1024
void section_immune() {
	HANDLE hFile;
	HANDLE hMapping;
	LPVOID pMapping;
	hFile = CreateFile(L"\\\\.\\E://test1.exe", GENERIC_READ| GENERIC_WRITE, FILE_SHARE_READ| FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL, NULL);
	if (INVALID_HANDLE_VALUE == hFile) {
		return;
	}
	//将PE文件映射到内存
	hMapping = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, 0, 0);
	if (!hMapping) {
		return;
	}
	pMapping = MapViewOfFile(hMapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);//返回的是map的开始地址
	if (!pMapping) {
		return;
	}

	PIMAGE_DOS_HEADER dosheader;
	dosheader = (PIMAGE_DOS_HEADER)pMapping;
	if (dosheader->e_magic != IMAGE_DOS_SIGNATURE) {
		cout << "无效的PE文件" << endl;
		return;
	}

	PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)((BYTE*)pMapping + dosheader->e_lfanew);
	if (nt_header->Signature != IMAGE_NT_SIGNATURE) {
		cout << "无效的PE文件" << endl;
		return;
	}

	PIMAGE_SECTION_HEADER section_header;
	section_header = IMAGE_FIRST_SECTION(nt_header);


	DWORD optionHeaderSize = nt_header->FileHeader.SizeOfOptionalHeader;
	DWORD NTHeaderSize = optionHeaderSize + 24;//获取nt header大小
	DWORD HeaderCheckSum = nt_header->OptionalHeader.CheckSum; //PE头里的校验值
	nt_header->OptionalHeader.CheckSum = 0;
	DWORD PointerToRawData = section_header->PointerToRawData;
	DWORD numOfSections = nt_header->FileHeader.NumberOfSections;
	DWORD PointerCopy = PointerToRawData - (40 * numOfSections + NTHeaderSize);
	memcpy((UINT8*)pMapping + PointerCopy, (UINT8*)nt_header, 40 * numOfSections + NTHeaderSize);
	dosheader->e_lfanew = PointerCopy;
	DWORD CheckSum = 0; //计算下来的校验值
	MapFileAndCheckSum(L"\\\\.\\E://test1.exe", &HeaderCheckSum, &CheckSum);
	nt_header->OptionalHeader.CheckSum = CheckSum;


	CloseHandle(hFile);
	CloseHandle(hMapping);


}

void between_section_immune() {
	HANDLE hFile;
	HANDLE hMapping;
	LPVOID pMapping;
	hFile = CreateFile(L"\\\\.\\E://test1_jiejianmianyi.exe", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL, NULL);
	if (INVALID_HANDLE_VALUE == hFile) {
		return;
	}
	//将PE文件映射到内存
	hMapping = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, 0, 0);
	if (!hMapping) {
		return;
	}
	pMapping = MapViewOfFile(hMapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);//返回的是map的开始地址
	if (!pMapping) {
		return;
	}

	PIMAGE_DOS_HEADER dosheader;
	dosheader = (PIMAGE_DOS_HEADER)pMapping;
	if (dosheader->e_magic != IMAGE_DOS_SIGNATURE) {
		cout << "无效的PE文件" << endl;
		return;
	}

	PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)((BYTE*)pMapping + dosheader->e_lfanew);
	if (nt_header->Signature != IMAGE_NT_SIGNATURE) {
		cout << "无效的PE文件" << endl;
		return;
	}

	PIMAGE_SECTION_HEADER section_header;
	section_header = IMAGE_FIRST_SECTION(nt_header);


	for (int i = 0; i < nt_header->FileHeader.NumberOfSections;i++, section_header++) {
		section_header->Misc.VirtualSize = static_cast<int>(section_header->SizeOfRawData);
	}

	cout << "done" << endl;
	CloseHandle(hFile);
	CloseHandle(hMapping);
}

int main() {
	section_immune();
	between_section_immune();
}
