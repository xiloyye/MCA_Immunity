#pragma once
#include <Windows.h>
#include <tchar.h>
#include <bitset>
#include <winioctl.h>
#include <iostream>
#include <vector>
#include <string>
using namespace std;


#define BufferLength 1024

struct MBR_disk_entry
{
	uint8_t bootflag;//引导标志
	uint8_t citouhao;//磁头号
	uint8_t shanquhao;//扇区号
	uint8_t zhumianhao;//柱面号
	uint8_t disk_flag;//分区类型标志
	uint8_t someinfo[3];//id、结束磁头号、结束柱面号、结束扇区号
	uint8_t relative[4];//相对起始扇区
	uint8_t sectors[4];//总扇区数
};
struct MBR
{
	uint8_t boot_code[446];//引导代码
	//4个分区表，每个16字节,只有一个分区表有内容，对应的标志是0xEE
	MBR_disk_entry pation_table_entry[4];
	uint8_t endflag[2];//55AA
};

struct BPB
{
	uint8_t BytePerSec[2];//每扇区字节数
	uint8_t SecPerClus;//每簇扇区数
	uint8_t RsvdSecCnt[2];//DOS保留扇区数
	uint8_t NumFATs;//FAT表个数
	uint8_t RootEntCnt[2];//未用
	uint8_t TotSec16[2];//未用
	uint8_t Media;//介质描述符
	uint8_t FATSz16[2];//未用
	uint8_t SecPerTrk[2];//每磁道扇区数
	uint8_t NumHeads[2];//磁头数
	uint8_t HidSec[4];//隐藏扇区
	uint8_t TotSec32[4];//该分区的扇区总数
	uint8_t FATSz32[4];//每FAT扇区数
	uint8_t	ExtFlags[2];//标记
	uint8_t FSVers[2];//版本
	uint8_t RootClus[4];//根目录首簇号
	uint8_t FSInfo[2];//文件系统信息扇区号
	uint8_t BkBootSec[2];//DBR备份扇区号
	uint8_t Reserved[12];//保留
	uint8_t DrvNum;//BIOS驱动器号
	uint8_t Reserved1;//未用
	uint8_t BootSig;//扩展引导标记
	uint8_t VolID[4];//卷序列号
	uint8_t VolLab[11];//卷标
	uint8_t FilSysType[8];//文件系统类型
};

struct DBR
{
	uint8_t BootSec_jmpBoot[3];
	uint8_t BootSec_OEMName[8];
	BPB bpb;
	uint8_t bootcode[420];
	uint8_t signature[2];//55 AA
};

struct shortfile {
	uint8_t FileName[8];//文件名
	uint8_t ExtendName[3];//扩展名
	uint8_t attributeOfFile;//属性字节
	uint8_t SystemReserve;//系统保留
	uint8_t CreateTime_ms;//创建时间的10毫秒位
	uint8_t CreateTime[2];//创建时间
	uint8_t CreateDate[2];//创建日期
	uint8_t LastAccess[2];//最后访问日期
	uint8_t HighCluster[2];//文件起始簇号高16位
	uint8_t LastModifyTime[2];//最近修改时间
	uint8_t LastModifyDate[2];//最近修改时间
	uint8_t LowCluster[2];//文件起始簇号低16位
	uint8_t FileSize[4];//文件长度
};

struct longfile {
	uint8_t attributeOfFile;//属性字节
	uint8_t unicodeOfFile1[10];//长文件名Unicode码
	uint8_t longFileSymbol;//长文件名目录项标志
	uint8_t SystemReserve;//系统保留
	uint8_t checkNum;//校验值
	uint8_t unicodeOfFile2[12];//长文件名Unicode码
	uint8_t FileStartCluster[2];//文件起始簇号，常置为0
	uint8_t unicodeOfFile3[4];//长文件名Unicode码
};

//rootdir（512字节）
struct rootdir {
	shortfile shortfile[16];//因为每次只能读512字节
};
//fat表的基本信息
struct fatInfo {
	uint32_t reserveSector;//保留扇区
	uint32_t FatPerSector;//每个Fat表扇区数
	uint32_t fat1;//fat1起始扇区
	uint32_t fat2;//fat2起始扇区
	uint32_t rootdir;//rootdir起始扇区
	uint32_t SectorPercluster;//每个簇的扇区数
};
//簇号链
struct clusterChain {
	uint32_t cluster[128];//每个clusterchain有128个目录项
};

struct fileInfo {
	std::string fileName;//文件名字
	uint32_t firstCluster;//首簇号
	//uint8_t fileClass;
	vector<int> filechain;
};

struct fileOFdisk {
	vector<fileInfo> filevec;//存放文件名
};

struct
{
	vector<string> vec;//存放待输出数据
	vector<uint32_t> vec2;//DBR起始扇区
	vector<fileOFdisk> diskfiles;//存放文件名
	vector<fatInfo> FatInfo;//存放fat信息
	vector<rootdir> RootDir;//存放rootdir信息
	vector<clusterChain> fat;//存放fat表128个簇号
}v;


//将4个uint8_t变为uint32_t
uint32_t uint8_t_ext32(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
	uint32_t result = 0;
	result = (static_cast<uint32_t>(a) << 24) |
		(static_cast<uint32_t>(b) << 16) |
		(static_cast<uint32_t>(c) << 8) |
		(static_cast<uint32_t>(d) << 0);
	return result;
}

// 将两个 uint8_t 类型的变量组合为一个 uint16_t 类型的变量
uint16_t combine_uint8_t(uint8_t high_byte, uint8_t low_byte) {
	return (uint16_t(high_byte) << 8) | uint16_t(low_byte);
}

//将四个连续字节存放的值转为int型
uint32_t transtoint(unsigned char a[])
{
	uint32_t sum = 0;
	for (int i = 0; i < 4; i++) {
		int m = a[i] / 16;
		int n = a[i] % 16;
		float len = 16;
		int temp1 = m * (pow(len, 7 - 2 * i));
		int temp2 = n * (pow(len, 6 - 2 * i));
		sum = sum + temp1 + temp2;
	}
	return sum;
}

//十进制转十六进制
string unsignedCharToHexString(unsigned char ch) {
	const char hex_chars[] = "0123456789abcdef";
	string result = "";
	unsigned int highHalfByte = (ch >> 4) & 0x0f;
	unsigned int lowHalfByte = (ch & 0x0f);
	result += hex_chars[highHalfByte];
	result += hex_chars[lowHalfByte];
	return result;
}

//找到分区表起始扇区
bool find_patition(MBR* mbr, char* lpBuffer, size_t len, bool ismbr, ULONGLONG* baseaddr, ULONGLONG* nextaddr, int EBRnum)
{
	bool mbrflag = 1;//在读取MBR的时候判断条目是主分区还是扩展分区条目 
	for (int i = 0; i < 446; i++) {
		mbr->boot_code[i] = lpBuffer[i];
	}
	int cnt = 446;
	for (int i = 0; i < 4; i++) {
		mbr->pation_table_entry[i].bootflag = lpBuffer[cnt];
		cnt++;
		mbr->pation_table_entry[i].citouhao = lpBuffer[cnt];
		cnt++;
		mbr->pation_table_entry[i].shanquhao = lpBuffer[cnt];
		cnt++;
		mbr->pation_table_entry[i].zhumianhao = lpBuffer[cnt];
		cnt++;
		mbr->pation_table_entry[i].disk_flag = lpBuffer[cnt];
		cnt++;
		for (int j = 0; j < 3; j++) {
			mbr->pation_table_entry[i].someinfo[j] = lpBuffer[cnt];
			cnt++;
		}
		for (int j = 0; j < 4; j++) {
			mbr->pation_table_entry[i].relative[j] = lpBuffer[cnt];
			cnt++;
		}
		for (int j = 0; j < 4; j++) {
			mbr->pation_table_entry[i].sectors[j] = lpBuffer[cnt];
			cnt++;
		}
	}
	for (int i = 0; i < 2; i++) {
		mbr->endflag[i] = lpBuffer[cnt];
		cnt++;
	}

	string mystr;
	if (ismbr) {
		for (int i = 0, rank = 1; i < 4; i++, rank++) {
			if (mbr->pation_table_entry[i].disk_flag == 0x5 || mbr->pation_table_entry[i].disk_flag == 0xf) {
				mbrflag = 0;
				rank = 4;
			}
			if (mbr->pation_table_entry[i].disk_flag == 0x00)//当第五位（标志位）是00时，代表分区表信息为空，无分区
			{
				//也不用往后读了 
				mystr = "";
			}
			else {
				uint8_t center[4];
				for (int j = 0, k = 3; j < 4; j++, k--) {
					center[j] = mbr->pation_table_entry[i].relative[k];
				}
				uint32_t tempadd = transtoint(center);
				v.vec2.push_back(tempadd);

				if (ismbr && !mbrflag)// if in mbr and got a extend entry,the EBR at relsecor+nowbase(0)
				{
					*baseaddr = (ULONGLONG)tempadd + (*baseaddr);//only change once
					*nextaddr = (ULONGLONG)0UL;
					//*nextaddr = (ULONGLONG)tempadd;
				}
			}
		}
	}
	else {
		int cnt = 0;
		for (; cnt < 2;) {
			if (mbr->pation_table_entry[cnt].disk_flag == 0x5) {
				mbrflag = 0;
			}
			if (mbr->pation_table_entry[cnt].disk_flag == 0x0) {
				mbrflag = 1;
			}
			else {
				uint8_t center[4];
				if (cnt == 0) {
					for (int j = 0, k = 3; j < 4; j++, k--) {
						center[j] = mbr->pation_table_entry[cnt].relative[k];
					}
					uint32_t tempadd = transtoint(center);
					v.vec2.push_back((ULONGLONG)tempadd + (*nextaddr) + (*baseaddr));
				}
				else {
					for (int j = 0, k = 3; j < 4; j++, k--) {
						center[j] = mbr->pation_table_entry[cnt].relative[k];
					}
					uint32_t tempadd = transtoint(center);
					*nextaddr = (ULONGLONG)tempadd;
				}
			}
			cnt++;
		}
	}
	return (mbrflag);
}

//FAT32文件系统解析
bool FATMsg(DBR* dbr, char* lpBuffer, size_t len, int num, uint32_t clus, HANDLE hDevice) {
	string mystr;
	fatInfo fatinfo;
	mystr = "第" + to_string(num);
	mystr += "磁盘FAT解析: ";
	v.vec.push_back(mystr);

	//把读取的值传入DBR
	int cnt = 0;
	for (int i = 0; i < 3; i++) {
		dbr->BootSec_jmpBoot[i] = lpBuffer[cnt];
		cnt++;
	}
	for (int i = 0; i < 8; i++) {
		dbr->BootSec_OEMName[i] = lpBuffer[cnt];
		cnt++;
	}
	for (int i = 0; i < 2; i++) {
		dbr->bpb.BytePerSec[i] = lpBuffer[cnt];
		cnt++;
	}
	dbr->bpb.SecPerClus = lpBuffer[cnt];
	cnt++;
	for (int i = 0; i < 2; i++) {
		dbr->bpb.RsvdSecCnt[i] = lpBuffer[cnt];
		cnt++;
	}
	dbr->bpb.NumFATs = lpBuffer[cnt];
	cnt++;
	for (int i = 0; i < 2; i++) {
		dbr->bpb.RootEntCnt[i] = lpBuffer[cnt];
		cnt++;
	}
	for (int i = 0; i < 2; i++) {
		dbr->bpb.TotSec16[i] = lpBuffer[cnt];
		cnt++;
	}
	dbr->bpb.Media = lpBuffer[cnt];
	cnt++;
	for (int i = 0; i < 2; i++) {
		dbr->bpb.FATSz16[i] = lpBuffer[cnt];
		cnt++;
	}
	for (int i = 0; i < 2; i++) {
		dbr->bpb.SecPerTrk[i] = lpBuffer[cnt];
		cnt++;
	}
	for (int i = 0; i < 2; i++) {
		dbr->bpb.NumHeads[i] = lpBuffer[cnt];
		cnt++;
	}
	for (int i = 0; i < 4; i++) {
		dbr->bpb.HidSec[i] = lpBuffer[cnt];
		cnt++;
	}
	for (int i = 0; i < 4; i++) {
		dbr->bpb.TotSec32[i] = lpBuffer[cnt];
		cnt++;
	}
	for (int i = 0; i < 4; i++) {
		dbr->bpb.FATSz32[i] = lpBuffer[cnt];
		cnt++;
	}
	for (int i = 0; i < 2; i++) {
		dbr->bpb.ExtFlags[i] = lpBuffer[cnt];
		cnt++;
	}
	for (int i = 0; i < 2; i++) {
		dbr->bpb.FSVers[i] = lpBuffer[cnt];
		cnt++;
	}
	for (int i = 0; i < 4; i++) {
		dbr->bpb.RootClus[i] = lpBuffer[cnt];
		cnt++;
	}
	for (int i = 0; i < 2; i++) {
		dbr->bpb.FSInfo[i] = lpBuffer[cnt];
		cnt++;
	}
	for (int i = 0; i < 2; i++) {
		dbr->bpb.BkBootSec[i] = lpBuffer[cnt];
		cnt++;
	}
	for (int i = 0; i < 12; i++) {
		dbr->bpb.Reserved[i] = lpBuffer[cnt];
		cnt++;
	}
	dbr->bpb.DrvNum = lpBuffer[cnt];
	cnt++;
	dbr->bpb.Reserved1 = lpBuffer[cnt];
	cnt++;
	dbr->bpb.BootSig = lpBuffer[cnt];
	cnt++;
	for (int i = 0; i < 4; i++) {
		dbr->bpb.VolID[i] = lpBuffer[cnt];
		cnt++;
	}
	for (int i = 0; i < 11; i++) {
		dbr->bpb.VolLab[i] = lpBuffer[cnt];
		cnt++;
	}
	for (int i = 0; i < 8; i++) {
		dbr->bpb.FilSysType[i] = lpBuffer[cnt];
		cnt++;
	}

	//解析BPB，找到FAT和根目录位置
	mystr = "";
	v.vec.push_back("每扇区字节数:");
	uint8_t temp[4] = { 0 };
	for (int j = 0, k = 1; j < 2; j++, k--) {
		mystr += unsignedCharToHexString(dbr->bpb.BytePerSec[k]);
		mystr += " ";
		temp[j + 2] = dbr->bpb.BytePerSec[k];
	}
	mystr += "h = ";
	uint32_t tempadd = transtoint(temp);
	mystr += to_string(tempadd);
	v.vec.push_back(mystr);

	mystr = "";
	v.vec.push_back("每簇扇区数:");
	fatinfo.SectorPercluster = dbr->bpb.SecPerClus;
	mystr += to_string(dbr->bpb.SecPerClus);
	v.vec.push_back(mystr);

	mystr = "";
	v.vec.push_back("保留扇区数:");
	for (int j = 0, k = 1; j < 2; j++, k--) {
		mystr += unsignedCharToHexString(dbr->bpb.RsvdSecCnt[k]);
		mystr += " ";
		temp[j + 2] = dbr->bpb.RsvdSecCnt[k];
	}
	mystr += "h = ";
	tempadd = transtoint(temp);
	uint32_t rsv = tempadd;
	fatinfo.reserveSector = rsv;
	mystr += to_string(tempadd);
	v.vec.push_back(mystr);

	mystr = "";
	v.vec.push_back("FAT表数目:");
	mystr += to_string(dbr->bpb.NumFATs);
	v.vec.push_back(mystr);

	mystr = "";
	v.vec.push_back("扇区总数:");
	for (int j = 0, k = 3; j < 4; j++, k--) {
		mystr += unsignedCharToHexString(dbr->bpb.TotSec32[k]);
		mystr += " ";
		temp[j] = dbr->bpb.TotSec32[k];
	}
	mystr += "h = ";
	tempadd = transtoint(temp);
	mystr += to_string(tempadd);
	v.vec.push_back(mystr);

	mystr = "";
	v.vec.push_back("每FAT扇区数:");
	for (int j = 0, k = 3; j < 4; j++, k--) {
		mystr += unsignedCharToHexString(dbr->bpb.FATSz32[k]);
		mystr += " ";
		temp[j] = dbr->bpb.FATSz32[k];
	}
	mystr += "h = ";
	tempadd = transtoint(temp);
	uint32_t spf = tempadd;
	fatinfo.FatPerSector = spf;
	mystr += to_string(tempadd);
	v.vec.push_back(mystr);

	mystr = "";
	v.vec.push_back("根目录首簇号:");
	for (int j = 0, k = 3; j < 4; j++, k--) {
		mystr += unsignedCharToHexString(dbr->bpb.RootClus[k]);
		mystr += " ";
		temp[j] = dbr->bpb.RootClus[k];
	}
	mystr += "h = ";
	tempadd = transtoint(temp);
	mystr += to_string(tempadd);
	v.vec.push_back(mystr);

	mystr = "";
	v.vec.push_back("FAT1的扇区号=DBR所在扇区+保留扇区:");
	uint32_t temp2 = clus + rsv;
	fatinfo.fat1 = temp2;
	v.vec.push_back(to_string(temp2));
	fatinfo.fat2 = temp2 + spf;

	mystr = "";
	v.vec.push_back("根目录的扇区号=FAT1的扇区号+2*(每一个FAT表扇区数):");
	uint32_t temp3 = temp2 + (2 * spf);
	v.vec.push_back(to_string(temp2));
	fatinfo.rootdir = temp3;
	v.FatInfo.push_back(fatinfo);

	/*查找文件：
	跳到根目录扇区，对于每一个文件，单独处理
	1.每次读取32字节，长短文件判断，若为长文件，则判断长文件名长度，一直到下一个0B位是短文件名标志
	2.对于不同文件，读取簇号
	3.跳到FAT表，读取簇链
	4.根据簇链跳到相应簇得到数据
	*/
	v.vec.push_back("//////////////////");
	char myBuf[BufferLength] = { 0 };
	LARGE_INTEGER offset2;
	DWORD dwCB2;
	offset2.QuadPart = ((ULONGLONG)temp3) * ((ULONGLONG)512);
	SetFilePointer(hDevice, offset2.LowPart, &offset2.HighPart, FILE_BEGIN);
	ReadFile(hDevice, myBuf, 512, &dwCB2, NULL);
	bool fin = false;

	rootdir rootDIR;
	shortfile sfile;
	cnt = 0;
	for (int i = 0; i < 16; i++) {
		for (int j = 0; j < 8; j++) {
			sfile.FileName[j] = myBuf[cnt + j];
		}
		for (int j = 8; j < 11; j++) {
			sfile.ExtendName[j - 8] = myBuf[cnt + j];
		}
		sfile.attributeOfFile = myBuf[cnt + 11];
		sfile.SystemReserve = myBuf[cnt + 12];
		sfile.CreateTime_ms = myBuf[cnt + 13];
		for (int j = 14; j < 16; j++) {
			sfile.CreateTime[j - 14] = myBuf[cnt + j];
		}
		for (int j = 16; j < 18; j++) {
			sfile.CreateDate[j - 16] = myBuf[cnt + j];
		}
		for (int j = 18; j < 20; j++) {
			sfile.LastAccess[j - 18] = myBuf[cnt + j];
		}
		for (int j = 20; j < 22; j++) {
			sfile.HighCluster[j - 20] = myBuf[cnt + j];
		}
		for (int j = 22; j < 24; j++) {
			sfile.LastModifyTime[j - 22] = myBuf[cnt + j];
		}
		for (int j = 24; j < 26; j++) {
			sfile.LastModifyDate[j - 24] = myBuf[cnt + j];
		}
		for (int j = 26; j < 28; j++) {
			sfile.LowCluster[j - 26] = myBuf[cnt + j];
		}
		for (int j = 28; j < 32; j++) {
			sfile.FileSize[j - 28] = myBuf[cnt + j];
		}
		rootDIR.shortfile[i] = sfile;
		cnt = cnt + 32;
	}
	v.RootDir.push_back(rootDIR);

	return fin;
}

//rootdir里32字节的fdt转长文件
longfile shortfileTOlongfile(shortfile s) {
	longfile l = { 0 };
	;	uint8_t temp[32] = { 0 };
	for (int j = 0; j < 8; j++) {
		temp[j] = s.FileName[j];
	}
	for (int j = 8; j < 11; j++) {
		temp[j] = s.ExtendName[j - 8];
	}
	temp[11] = s.attributeOfFile;
	temp[12] = s.SystemReserve;
	temp[13] = s.CreateTime_ms;
	for (int j = 14; j < 16; j++) {
		temp[j] = s.CreateTime[j - 14];
	}
	for (int j = 16; j < 18; j++) {
		temp[j] = s.CreateDate[j - 16];
	}
	for (int j = 18; j < 20; j++) {
		temp[j] = s.LastAccess[j - 18];
	}
	for (int j = 20; j < 22; j++) {
		temp[j] = s.HighCluster[j - 20];
	}
	for (int j = 22; j < 24; j++) {
		temp[j] = s.LastModifyTime[j - 22];
	}
	for (int j = 24; j < 26; j++) {
		temp[j] = s.LastModifyDate[j - 24];
	}
	for (int j = 26; j < 28; j++) {
		temp[j] = s.LowCluster[j - 26];
	}
	for (int j = 28; j < 32; j++) {
		temp[j] = s.FileSize[j - 28];
	}

	l.attributeOfFile = temp[0];
	for (int j = 1; j < 11; j++) {
		l.unicodeOfFile1[j - 1] = temp[j];
	}
	l.attributeOfFile = temp[11];
	l.SystemReserve = temp[12];
	l.checkNum = temp[13];
	for (int j = 14; j < 26; j++) {
		l.unicodeOfFile2[j - 14] = temp[j];
	}
	for (int j = 26; j < 28; j++) {
		l.FileStartCluster[j - 26] = temp[j];
	}
	for (int j = 28; j < 32; j++) {
		l.unicodeOfFile3[j - 28] = temp[j];
	}

	return l;
}

void findClusChain(HANDLE hDevice, int disknum = 0) {
	clusterChain clus_chain;
	LARGE_INTEGER offset;
	DWORD dwCB;
	char myBuf[BufferLength] = { 0 };
	offset.QuadPart = ((ULONGLONG)v.FatInfo[disknum].fat1) * ((ULONGLONG)512);
	SetFilePointer(hDevice, offset.LowPart, &offset.HighPart, FILE_BEGIN);
	int  FatPerSector = 2;// FatPerSector:每个Fat表扇区数，这里为了方便，只取两个扇区
	ReadFile(hDevice, myBuf, 512 * FatPerSector, &dwCB, NULL);
	int cnt = 0;
	for (int i = 0; i < 128; i++) {
		clus_chain.cluster[i] = uint8_t_ext32(myBuf[cnt + 3], myBuf[cnt + 2], myBuf[cnt + 1], myBuf[cnt]);
		cnt = cnt + 4;
	}
	v.fat.push_back(clus_chain);
	if (clus_chain.cluster[127] != 0x0fffffff) {
		for (int i = 0; i < 128; i++) {
			clus_chain.cluster[i] = uint8_t_ext32(myBuf[cnt + 3], myBuf[cnt + 2], myBuf[cnt + 1], myBuf[cnt]);
			cnt = cnt + 4;
		}
		v.fat.push_back(clus_chain);
	}

	for (int i = 0; i < v.diskfiles[disknum].filevec.size(); i++) {
		int _cluster = static_cast<int>(v.diskfiles[disknum].filevec[i].firstCluster);
		v.diskfiles[disknum].filevec[i].filechain.push_back(_cluster);
		int flag = 0;
		if (_cluster > 127) {
			flag = 1;
			int flag2 = 128;
			while (static_cast<int>(v.fat[flag].cluster[_cluster - flag2]) != static_cast<int>(0x0fffffff) ||
				static_cast<int>(v.fat[flag].cluster[_cluster - flag2]) != static_cast<int>(0x0))
			{
				_cluster = static_cast<int>(v.fat[flag].cluster[_cluster - flag2]);
				if (_cluster == static_cast<int>(0x0fffffff)) {
					break;
				}
				v.diskfiles[disknum].filevec[i].filechain.push_back(_cluster);
				if (_cluster > 128) {
					flag = 1;
					int flag2 = 128;
				}
				else {
					flag = 0;
					int flag2 = 0;
				}
			}
		}
		else {
			flag = 0;
			int flag2 = 0;
			while (static_cast<int>(v.fat[flag].cluster[_cluster - flag2]) != static_cast<int>(0x0fffffff) ||
				static_cast<int>(v.fat[flag].cluster[_cluster - flag2]) != static_cast<int>(0x0))
			{
				_cluster = static_cast<int>(v.fat[flag].cluster[_cluster - flag2]);
				if (_cluster == static_cast<int>(0x0fffffff)) {
					break;
				}
				v.diskfiles[disknum].filevec[i].filechain.push_back(_cluster);
				if (_cluster > 128) {
					flag = 1;
					int flag2 = 128;
				}
				else {
					flag = 0;
					int flag2 = 0;
				}
			}
		}
	}

}

void rootMsg(rootdir root) {
	string name = "";
	fileOFdisk fileofdisk;
	fileInfo fInfo;
	for (int i = 0; i < 16;) {
		longfile lfile;
		if (root.shortfile[i].attributeOfFile == 0x00) {
			break;
		}
		if (root.shortfile[i].attributeOfFile == 0x08) {//卷标,跳过
			i++;
			continue;
		}
		if (root.shortfile[i].attributeOfFile == 0x10) {//子目录
			i++;
			continue;
		}
		if (root.shortfile[i].attributeOfFile == 0x0f) {////长文件
			lfile = shortfileTOlongfile(root.shortfile[i]);
			if (root.shortfile[i].FileName[0] == 0xe5) {//删除了的文件
				i++;
				continue;
			}
			else {
				string name_part = "";
				for (int j = 0; j < 10;) {
					int n;
					n = static_cast<int>(combine_uint8_t(lfile.unicodeOfFile1[j + 1], lfile.unicodeOfFile1[j]));
					if (n != 0 && n != static_cast<int>(0xffff)) {
						name_part = name_part + static_cast<char>(n);
					}
					j = j + 2;
				}
				for (int j = 0; j < 12;) {
					int n;
					n = static_cast<int>(combine_uint8_t(lfile.unicodeOfFile2[j + 1], lfile.unicodeOfFile2[j]));
					if (n != 0 && n != static_cast<int>(0xffff)) {
						name_part = name_part + static_cast<char>(n);
					}
					j = j + 2;
				}
				for (int j = 0; j < 4;) {
					int n;
					n = static_cast<int>(combine_uint8_t(lfile.unicodeOfFile3[j + 1], lfile.unicodeOfFile3[j]));
					if (n != 0 && n != static_cast<int>(0xffff)) {
						name_part = name_part + static_cast<char>(n);
					}
					j = j + 2;
				}
				name = name_part + name;
				i++;
				continue;
			}
		}
		if (root.shortfile[i].attributeOfFile == 0x16) {//隐藏系统子目录/文件
			fInfo.firstCluster = uint8_t_ext32(root.shortfile[i].HighCluster[1], root.shortfile[i].HighCluster[0], root.shortfile[i].LowCluster[1], root.shortfile[i].LowCluster[0]);
			fInfo.fileName = name;
			name = "";
			fileofdisk.filevec.push_back(fInfo);
			i++;
			continue;
		}
		if (root.shortfile[i].attributeOfFile == 0x20) {//短文件
			if (root.shortfile[i].FileName[0] == 0xe5) {//删除了的文件
				i++;
				continue;
			}
			else {
				fInfo.firstCluster = uint8_t_ext32(root.shortfile[i].HighCluster[1], root.shortfile[i].HighCluster[0], root.shortfile[i].LowCluster[1], root.shortfile[i].LowCluster[0]);
				string name_part = "";
				for (int j = 0; j < 8; j++) {
					if (root.shortfile[i].FileName[j] != 0x0) {
						name_part = name_part + static_cast<char>(root.shortfile[i].FileName[j]);
					}
				}
				if (name == "") {
					name = name_part + name;
					fInfo.fileName = name;
				}
				else {
					fInfo.fileName = name;
				}
				name = "";
				fileofdisk.filevec.push_back(fInfo);
			}
		}
		i++;
	}
	v.diskfiles.push_back(fileofdisk);
}

void showMsg(bool FATINFO, int disknum) {
	if (FATINFO) {
		char buf[9];
		sprintf(buf, "%08X", v.FatInfo[disknum].reserveSector);
		string hexStr(buf);
		printf("保留扇区:%sh\n", hexStr.c_str());

		sprintf(buf, "%08X", v.FatInfo[disknum].FatPerSector);
		string hexStr2(buf);
		printf("每个Fat表扇区数:%sh\n", hexStr2.c_str());

		sprintf(buf, "%08X", v.FatInfo[disknum].fat1);
		string hexStr3(buf);
		printf("fat1起始扇区:%sh\n", hexStr3.c_str());

		sprintf(buf, "%08X", v.FatInfo[disknum].fat2);
		string hexStr4(buf);
		printf("fat2起始扇区:%sh\n", hexStr4.c_str());

		sprintf(buf, "%08X", v.FatInfo[disknum].rootdir);
		string hexStr5(buf);
		printf("rootdir起始扇区:%sh\n", hexStr5.c_str());

		sprintf(buf, "%08X", v.FatInfo[disknum].SectorPercluster);
		string hexStr6(buf);
		printf("每个簇的扇区数:%sh\n", hexStr6.c_str());

	}
	for (int i = 0; i < v.diskfiles[disknum].filevec.size(); i++) {
		printf("文件名字:%s\n", v.diskfiles[disknum].filevec[i].fileName.c_str());
		char buf2[9];
		sprintf(buf2, "%08X", v.diskfiles[disknum].filevec[i].firstCluster);
		string hexStr7(buf2);
		printf("首簇号:%s\n", hexStr7.c_str());
		printf("簇号链:");
		for (int j = 0; j < v.diskfiles[disknum].filevec[i].filechain.size(); j++) {
			if (j % 6 == 0) {
				printf("\n");
			}
			printf("%d->", v.diskfiles[disknum].filevec[i].filechain[j]);
		}
		printf("\n");
	}
}

//搜索根目录下的EXE文件
void showExe(int disknum = 0) {
	cout << "exe file as follows:" << endl;
	int size = v.diskfiles[disknum].filevec.size();
	for (int i = 0; i < size; i++) {
		int filesize = v.diskfiles[disknum].filevec[i].fileName.size();
		string extendName = v.diskfiles[disknum].filevec[i].fileName.substr(filesize - 3, 3);
		if (extendName.compare("EXE") == 0 || extendName.compare("exe") == 0) {
			cout << "\t" << v.diskfiles[disknum].filevec[i].fileName << endl;
		}
	}
}

/*GetDriveMsg一定要按照步骤执行函数，否则很容易造成空指针访问
顺序为find_patition->FATMsg->rootMsg->findClusChain->showMsg
*/
bool GetDriveMsg(DISK_GEOMETRY* pdg, int addr)
{
	HANDLE hDevice;               // 设备句柄
	BOOL bResult;                 // results flag
	DWORD junk;                   // discard resultscc
	char lpBuffer[BufferLength] = { 0 };
	MBR* mbr = new MBR;
	DBR* dbr = new DBR;


	//通过CreateFile来获得设备的句柄
	hDevice = CreateFile(TEXT("\\\\.\\PhysicalDrive1"), // 设备名称
		GENERIC_READ,                // no access to the drive
		FILE_SHARE_READ | FILE_SHARE_WRITE,  // share mode
		NULL,             // default security attributes
		OPEN_EXISTING,    // disposition
		0,                // file attributes
		NULL);            // do not copy file attributes
	if (hDevice == INVALID_HANDLE_VALUE) // cannot open the drive
	{
		printf("cannot open the drive");
		return (FALSE);
	}

	//通过DeviceIoControl函数与设备进行IO
	bResult = DeviceIoControl(hDevice, // 设备的句柄
		IOCTL_DISK_GET_DRIVE_GEOMETRY, // 控制码，指明设备的类型
		NULL,
		0, // no input buffer
		pdg,
		sizeof(*pdg),
		&junk,                 // # bytes returned
		(LPOVERLAPPED)NULL); // synchronous I/O

	LARGE_INTEGER offset;//long long signed
	offset.QuadPart = (ULONGLONG)addr * (ULONGLONG)512;//a sector
	SetFilePointer(hDevice, offset.LowPart, &offset.HighPart, FILE_BEGIN);//从0开始读MBR
	if (GetLastError())
		return (FALSE);//如果出错了

	DWORD dwCB;
	//从这个位置开始读 
	BOOL bRet = ReadFile(hDevice, lpBuffer, 512, &dwCB, NULL);

	bool finished = 0;
	int EBRnum = 0;
	ULONGLONG* baseaddr = new ULONGLONG, * nextaddr = new ULONGLONG;//扩展分区起始地址，EBR地址 
	*baseaddr = (ULONGLONG)0;
	*nextaddr = (ULONGLONG)0;
	finished = find_patition(mbr, lpBuffer, 512, true, baseaddr, nextaddr, EBRnum);

	if (finished)
		CloseHandle(hDevice);
	else
	{
		//继续读
		do {
			EBRnum++;
			memset(lpBuffer, 0, sizeof(lpBuffer));
			offset.QuadPart = (ULONGLONG)((*baseaddr) * ((ULONGLONG)512) + (*nextaddr) * ((ULONGLONG)512));//find the EBR
			SetFilePointer(hDevice, offset.LowPart, &offset.HighPart, FILE_BEGIN);//读EBR
			ReadFile(hDevice, lpBuffer, 512, &dwCB, NULL);
		} while (!find_patition(mbr, lpBuffer, 512, false, baseaddr, nextaddr, EBRnum));
		//CloseHandle(hDevice);
	}

	//FAT message
	LARGE_INTEGER offset3;
	offset3.QuadPart = (ULONGLONG)addr * (ULONGLONG)512;
	SetFilePointer(hDevice, offset3.LowPart, &offset3.HighPart, FILE_BEGIN);
	int order = 1;
	for (int i = 0; i < v.vec2.size(); i++) {
		if (i == 3) {
			continue;
		}

		memset(lpBuffer, 0, sizeof(lpBuffer));
		offset3.QuadPart = (ULONGLONG)((ULONGLONG)(v.vec2[i]) * ((ULONGLONG)512));//find the address
		SetFilePointer(hDevice, offset3.LowPart, &offset3.HighPart, FILE_BEGIN);//读DBR
		ReadFile(hDevice, lpBuffer, 512, &dwCB, NULL);
		FATMsg(dbr, lpBuffer, 512, order, v.vec2[i], hDevice);
		order++;
	}

	//为了方便，只演示获取u盘第一个逻辑卷文件的解析
	rootMsg(v.RootDir[0]);
	findClusChain(hDevice, 0);
	showMsg(false, 0);


	CloseHandle(hDevice);
	delete mbr;
	delete dbr;
	delete baseaddr;
	delete nextaddr;
	return bResult;
}

void show_PE_FileHeader(LPVOID pMapping) {
	// 获取PE文件头指针
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pMapping;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((DWORD)pMapping + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)&pNtHeader->FileHeader;

	// 输出文件头信息
	cout << "AddressOfEntryPoint: 0x" << hex << pNtHeader->OptionalHeader.AddressOfEntryPoint << endl;
	cout << "ImageBase: 0x" << hex << pNtHeader->OptionalHeader.ImageBase << endl;
	cout << "SectionAlignment: " << dec << pNtHeader->OptionalHeader.SectionAlignment << endl;
	cout << "FileAlignment: " << dec << pNtHeader->OptionalHeader.FileAlignment << endl;
	cout << "NumberOfSections: " << dec << pFileHeader->NumberOfSections << endl;
}

bool GetPEMsg() {
	//映射过程
	HANDLE hFile;
	HANDLE hMapping;
	LPVOID pMapping;
	hFile = CreateFile(TEXT("E://exp1.1.exe"), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL, NULL);
	if (INVALID_HANDLE_VALUE == hFile) {
		printf("can't open file");
		return false;
	}
	//将PE文件映射到内存
	hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, 0);
	if (!hMapping) {
		return false;
	}
	pMapping = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);//返回的是map的开始地址
	if (!pMapping) {
		return false;
	}

	//获取DOS_header
	//获取DOS header内容主要是获取e_lfanew值，指明了nt_header在文件中的位置
	PIMAGE_DOS_HEADER dosheader;
	dosheader = (PIMAGE_DOS_HEADER)pMapping;
	if (dosheader->e_magic != IMAGE_DOS_SIGNATURE) {
		cout << "无效的PE文件" << endl;
		return false;
	}

	/*获取nt_header
	pMapping是一个void指针，因此需要将这个指针转换为byte或UINT8指针就可以用于加减，
	加上e_lfanew就是nt_header的内容
	NT_Header包含signature、FileHeader和OptionalHeader，FileHeader中的numberOfSections指明了节表数量
	OptionalHeader里包含了AddressOfEntryPoint、ImageBase、SectionAlignment、FileAlignment、NumberOfSections等信息
	PIMAGE_NT_HEADERS也是一个header结构体指针，指定了它的地址，结构体参数会从这个地址开始取得对应参数的值。因此可以直接通过->访问参数
	*/
	PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)((BYTE*)pMapping + dosheader->e_lfanew);
	if (nt_header->Signature != IMAGE_NT_SIGNATURE) {
		cout << "无效的PE文件" << endl;
		return false;
	}
	show_PE_FileHeader(pMapping);

	/*解析节表信息
	获取section内容可以通过windows提供的API（IMAGE_FIRST_SECTION），传入nt_header指针后它会自动返回第一个section的指针，
	通过这个结构体指针的加减即可获取所有节表内容
	*/
	PIMAGE_SECTION_HEADER section_header;
	section_header = IMAGE_FIRST_SECTION(nt_header);
	for (int i = 0; i < nt_header->FileHeader.NumberOfSections;
		i++, section_header++) {
		cout << "节名:" << section_header->Name << "\n" << "节在内存中的大小，对齐前的大小:" << section_header->Misc.VirtualSize
			<< "\n" << "节区在内存中的偏移位置:" << section_header->VirtualAddress << "\n" <<
			"节区在硬盘中所占大小，文件对齐后大小:" << section_header->SizeOfRawData << "\n"
			<< "节区在硬盘文件中的偏移量:" << section_header->PointerToRawData << "\n" << "节属性的标志:" << section_header->Characteristics << endl;
	}

	/*获取.text内容写入磁盘隐藏扇区
	因为text节是第一个节表，所以只需要在调用IMAGE_FIRST_SECTION即可获取它的地址和大小，
	此时动态声明一个数组指针，将数组大小设置为节表大小，
	并通过memcpy函数将对应位置（即前面获取的节表位置加上pMapping地址）对应大小(节表地址)的.text内容写入这个数组
	*/
	DWORD PointerToRawData = IMAGE_FIRST_SECTION(nt_header)->PointerToRawData;
	DWORD SizeOfRawData = IMAGE_FIRST_SECTION(nt_header)->SizeOfRawData;
	UINT8* textContent = new UINT8[SizeOfRawData];
	memcpy(textContent, (UINT8*)pMapping + PointerToRawData, SizeOfRawData);

	/*写入物理磁盘的隐藏扇区，只需要使用createFile以写的方式打开文件句柄，并写文件，
	隐藏扇区起始就是保留扇区没有使用的部分，这里写在第二个扇区（即扇区1），即偏移512字节。
	注意因为前面使用过CreateFile，为了避免冲突前面的句柄都可以关闭
	*/
	CloseHandle(hFile);
	HANDLE hDrive; // 设备句柄
	LPCWSTR lpDriveName = L"\\\\.\\E:"; // 目标驱动器
	hDrive = CreateFile(lpDriveName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL, NULL);
	if (hDrive == INVALID_HANDLE_VALUE) {
		cout << "Failed to open drive, error code: " << GetLastError() << endl;
		return 1;
	}
	OVERLAPPED overLap = { 0 };
	overLap.Offset = 512 * 4;
	DWORD writeByte;
	DWORD readsize = 0;
	LARGE_INTEGER offset;//long long signed
	offset.QuadPart = (ULONGLONG)0 * (ULONGLONG)512;//0
	SetFilePointer(hDrive, offset.LowPart, &offset.HighPart, FILE_BEGIN);
	if (!WriteFile(hDrive, textContent, SizeOfRawData, &writeByte, &overLap)) {
		cout << dec << "error code" << GetLastError() << endl;
	}
	else {
		cout << "successfully write txt" << endl;
	}
	CloseHandle(hDrive);
	UnmapViewOfFile(pMapping);
	return true;
}


