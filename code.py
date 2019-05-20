import pefile
import os
import json
import hexdumpfile
import struct

OPTIONAL_HEADER_NAMES = [['Magic', 'Magic'],
    ['MajorLinkerVersion', 'Major Linker Version'],
    ['MinorLinkerVersion', 'Minor Linker Version'],
    ['SizeOfCode', 'Size of Code'],
    ['SizeOfInitializedData', 'Size of Initialized Data'],
    ['SizeOfUninitializedData', 'Size of Uninitialized Data'],
    ['AddressOfEntryPoint', 'Address of Entry Point'],
    ['BaseOfCode', 'Base of Code'],
    ['BaseOfData', 'Base of Data'],
    ['ImageBase', 'Image Base'],
    ['SectionAlignment', 'Section Alignment'],
    ['FileAlignment', 'File Alignment'],
    ['MajorOperatingSystemVersion', 'Major Operating System Version'],
    ['MinorOperatingSystemVersion', 'Minor Operating System Version'],
    ['MajorImageVersion', 'Major Image Version'],
    ['MinorImageVersion', 'Minor Image Version'],
    ['MajorSubsystemVersion', 'Major Subsystem Version'],
    ['MinorSubsystemVersion', 'Minor Subsystem Version'],
    ['Win32VersionValue', 'Win32 Version Value'],
    ['SizeOfImage', 'Size of Image'],
    ['SizeOfHeaders', 'Size of Headers'],
    ['CheckSum', 'Checksum'],
    ['Subsystem', 'Subsystem'],
    ['DllCharacteristics', 'DllCharacteristics'],
    ['SizeOfStackReserve', 'Size of Stack Reserve'],
    ['SizeOfStackCommit', 'Size of Stack Commit'],
    ['SizeOfHeapReserve', 'Size of Heap Reserve'],
    ['SizeOfHeapCommit', 'Size of Heap Commit'],
    ['NumberOfRvaAndSizes', 'Number of Data Directories']]

FILE_HEADER_NAMES = [['Machine', 'Machine'],
    ['NumberOfSections', 'Number of Sections'],
    ['TimeDateStamp', 'Time Date Stamp'],
    ['PointerToSymbolTable', 'Pointer to Symbol Table'],
    ['NumberOfSymbols', 'Number of Symbols'],
    ['SizeOfOptionalHeader', 'Size of Optional Header'],
    ['Characteristics', 'Characteristics']]

MACHINE_NAMES_AND_VALUES = [
    [332, 'IMAGE_FILE_MACHINE_I386'],
    [512, 'IMAGE_FILE_MACHINE_IA64'],
    [34404, 'IMAGE_FILE_MACHINE_AMD64']]

CHARACTERISTIC_NAMES_AND_VALUES = [
    [1, 'IMAGE_FILE_RELOCS_STRIPPED'],
    [2, 'IMAGE_FILE_EXECUTABLE_IMAGE'],
    [4, 'IMAGE_FILE_LINE_NUMS_STRIPPED'],
    [8, 'IMAGE_FILE_LOCAL_SYMS_STRIPPED'],
    [16, 'IMAGE_FILE_AGGRESIVE_WS_TRIM'],
    [32, 'IMAGE_FILE_LARGE_ADDRESS_AWARE'],
    [128, 'IMAGE_FILE_BYTES_REVERSED_LO'],
    [256, 'IMAGE_FILE_32BIT_MACHINE'],
    [512, 'IMAGE_FILE_DEBUG_STRIPPED'],
    [1024, 'IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP'],
    [2048, 'IMAGE_FILE_NET_RUN_FROM_SWAP'],
    [4096, 'IMAGE_FILE_SYSTEM'],
    [8192, 'IMAGE_FILE_DLL'],
    [16384, 'IMAGE_FILE_UP_SYSTEM_ONLY'],
    [32768, 'IMAGE_FILE_BYTES_REVERSED_HI']]

DLL_CHARACTERISTIC_NAMES_AND_VALUES = [
    ['0x0040', 'IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE'],
    ['0x0080', 'IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY'],
    ['0x0100', 'IMAGE_DLLCHARACTERISTICS_NX_COMPAT'],
    ['0x0200', 'IMAGE_DLLCHARACTERISTICS_NO_ISOLATION'],
    ['0x0400', 'IMAGE_DLLCHARACTERISTICS_NO_SEH'],
    ['0x0800', 'IMAGE_DLLCHARACTERISTICS_NO_BIND'],
    ['0x2000', 'IMAGE_DLLCHARACTERISTICS_WDM_DRIVER'],
    ['0x8000', 'IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE']]

SECTION_NAMES = [['Name', 'Name'],
    ['Misc_VirtualSize', 'Virtual Size'],
    ['VirtualAddress', 'RVA'],
    ['SizeOfRawData', 'Size of Raw Data'],
    ['PointerToRawData', 'Pointer to Raw Data'],
    ['PointerToRelocations', 'Pointer to Relocations'],
    ['PointerToLinenumbers', 'Pointerto Line Numbers'],
    ['NumberOfRelocations', 'Number Of Relocations'],
    ['NumberOfLinenumbers', 'Number of Line Numbers'],
    ['Characteristics', 'Characteristics']]

DOS_HEADER_NAMES_AND_VALUES = [['e_magic', 'Magic number'],
    ['e_cblp', 'Bytes on Last Page of File'],
    ['e_cp', 'Pages in File'],
    ['e_crlc', 'Relocations'],
    ['e_cparhdr', 'Size of Header in Paragraphs'],
    ['e_minalloc', 'Minimum Extra Paragraphs Needed'],
    ['e_maxalloc', 'Maximum Extra Paragraphs Needed'],
    ['e_ss', 'Initial (relative) SS value'],
    ['e_sp', 'Initial SP value'],
    ['e_csum', 'Checksum'],
    ['e_ip', 'Initial IP value'],
    ['e_cs', 'Initial (relative) CS value'],
    ['e_lfarlc', 'Offset to Relocation Table'],
    ['e_ovno', 'Overlay Number'],
    ['e_res', 'Reserved Words'],
    ['e_oemid', 'OEM Identifier'],
    ['e_oeminfo', 'OEM Information'],
    ['e_res2', 'Reserved Words'],
    ['e_lfanew', 'Offset to New EXE Header']]

data = {'dump_file': ''}
data['dump_file'] = hexdumpfile.read_hex_dump(os.sys.argv[1], 0, 100*16)
pe = pefile.PE(os.sys.argv[1])

dump_file = pe.dump_dict()

def write_imported_symbols(dump_file_params):
    FILE_IMPORTED_SYMBOLS = "imported_symbols.json"

    import_dlls = []

    for dll in dump_file_params["Imported symbols"]:
        for index in range(1, len(dll)):
            import_dlls.append(dll[index])
    
    with open(FILE_IMPORTED_SYMBOLS, 'w') as outfile:  
        json.dump(import_dlls, outfile, indent=2)

def write_exported_symbols(dump_file_params):
    for export_symbol in dump_file_params["Exported symbols"]:
        print(export_symbol)

def read_sections(pefile_params):
    sections_json = dump_file["PE Sections"]
    count = 0
    sections = {}
    names = []
    for section in pefile_params.sections:
        names.append(section.Name.rstrip(' \t\r\n\0'))
        name_value = section.Name.encode('hex')
        name_value = " ".join(name_value[i:i+2] for i in range(0, len(name_value), 2))

        count_temp = 0    
        value = {}

        for section_name in SECTION_NAMES:
            if section_name[0] == 'Name':
                value[str(count_temp)] = [
                    hex(sections_json[count][section_name[0]]['FileOffset']),
                    name_value,
                    section_name[1],
                    section.Name.rstrip(' \t\r\n\0')
                ]
            else:
                value[str(count_temp)] = [
                    hex(sections_json[count][section_name[0]]['FileOffset']),
                    hex(sections_json[count][section_name[0]]['Value']),
                    section_name[1],
                    ''
                ]
            count_temp += 1

        flags = sections_json[count]['Flags']
        
        for flag in flags:
            value[str(count_temp)] = [
                '',
                '',
                '',
                flag
            ]
            count_temp += 1
        value['data'] = hexdumpfile.read_hex_dump(os.sys.argv[1], section.PointerToRawData, section.SizeOfRawData)

        sections[section.Name.rstrip(' \t\r\0')] = value

        count_temp = count_temp + 1
        count += 1

    sections["size"] = count_temp
    sections["names"] = names
    return sections

def read_signature(pefile_params):
    signature_json = dump_file['NT_HEADERS']

    result_json = {
        0: [
        hex(signature_json['Signature']['FileOffset']),
        hex(signature_json['Signature']['Value']),
        'singature',
        'IMAGE_NT_SINGATURE PE'
        ]
    }

    return result_json

def read_optional_header(pefile_params):
    optional_json = dump_file['OPTIONAL_HEADER']
    dllCharacteristics = dump_file['DllCharacteristics']

    result_json = {}

    count = 0
    for name in OPTIONAL_HEADER_NAMES:
        if name[0] != 'Win32VersionValue':
            result_json[str(count)] = [
                hex(optional_json[name[0]]['FileOffset']),
                hex(optional_json[name[0]]['Value']),
                name[1],
                ''
            ]
        else:
            result_json[str(count)] = [
                hex(optional_json['MinorSubsystemVersion']['FileOffset'] + 4),
                '0x0',
                name[1],
                ''
            ]
        count = count + 1
    
    for dll in dllCharacteristics:
        for dllCharacteristic in DLL_CHARACTERISTIC_NAMES_AND_VALUES:
            if dllCharacteristic[1] == dll:
                result_json[str(count)] = [
                    '',
                    '',
                    dllCharacteristic[0][2:],
                    dll
                ]
                break
        count = count + 1

    for data_directory in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
        data_directory_json = data_directory.dump_dict()
        result_json[str(count)] = [
            hex(data_directory_json['VirtualAddress']['FileOffset']),
            hex(data_directory_json['VirtualAddress']['Value']),
            'RVA',
            data_directory_json['Structure']
        ]

        result_json[str(count + 1)] = [
            hex(data_directory_json['Size']['FileOffset']),
            hex(data_directory_json['Size']['Value']),
            'Size',
            ''
        ]
        count = count + 2

    return result_json

def read_file_header(pefile_params):
    file_header_json = dump_file['FILE_HEADER']
    flags_json = dump_file['Flags']
    result_json = {}
    count = 0

    for file_header_name in FILE_HEADER_NAMES:
        pFile = hex(file_header_json[file_header_name[0]]['FileOffset'])
        value = ''
        data = ''

        if (file_header_name[0] == 'TimeDateStamp'):
            data = file_header_json[file_header_name[0]]['Value'].split()[0]
            temp = file_header_json[file_header_name[0]]['Value']
            value = temp[(temp.find(' ') + 1):]
        else:
            data = hex(file_header_json[file_header_name[0]]['Value'])
            if (file_header_name[0] == 'Machine'):
                for machine_name_and_value in MACHINE_NAMES_AND_VALUES:
                    if (data == hex(machine_name_and_value[0])):
                        value = machine_name_and_value[1]
        description = file_header_name[1]

        result_json[str(count)] = [
            pFile,
            data,
            description,
            value
        ]

        count = count + 1
    
    for flag_json in flags_json:
        value = ''
        for characteristic_name_and_value in CHARACTERISTIC_NAMES_AND_VALUES:
            if (characteristic_name_and_value[1] == flag_json):
                value = hex(characteristic_name_and_value[0])
        result_json[str(count)] = [
            '',
            '',
            value,
            flag_json
        ]

        count = count + 1

    return result_json


def read_dos_header(pefile_params):
    dos_header = dump_file['DOS_HEADER']
    count = 0

    result_json = {}

    for dos_header_name_and_value in DOS_HEADER_NAMES_AND_VALUES:
        if (dos_header_name_and_value[0] == 'e_res'):
            temp = dos_header[dos_header_name_and_value[0]]['Value'].split('\\x')[1:]
            for index in range(4):
                data = '0x' + str(temp[index * 2]) + str(temp[index * 2 + 1])
                result_json[str(count)] = [
                    hex(dos_header[dos_header_name_and_value[0]]['FileOffset'] + index * 2),
                    data,
                    dos_header_name_and_value[1],
                    ''
                ]
                count = count + 1
            count = count - 1
        elif (dos_header_name_and_value[0] == 'e_res2'):
            temp = dos_header[dos_header_name_and_value[0]]['Value'].split('\\x')[1:]
            for index in range(10):
                data = '0x' + str(temp[index * 2]) + str(temp[index * 2 + 1])
                result_json[str(count)] = [
                    hex(dos_header[dos_header_name_and_value[0]]['FileOffset'] + index * 2),
                    data,
                    dos_header_name_and_value[1],
                    ''
                ]
                count = count + 1
            count = count - 1
        else:
            value_temp = ''

            if (dos_header_name_and_value[0] == 'e_magic'):
                value_temp = 'MZ'
            result_json[str(count)] = [
                hex(dos_header[dos_header_name_and_value[0]]['FileOffset']),
                hex(dos_header[dos_header_name_and_value[0]]['Value']),
                dos_header_name_and_value[1],
                value_temp
            ]
        count = count + 1
    return result_json

def read_dos_header_data():
    pFile = dump_file['DOS_HEADER']['e_lfarlc']['Value']

    return hexdumpfile.read_hex_dump(os.sys.argv[1], int(pFile), 10*16)

data['optional_header'] = read_optional_header(pe)
data['sections'] = read_sections(pe)
data['signature'] = read_signature(pe)
data['file_header'] = read_file_header(pe)
data['dos_header'] = read_dos_header(pe)
data['dos_header']['data'] = read_dos_header_data()

with open('data.json', 'w') as outfile:
    json.dump(data, outfile, indent=2)