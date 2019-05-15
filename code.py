import pefile
import os
import json
import hexdumpfile

data = {'dump_file': ''}

data['dump_file'] = hexdumpfile.read_hex_dump(os.sys.argv[1], 0, 100*16)



pe = pefile.PE(os.sys.argv[1])

# for item in pe.DIRECTORY_ENTRY_IMPORT:
#     print item.dll
#     for i in item.imports:
#         print i.name

dump_file = pe.dump_dict()



#print(json.dumps(dump_file))

with open('data1.json', 'w') as outfile:
    json.dump(dump_file, outfile, indent=2)

FILE_IMPORTED_SYMBOLS = "imported_symbols.json"

def write_imported_symbols(dump_file_params):
    import_dlls = []

    for dll in dump_file_params["Imported symbols"]:
        for index in range(1, len(dll)):
            import_dlls.append(dll[index])
    
    with open(FILE_IMPORTED_SYMBOLS, 'w') as outfile:  
        json.dump(import_dlls, outfile, indent=2)

def write_exported_symbols(dump_file_params):
    
    for export_symbol in dump_file_params["Exported symbols"]:
        print(export_symbol)

def write_sections(pefile_params):
    sections_json = dump_file["PE Sections"]
    count = 0
    sections = {}
    names = []
    for section in pefile_params.sections:
        names.append(section.Name.rstrip(' \t\r\n\0'))
        #print(section.Name, hex(section.PointerToRawData), hex(section.VirtualAddress), hex(section.Misc_VirtualSize), section.SizeOfRawData)
        #print(hexdumpfile.read_hex_dump(os.sys.argv[1], section.PointerToRawData, section.SizeOfRawData))
        name_value = section.Name.encode('hex')
        name_value = " ".join(name_value[i:i+2] for i in range(0, len(name_value), 2))
        value = {
            0: [
                hex(sections_json[count]['Name']['FileOffset']),
                name_value,
                'Name',
                section.Name.rstrip(' \t\r\n\0')
            ],
            1: [
                hex(sections_json[count]['Misc_VirtualSize']['FileOffset']),
                hex(sections_json[count]['Misc_VirtualSize']['Value']),
                'Virtual Size',
                ''               
            ],
            2: [
                hex(sections_json[count]['VirtualAddress']['FileOffset']),
                hex(sections_json[count]['VirtualAddress']['Value']),
                'RVA',
                ''                
            ],
            3: [
                hex(sections_json[count]['SizeOfRawData']['FileOffset']),
                hex(sections_json[count]['SizeOfRawData']['Value']),
                'Size of Raw Data',
                ''                
            ],
            4: [
                hex(sections_json[count]['PointerToRawData']['FileOffset']),
                hex(sections_json[count]['PointerToRawData']['Value']),
                'Pointer to Raw Data',
                ''                
            ],
            5: [
                hex(sections_json[count]['PointerToRelocations']['FileOffset']),
                hex(sections_json[count]['PointerToRelocations']['Value']),
                'Pointer to Relocations',
                ''                
            ],
            6: [
                hex(sections_json[count]['PointerToLinenumbers']['FileOffset']),
                hex(sections_json[count]['PointerToLinenumbers']['Value']),
                'Pointer to Line Numbers',
                ''                
            ],
            7: [
                hex(sections_json[count]['NumberOfRelocations']['FileOffset']),
                hex(sections_json[count]['NumberOfRelocations']['Value']),
                'Number of Relocations',
                ''                
            ],
            8: [
                hex(sections_json[count]['NumberOfLinenumbers']['FileOffset']),
                hex(sections_json[count]['NumberOfLinenumbers']['Value']),
                'Number of Line Numbers',
                ''                
            ],
            9: [
                hex(sections_json[count]['Characteristics']['FileOffset']),
                hex(sections_json[count]['Characteristics']['Value']),
                'Characteristics',
                ''                
            ]
        }
        flags = sections_json[count]['Flags']
        
        temp_count = 10
        for flag in flags:
            value[str(temp_count)] = [
                '',
                '',
                '',
                flag
            ]
            temp_count += 1
        value['data'] = hexdumpfile.read_hex_dump(os.sys.argv[1], section.PointerToRawData, section.SizeOfRawData)

        sections[section.Name.rstrip(' \t\r\0')] = value

        count = count + 1

    sections["size"] = count
    sections["names"] = names
    return sections

#write_imported_symbols(dump_file)
#write_exported_symbols(dump_file)

#print pe.OPTIONAL_HEADER
#print pe.FILE_HEADER
#print pe.DOS_HEADER
#pe.DOS_HEADER.values()
data["sections"] = write_sections(pe)
with open('data.json', 'w') as outfile:
    json.dump(data, outfile, indent=2)
#print pe.NT_HEADERS.get_file_offset()
#print pe.NT_HEADERS.__getattribute__('Signature').__getitem__("FileOffset")

#print(json.dumps(pe.DOS_HEADER.dump_dict(), indent=4))