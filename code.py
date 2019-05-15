import pefile
import os
import json
import hexdumpfile

data = {'dump_file': ''}

data['dump_file'] = hexdumpfile.read_hex_dump(os.sys.argv[1])

with open('data.json', 'w') as outfile:
    json.dump(data, outfile, indent=2)

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
    for section in pefile_params.sections:
        print(section.Name, hex(section.PointerToRawData), hex(section.VirtualAddress), hex(section.Misc_VirtualSize), section.SizeOfRawData)
        if (len(section.get_data()) != 0):
            value = ""
            name = "section-" + section.Name + ".txt"

            for character in section.get_data():
                if (ord(character) < 32 or ord(character) > 126):
                    value = value + '.'
                else:
                    value = value + character

            # with open(os.getcwd() + "/section-%s.txt" % section.Name, "w") as outfile:
            #     outfile.write(value)

#write_imported_symbols(dump_file)
#write_exported_symbols(dump_file)

#print pe.OPTIONAL_HEADER
#print pe.FILE_HEADER
#print pe.DOS_HEADER
#pe.DOS_HEADER.values()
#write_sections(pe)
#print pe.NT_HEADERS.get_file_offset()
#print pe.FILE_HEADER.dump_dict()
#print pe.NT_HEADERS.__getattribute__('Signature').__getitem__("FileOffset")

print(json.dumps(pe.DOS_HEADER.dump_dict(), indent=4))