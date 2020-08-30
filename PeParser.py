import pefile
import struct
import datetime

def print_info(data_list):
    for data in data_list:
        print(data[0].ljust(20), data[1].ljust(30), str(data[2]).ljust(20) )

def dos_header_info(pe):
    print('-'*100)
    print('Dos Header Info\n')
    dos_header_list = []
    dos_header_list.append(['실제 변수명', '의미', '값'])
    dos_header_list.append(['emagic', 'DOS Signature', struct.pack('<H', pe.DOS_HEADER.e_magic).decode('utf8')])
    dos_header_list.append(['e_cblp', 'Bytes on Last Page of File', hex(pe.DOS_HEADER.e_cblp)])
    dos_header_list.append(['e_cp', 'Pages in File', hex(pe.DOS_HEADER.e_cp)])
    dos_header_list.append(['e_crlc', 'Relocations', hex(pe.DOS_HEADER.e_crlc)])
    dos_header_list.append(['e_cparhdr', 'Size of Header in Paragraphs', hex(pe.DOS_HEADER.e_cparhdr)])
    dos_header_list.append(['e_minalloc', 'Minimum Extra Paragraphs', hex(pe.DOS_HEADER.e_minalloc)])
    dos_header_list.append(['e_maxalloc', 'Maximum Extra Paragraphs', hex(pe.DOS_HEADER.e_maxalloc)])
    dos_header_list.append(['e_ss', 'Initial(relatice) SS', hex(pe.DOS_HEADER.e_ss)])
    dos_header_list.append(['e_sp', 'Initial SP', hex(pe.DOS_HEADER.e_sp)])
    dos_header_list.append(['e_csum', 'Checksum', hex(pe.DOS_HEADER.e_csum)])
    dos_header_list.append(['e_ip', 'Initial IP', hex(pe.DOS_HEADER.e_ip)])
    dos_header_list.append(['e_cs', 'Initial CS', hex(pe.DOS_HEADER.e_cs)])
    dos_header_list.append(['e_lfarlc', 'Offess to Relocation Table', hex(pe.DOS_HEADER.e_lfarlc)])
    dos_header_list.append(['e_ovno', 'Overlay Number', hex(pe.DOS_HEADER.e_ovno)])
    dos_header_list.append(['e_res', 'Reserved', hex(pe.DOS_HEADER.e_res[0])])
    dos_header_list.append(['e_res', 'Reserved', hex(pe.DOS_HEADER.e_res[1])])
    dos_header_list.append(['e_res', 'Reserved', hex(pe.DOS_HEADER.e_res[2])])
    dos_header_list.append(['e_res', 'Reserved', hex(pe.DOS_HEADER.e_res[3])])
    dos_header_list.append(['e_oemid', 'OEM Identifier', hex(pe.DOS_HEADER.e_oemid)])
    dos_header_list.append(['e_oeminfo', 'OEM Information', hex(pe.DOS_HEADER.e_oeminfo)])
    dos_header_list.append(['e_res2', 'Reserved', hex(pe.DOS_HEADER.e_res2[1])])
    dos_header_list.append(['e_res2', 'Reserved', hex(pe.DOS_HEADER.e_res2[2])])
    dos_header_list.append(['e_res2', 'Reserved', hex(pe.DOS_HEADER.e_res2[3])])
    dos_header_list.append(['e_res2', 'Reserved', hex(pe.DOS_HEADER.e_res2[4])])
    dos_header_list.append(['e_res2', 'Reserved', hex(pe.DOS_HEADER.e_res2[5])])
    dos_header_list.append(['e_res2', 'Reserved', hex(pe.DOS_HEADER.e_res2[6])])
    dos_header_list.append(['e_res2', 'Reserved', hex(pe.DOS_HEADER.e_res2[7])])
    dos_header_list.append(['e_res2', 'Reserved', hex(pe.DOS_HEADER.e_res2[8])])
    dos_header_list.append(['e_res2', 'Reserved', hex(pe.DOS_HEADER.e_res2[9])])
    dos_header_list.append(['e_lfanew', 'NT Header Offset', hex(pe.DOS_HEADER.e_lfanew)])

    print_info(dos_header_list)
    print('-'*100)

def nt_header_info(pe):
    print('NT Header Info\n')
    
    nt_header_list = []
    nt_header_list.append(['실제 변수명', '의미', '값'])
    nt_header_list.append(['Signatue', 'NT Signature', struct.pack('<H', pe.NT_HEADERS.Signature).decode('utf8')])
    
    print_info(nt_header_list)
    print('-'*100)

print('-'*100)
path = ".\VSCodeUserSetup-x64-1.48.2.exe"
print('PATH = ' + path)
pe = pefile.PE(path)
dos_header_info(pe)
nt_header_info(pe)