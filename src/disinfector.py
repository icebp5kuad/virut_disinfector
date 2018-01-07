import re 
import os
import sys
import glob
import pefile
import struct


__author__ = "ICEBP5KUAD"

__version__ = "0.1"
__maintainer__ = "D00RT"
__email__ = ["icebp5kuad@gmail.com", "d00rt.fake@gmail.com"]
__status__ = "Test"


SIGNATURE_OFFSET = 0x2200
PATTERN_SIGNATURE_RE = re.compile('\xF9\xE8\x22\x00\x00\x00.\x31\xEB\x56')
PATTERN_1_RE = re.compile(r'\x52\xC1\xE9\x1D\x68\x31\xD4\x00\x00\x58\x5A\x81\xC1\x94\x01\x00\x00\x80\x4D\x00\xF0\x89\x6C\x24\x04\xF7\xD1\x81\x6C\x24\x04')


def get_signature_offsets(filename):
	if os.path.getsize(filename) >= 0x2200:
		size = os.path.getsize(filename)

		with open(filename, 'rb') as f:
			buff = f.read()

		iterator = PATTERN_SIGNATURE_RE.finditer(buff)

		last_match = False
		for match in iterator:
			last_match = match

		return last_match

	return False


def get_sub_value(filename, sig_offset):
	OFFSET = 0x75

	with open(filename, 'rb') as f:
		buff = f.read()

	value = struct.unpack('=I', buff[sig_offset + OFFSET: sig_offset + OFFSET + 4])[0]
	return value


def get_func_addr_offset(sig_offset):
	return sig_offset + 0x6


def fix_original_entry_point(pe, disk_offset, value_to_sub):

	# Get disk_offset virtual address
	va = get_virtual_addr_from_offset(pe, disk_offset)

	# Subtract the specific function address with the gotten value
	EOP_VA = va - value_to_sub

	pe.OPTIONAL_HEADER.AddressOfEntryPoint = EOP_VA


def get_virtual_addr_from_offset(pe, disk_offset):

	# Get the last section
	sections = pe.sections
	last_section = sections[len(sections) - 1]

	# Get the virtual address of the beginning of the last section
	section_va = last_section.VirtualAddress

	# Get the disk offset of the beginning of the last section from its virtual address
	section_offset = pe.get_offset_from_rva(section_va)

	# Get the offset between the beginning of the last section in disk and disk_offset
	offset = disk_offset - section_offset

	# Get the virtual address of the disk_offset
	return section_va + offset


def fix_section(pe, physical_offset):

	# Get the last section
	sections = pe.sections
	last_section = sections[len(sections) - 1]

	# Delete fileinfector shellcode
	pe.set_bytes_at_offset(physical_offset, '\x00' * 0x2200)

	# Fix up section size
	last_section.SizeOfRawData -= 0x2200


def write_to_file(pe, filename, output_filename=None):
	if not output_filename:
		pe.write(filename + ".disinfected")
	else:
		pe.write(output_filename)


def disinfect_file(filename, output_filename=None):
	if not os.path.exists(filename) and os.path.isdir(filename):
		raise Exception('[WARNING] {filename} does not exist. or is a directory.'.format(filename=filename))
	
	# Looking for fileinfector signature
	match = get_signature_offsets(filename)

	if not match:
		raise Exception('[WARNING] {filename} is not an infected file.'.format(filename=filename))
	
	try:
		pe = pefile.PE(filename)
	except Exception:
		raise Exception('[WARNING] pefile module can not parse {filename} file.'.format(filename=filename))
	
	if not match:
		raise Exception('[WARNING] {filename} is not an infected file.'.format(filename=filename))

	# Get the match offsets
	b_dsk_offs, f_dsk_offs = match.span()

	# Get value to subtract with a specific function address (offset)
	value_to_sub = get_sub_value(filename, b_dsk_offs)

	# Get a specific function address offset on disk
	func_addr_dsk_offset = get_func_addr_offset(b_dsk_offs)

	fix_original_entry_point(pe, func_addr_dsk_offset, value_to_sub)

	# Fix up the last section size, and delete the fileinfector shellcode
	fix_section(pe, b_dsk_offs)

	write_to_file(pe, filename, output_filename)

	return "[INFO] The file {filename} was disinfected sucessfuly as {output_filename}".format(filename=filename, output_filename=output_filename if output_filename else filename + ".disinfected")


##
# EXPORTS (disinfect_directory, disinfect_directory_use_test)
##
#
#	You can use these functions from another python modules to disinfect directories.
#
##
def disinfect_directory(path):
	if not os.path.isdir(path):
		raise Exception('{path} is not a directory'.format(path=path))

	for resource in glob.glob(os.path.join(path, '*')):
		try:
			yield disinfect_file(resource, resource)
		except Exception as e:
			yield e.message

	yield "[INFO] Finished."


def disinfect_directory_use_test(path):
	for file_status in disinfect_directory(path):
		print file_status


def main(filename, output_filename=None):

	print disinfect_file(filename, output_filename)


def usage():
	print ''
	print 'File disinfector. '
	print ''
	print 'Usage:'
	print ''
	print '      1) python {program_name} path_to_the_infected_pe'.format(program_name=sys.argv[0])
	print '      2) python {program_name} path_to_the_infected_pe output_filename'.format(program_name=sys.argv[0])
	print ''
	print 'Example:'
	print ''
	print '      1) python {program_name} explorer.exe'.format(program_name=sys.argv[0])
	print '      2) python {program_name} explorer.exe explorer_disinfected.exe'.format(program_name=sys.argv[0])
	print ''
	print 'Output:'
	print ''
	print '      If the function succeeds, the return value is a disinfected file with .disinfected extension'
	print '      or with the given output filename'


if __name__ == '__main__':
	if len(sys.argv) >= 2 and len(sys.argv) <= 3:
		try:
			main(sys.argv[1], sys.argv[2]) if len(sys.argv) == 3 else main(sys.argv[1])
		except Exception as e:
			print "[ERROR] Error: {err}".format(err=e)

	else:
		usage()
