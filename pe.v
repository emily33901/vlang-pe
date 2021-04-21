module main

import os

struct Object {
	file os.File
mut:
	dos_header       DosHeader
	nt_header        NTHeader
	data_directories []Directory
	size_of_headers  u32

	sections []Section
}

fn new_object(mut file os.File) ?Object {
	// Parse out DOS and NT headers
	mut o := Object{
		file: file
	}

	file.read_struct_at(mut o.dos_header, 0) ?
	file.read_struct_at(mut o.nt_header, o.dos_header.lfanew) ?

	// Check whether it is a valid PE file
	dos := o.dos_header
	nt := o.nt_header.optional

	if dos.magic != 23117 {
		return error('Invalid dos magic')
	}
	if nt.magic != C.IMAGE_NT_OPTIONAL_HDR64_MAGIC {
		return error('Invalid nt magic')
	}

	// Now read the sections
	{
		section_count := o.nt_header.file.number_of_sections

		o.sections = []Section{len: int(section_count)}

		offset := o.dos_header.lfanew + o.nt_header.file.size_of_optional_header +
			(sizeof(NTHeader) - sizeof(OptionalHeader))

		// Seek and read header
		file.seek(offset) ?
		for mut section in o.sections {
			file.read_struct(mut section.header) ?
		}

		for mut section in o.sections {
			// read data if there is any
			if section.file_size() > 0 {
				file_size, virtual_size := section.file_size(), section.virtual_size()
				len := if file_size > virtual_size { file_size } else { virtual_size }

				section.data = []byte{len: int(len)}

				file.read_from(section.header.pointer_to_raw_data, mut section.data[..section.file_size()]) ?
			}
		}
	}
	// Get the data directories
	o.nt_header.optional.number_of_rva_and_sizes = clamp(o.nt_header.optional.number_of_rva_and_sizes,
		u32(0), u32(max_data_dirs))
	mut dd_count := o.nt_header.optional.number_of_rva_and_sizes
	if dd_count > 0 {
		descs := []DataDirectoryDescriptor{len: int(dd_count)}

		offset := o.dos_header.lfanew + __offsetof(NTHeader, optional) + sizeof(OptionalHeader)

		// seek and read
		file.seek(offset) ?
		for i := 0; i < dd_count; i++ {
			file.read_struct(mut descs[i]) ?
		}

		for i := 0; i < dd_count; i++ {
			desc := &descs[i]
			id := DataDirectoryId(i)

			if desc.rva == 0 || desc.size == 0 {
				continue
			}

			if dir := new_directory(mut o, id, desc) {
				o.data_directories << dir
			}
		}
	}

	return o
}

fn (o Object) size_of_headers() u32 {
	return o.nt_header.optional.size_of_headers
}

fn (o Object) section_from_rva(rva u64) ?Section {
	for s in o.sections {
		if rva >= s.rva() && rva < (s.rva() + s.aligned_virtual_size(o.section_align())) {
			return s
		}
	}

	return none
}

fn (o Object) section_align() u64 {
	return o.nt_header.optional.section_alignment
}

fn (o Object) rva_to_file_offset(rva u64) ?u64 {
	if o.size_of_headers() > rva {
		// Address is in the headers so no adjustment needs
		// to take place
		return rva
	}

	section := o.section_from_rva(rva) ?
	return section.file_addr() + rva - section.rva()
}

fn (o Object) section_alignment() u64 {
	return o.nt_header.optional.section_alignment
}

fn (o Object) rva_data<T>(rva u64) ?T {
	mut section := o.section_from_rva(rva) ?
	return section.rva_data<T>(rva, o.section_alignment())
}

fn (o Object) directory<T>() ?T {
	for dir in o.data_directories {
		if dir is T {
			return dir
		}
	}

	return none
}

struct DosHeader {
pub mut:
	magic    u16
	cblp     u16
	cp       u16
	crlc     u16
	cparhdr  u16
	minalloc u16
	maxalloc u16
	ss       u16
	sp       u16
	csum     u16
	ip       u16
	cs       u16
	lfarlc   u16
	ovno     u16
	res      [4]u16
	oemid    u16
	oeminfo  u16
	res2     [10]u16
	lfanew   u32
}

enum WindowsSubsystem {
	unknown = 0
	native
	windows_gui
	windows_cui
	os2_cui = 5
	posix_cui = 7
	windows_native
	windows_ce
	efi
	efi_driver_boot_service
	efi_driver_runtime
	efi_rom
	xbox
	windows_boot_app = 16
}

struct NTHeader {
mut:
	signature u32
	file      FileHeader
	optional  OptionalHeader
}

struct OptionalHeader {
mut:
	// Standard fields
	magic                      u16
	linker_version             u16
	size_of_code               u32
	size_of_initialized_data   u32
	size_of_uninitialized_data u32
	address_of_entry_point     u32
	base_of_code               u32
	// Windows specific fields

	image_base               u64
	section_alignment        u32
	file_alignment           u32
	operating_system_version u32
	image_version            u32
	subsystem_version        WindowsSubsystem
	win32_version_value      u32
	size_of_image            u32
	size_of_headers          u32
	check_sum                u32
	subsystem                u16
	dll_characteristics      u16
	size_of_stack_reserve    u64
	size_of_stack_commit     u64
	size_of_heap_reserve     u64
	size_of_heap_commit      u64
	loader_flags             u32
	number_of_rva_and_sizes  u32
	// TODO(emily): data directory
	// data_directory [0]IMAGE_DATA_DIRECTORY
}

enum DataDirectoryId {
	export
	@import
	resource
	exception
	certificate
	relocation
	debug
	arch
	global
	tls
	config
	bound_import
	iat
	delay_import
	clr_header
	reserved
}

const (
	max_data_dirs = 16
)

struct FileHeader {
pub mut:
	machine                 u16
	number_of_sections      u16
	time_date_stamp         u32
	pointer_to_symbol_table u32
	number_of_symbols       u32
	size_of_optional_header u16
	characteristics         u16
}

struct DataDirectoryDescriptor {
	rva  u32
	size u32
}

[flag]
enum Characteristics {
	reserved1
	reserved2
	reserved3
	reserved4
	high_entropy_va
	dynamic_base
	force_integrity
	nx_compat
	no_isolation
	no_seh
	no_bind
	app_container
	wdm_driver
	guard_cf
	terminal_server_aware
}
