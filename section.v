module main

struct SectionHeader {
mut:
	name                 [8]u8
	virtual_size         u32
	virtual_addr         u32
	size_of_raw_data     u32
	pointer_to_raw_data  u32
	pointer_to_relocs    u32
	pointer_to_line_nums u32
	number_of_relocs     u16
	number_of_line_nums  u16
	characteristics      Characteristics
}

struct Section {
mut:
	// Reserved for when we virtual map / unmap
	// this section
	old_len int
	mapped  bool
pub mut:
	header SectionHeader
	data   []byte
}

fn (s Section) file_addr() u64 {
	return s.header.pointer_to_raw_data
}

fn (s Section) rva() u64 {
	return s.header.virtual_addr
}

fn (s Section) file_size() u64 {
	return s.header.size_of_raw_data
}

fn (s Section) virtual_size() u64 {
	return s.header.virtual_size
}

fn (s Section) aligned_virtual_size(section_align u64) u64 {
	if s.file_size() > 0 && s.virtual_size() == 0 {
		return align_up(s.file_size(), section_align)
	}

	return align_up(s.virtual_size(), section_align)
}

fn (s Section) str() string {
	return unsafe { s.header.name[0..].bytestr() }
}

fn (mut s Section) virtual_data(section_alignment u64) []byte {
	fake := unsafe {
		FakeArray{
			data: s.data.data
			len: int(s.header.virtual_size)
			cap: int(s.header.virtual_size)
			element_size: 1
		}
	}

	return unsafe { *&[]byte(&fake) }
}

[manualfree]
fn (mut s Section) rva_data<T>(rva u64, section_alignment u64) ?T {
	va := rva - s.rva()
	vdata := s.virtual_data(section_alignment)

	addr := unsafe {
		&u8(u64(vdata.data) + va)
	}

	$if T is string {
		// special for string
		return unsafe { tos_clone(addr) }
	}

	// Just going to assume T is a struct
	return unsafe { *&T(addr) }
}
