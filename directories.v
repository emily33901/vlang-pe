module main

struct Architecture {}

struct BoundImportRef {
mut:
	@module   string
	timestamp u32
}

struct BoundImport {
mut:
	@module   string
	timestamp u32
	refs      []BoundImportRef
}

struct CLR {}

struct Certificate {}

struct Debugging {}

struct DelayImport {}

struct Exception {}

struct ImportFunction {
mut:
	name string

	hint    int
	ordinal int
	iat_va  u64
}

struct ImportLibrary {
mut:
	name         string
	rva          u64
	original_rva u64
	timestamp    u32
	funcs        []ImportFunction
}

struct ExportFunction {
mut:
	rva          u64
	has_name     bool
	name         string
	ordinal      u16
	forward_name string
}

struct ExportInfo {
mut:
	characteristics          u32
	time_date_stamp          u32
	major_version            u16
	minor_version            u16
	name                     string
	base                     u64
	number_of_functions      u32
	number_of_names          u32
	address_of_functions     u64 // RVA from base of image
	address_of_names         u64 // RVA from base of image
	address_of_name_ordinals u64 // RVA from base of image

	funcs []ExportFunction
}

struct GlobalPointerRegister {}

struct ImportAddress {}

struct LoadConfiguration {}

struct Relocation {}

struct Resource {}

struct TLS {}

type Directory = Architecture | BoundImport | CLR | Certificate | Debugging | DelayImport |
	Exception | ExportInfo | GlobalPointerRegister | ImportAddress | LoadConfiguration |
	Relocation | Resource | TLS | []ImportLibrary

union ImageThunkData {
	forwarder_string u64 // cstring
	function         u64 // &u64
	ordinal          u64
	addr_of_data     u64 // ImageImportByName
}

struct ImageImportDescriptor {
	// RVA to original unbound IAT (PIMAGE_THUNK_DATA)
	original_first_thunk u32
	// 0 if not bound,
	// -1 if bound, and real date\time stamp
	//     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
	// O.W. date/time stamp of DLL bound to (Old BIND)
	time_date_stamp u32
	forwarder_chain u32 // -1 if no forwarders
	name            u32
	first_thunk     u32 // RVA to IAT (if bound this IAT has actual addresses)
}

struct NativeExportInfo {
	characteristics          u32
	time_date_stamp          u32
	major_version            u16
	minor_version            u16
	name                     u32
	base                     u32
	number_of_functions      u32
	number_of_names          u32
	address_of_functions     u32 // RVA from base of image
	address_of_names         u32 // RVA from base of image
	address_of_name_ordinals u32 // RVA from base of image
}

const (
	import_snap_flag = u64(0x8000000000000000)
)

fn new_directory(mut pe Object, id DataDirectoryId, dd_desc DataDirectoryDescriptor) ?Directory {
	match id {
		.export {
			exports := ExportInfo{}

			export_info := pe.rva_data<NativeExportInfo>(dd_desc.rva) ?

			println('$export_info')

			return exports
		}
		.@import {
			mut imports := []ImportLibrary{}

			mut import_desc := pe.rva_data<ImageImportDescriptor>(dd_desc.rva) ?

			mut last_rva := dd_desc.rva
			for import_desc.name != 0 {
				name := pe.rva_data<string>(u64(import_desc.name)) ?

				println('$name')

				mut current_thunk_rva := u64(import_desc.first_thunk)
				mut addr_table := pe.rva_data<u64>(current_thunk_rva) ?

				mut current_original_thunk_rva := u64(import_desc.original_first_thunk)
				mut lookup_table := u64(0)
				if current_original_thunk_rva == 0 {
					lookup_table = addr_table
				} else {
					lookup_table = pe.rva_data<u64>(current_original_thunk_rva) ?
				}

				if current_original_thunk_rva == 0 {
					current_original_thunk_rva = addr_table
				}

				mut funcs := []ImportFunction{}
				if addr_table != 0 && lookup_table != 0 {
					for true {
						// Get VA from address table
						addr := pe.rva_data<u64>(current_thunk_rva) ?
						current_thunk_rva += sizeof(u64)

						if addr == 0 {
							break
						}

						lookup := pe.rva_data<u64>(current_original_thunk_rva) ?
						current_original_thunk_rva += sizeof(u64)

						if lookup & import_snap_flag != 0 {
							// Ordinal
							funcs << ImportFunction{
								name: ''
								hint: 0
								ordinal: int(lookup & 0xFFFF)
							}
						} else {
							// TODO(emily): max length here and check that its valid!
							func_name := pe.rva_data<string>(lookup + sizeof(u16)) ?
							hint := pe.rva_data<u16>(lookup) ?

							funcs << ImportFunction{
								name: func_name
								hint: hint
								ordinal: 0
							}
						}
					}
				}

				imports << ImportLibrary{
					name: name
					timestamp: import_desc.time_date_stamp
					rva: import_desc.first_thunk
					original_rva: import_desc.original_first_thunk
					funcs: funcs
				}

				last_rva += sizeof(ImageImportDescriptor)
				import_desc = pe.rva_data<ImageImportDescriptor>(last_rva) ?
			}

			// TODO(emily): clone here because autofree is mean :(
			return imports.clone()
		}
		.resource {}
		.exception {}
		.certificate {}
		.relocation {}
		.debug {}
		.arch {}
		.global {}
		.tls {}
		.config {}
		.bound_import {
			bound_imports := []BoundImport{}
		}
		.iat {}
		.delay_import {}
		.clr_header {}
		.reserved {}
	}

	return none
}
