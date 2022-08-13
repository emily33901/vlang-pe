module main

import os

fn main() {
	// mut file := os.open_file('vlang-pe.exe', 'rb') ?
	mut file := os.open_file('c:/windows/system32/xboxgipsynthetic.dll', 'rb')?
	pe := new_object(mut file)?

	import_libraries := pe.directory<[]ImportLibrary>()?

	for lib in import_libraries {
		println('$lib.name')
		for func in lib.funcs {
			if func.ordinal != 0 {
				println('> $func.ordinal')
			} else {
				println('> $func.name')
			}
		}
		println('')
	}
}
