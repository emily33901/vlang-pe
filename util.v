module main

fn align_down(x u64, align u64) u64 {
	return x & ~(align - 1)
}

fn align_up(x u64, align u64) u64 {
	return if (x & (align - 1)) != 0 { align_down(x, align) + align } else { x }
}

fn clamp<T>(value T, min T, max T) T {
	return if value > max {
		max
	} else if value < min {
		min
	} else {
		value
	}
}

type FakeArray = array
