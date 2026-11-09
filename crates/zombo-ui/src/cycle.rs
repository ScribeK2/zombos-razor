/// The item `delta` places after `current` in `all`, wrapping around. An item
/// not in `all` counts as the first one.
pub fn step<T: Copy + PartialEq>(all: &[T], current: T, delta: isize) -> T {
    let len = isize::try_from(all.len()).unwrap_or(isize::MAX).max(1);
    let at = isize::try_from(all.iter().position(|&x| x == current).unwrap_or(0)).unwrap_or(0);
    let next = usize::try_from(at.saturating_add(delta).rem_euclid(len)).unwrap_or(0);
    all.get(next).copied().unwrap_or(current)
}

#[cfg(test)]
mod tests {
    use super::step;

    #[test]
    fn wraps_both_ways_and_survives_empty_or_unknown() {
        assert_eq!(step(&[1, 2, 3], 3, 1), 1);
        assert_eq!(step(&[1, 2, 3], 1, -1), 3);
        assert_eq!(step(&[1, 2, 3], 9, 1), 2);
        assert_eq!(step(&[], 5, 1), 5);
        assert!([1, 2, 3].contains(&step(&[1, 2, 3], 1, isize::MIN)));
        assert!([1, 2, 3].contains(&step(&[1, 2, 3], 1, isize::MAX)));
    }
}
