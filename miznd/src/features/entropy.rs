/// Shannon entropy of a byte slice.
///
/// Returns a value in [0.0, 8.0]:
///   - 0.0 → all bytes identical (e.g. all-zero padding)
///   - 8.0 → perfectly uniform distribution (ideal encrypted / compressed data)
///
/// Zero allocations; O(n) over payload length.
#[allow(dead_code)] // called from ingestion.rs via crate::entropy::shannon_entropy
#[inline]
pub fn shannon_entropy(payload: &[u8]) -> f64 {
    if payload.is_empty() {
        return 0.0;
    }

    let mut freq = [0u32; 256];
    for &b in payload {
        freq[b as usize] += 1;
    }

    let len = payload.len() as f64;
    let mut entropy = 0.0f64;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_zero() {
        assert_eq!(shannon_entropy(&[]), 0.0);
    }

    #[test]
    fn uniform_byte_is_zero() {
        let data = vec![0xAAu8; 1024];
        assert_eq!(shannon_entropy(&data), 0.0);
    }

    #[test]
    fn all_distinct_bytes_approaches_eight() {
        // 256 distinct bytes → H ≈ 8.0
        let data: Vec<u8> = (0..=255u8).collect();
        let h = shannon_entropy(&data);
        assert!((h - 8.0).abs() < 1e-9, "got {h}");
    }

    #[test]
    fn ascii_text_is_low() {
        let text = b"Hello, world! This is plain ASCII text.";
        let h = shannon_entropy(text);
        // Typical English text ≈ 3.5–4.5
        assert!(h > 2.0 && h < 6.0, "got {h}");
    }
}
