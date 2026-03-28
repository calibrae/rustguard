//! Anti-replay sliding window.
//!
//! WireGuard uses a 2048-bit bitmap to track which nonces have been seen.
//! The window slides forward as new (higher) counters arrive.
//! Any counter below the window floor or already marked is rejected.
//!
//! This is the same algorithm used in IPsec (RFC 6479) and the
//! WireGuard kernel implementation.

const WINDOW_SIZE: u64 = 2048;
const BITMAP_LEN: usize = (WINDOW_SIZE / 64) as usize; // 32 u64s

pub struct ReplayWindow {
    /// Highest counter value we've accepted.
    top: u64,
    /// Bitmap of seen counters. Bit i of bitmap[j] represents
    /// counter (top - (j * 64 + i)), relative to the current top.
    bitmap: [u64; BITMAP_LEN],
}

impl ReplayWindow {
    pub fn new() -> Self {
        Self {
            top: 0,
            bitmap: [0; BITMAP_LEN],
        }
    }

    /// Check if a counter would be acceptable (without marking it).
    /// Call `update()` only after the packet is authenticated.
    pub fn check(&self, counter: u64) -> bool {
        // First packet: accept any counter.
        if self.top == 0 && self.bitmap == [0; BITMAP_LEN] {
            return true;
        }

        if counter > self.top {
            return true; // New high is always acceptable.
        }

        let age = self.top - counter;
        if age >= WINDOW_SIZE {
            return false; // Too old.
        }

        let idx = age as usize;
        let word = idx / 64;
        let bit = idx % 64;

        self.bitmap[word] & (1u64 << bit) == 0
    }

    /// Mark a counter as seen. Only call after authentication succeeds.
    pub fn update(&mut self, counter: u64) {
        if self.top == 0 && self.bitmap == [0; BITMAP_LEN] {
            self.top = counter;
            self.set_bit(0);
            return;
        }

        if counter > self.top {
            let shift = counter - self.top;
            self.shift_window(shift);
            self.top = counter;
            self.set_bit(0);
            return;
        }

        let age = self.top - counter;
        if age < WINDOW_SIZE {
            let idx = age as usize;
            let word = idx / 64;
            let bit = idx % 64;
            self.bitmap[word] |= 1u64 << bit;
        }
    }

    /// Combined check-and-update (for backward compat in tests).
    pub fn check_and_update(&mut self, counter: u64) -> bool {
        if !self.check(counter) {
            return false;
        }
        self.update(counter);
        true
    }

    fn set_bit(&mut self, idx: usize) {
        let word = idx / 64;
        let bit = idx % 64;
        self.bitmap[word] |= 1u64 << bit;
    }

    fn shift_window(&mut self, shift: u64) {
        if shift >= WINDOW_SIZE {
            // Entire window is stale, reset.
            self.bitmap = [0; BITMAP_LEN];
            return;
        }

        let word_shift = (shift / 64) as usize;
        let bit_shift = (shift % 64) as u32;

        if word_shift > 0 {
            // Shift whole words.
            self.bitmap.copy_within(..BITMAP_LEN - word_shift, word_shift);
            self.bitmap[..word_shift].fill(0);
        }

        if bit_shift > 0 {
            // Shift remaining bits within words, from low index to high.
            // Bits move toward higher positions (older ages).
            let mut carry = 0u64;
            for word in self.bitmap.iter_mut() {
                let new_carry = *word >> (64 - bit_shift);
                *word = (*word << bit_shift) | carry;
                carry = new_carry;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequential_counters_accepted() {
        let mut w = ReplayWindow::new();
        for i in 0..100 {
            assert!(w.check_and_update(i), "counter {i} should be accepted");
        }
    }

    #[test]
    fn duplicate_rejected() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_update(0));
        assert!(!w.check_and_update(0), "duplicate should be rejected");
    }

    #[test]
    fn old_within_window_accepted_once() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_update(100));
        assert!(w.check_and_update(50), "old but in window");
        assert!(!w.check_and_update(50), "duplicate of old");
    }

    #[test]
    fn too_old_rejected() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_update(WINDOW_SIZE + 10));
        assert!(!w.check_and_update(0), "below window floor");
        assert!(!w.check_and_update(10), "also below window floor");
    }

    #[test]
    fn out_of_order_within_window() {
        let mut w = ReplayWindow::new();
        // Send 0, 2, 1, 4, 3 — all should be accepted.
        assert!(w.check_and_update(0));
        assert!(w.check_and_update(2));
        assert!(w.check_and_update(1));
        assert!(w.check_and_update(4));
        assert!(w.check_and_update(3));
    }

    #[test]
    fn large_jump_clears_window() {
        let mut w = ReplayWindow::new();
        for i in 0..100 {
            w.check_and_update(i);
        }
        // Jump far ahead — everything old is gone.
        assert!(w.check_and_update(100_000));
        assert!(!w.check_and_update(50), "old counter after big jump");
    }

    #[test]
    fn window_boundary_exact() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_update(WINDOW_SIZE));
        // Counter 1 is exactly at the edge (age = WINDOW_SIZE - 1).
        assert!(w.check_and_update(1));
        // Counter 0 is just outside (age = WINDOW_SIZE).
        assert!(!w.check_and_update(0));
    }

    #[test]
    fn stress_sequential() {
        let mut w = ReplayWindow::new();
        for i in 0..10_000 {
            assert!(w.check_and_update(i));
        }
    }

    #[test]
    fn stress_reverse_within_window() {
        let mut w = ReplayWindow::new();
        // Deliver packets in reverse order within window size.
        let start = WINDOW_SIZE - 1;
        for i in (0..=start).rev() {
            assert!(w.check_and_update(i), "counter {i} should be accepted");
        }
    }

    // --- Edge case tests that would have caught the inverted shift bug ---

    #[test]
    fn replay_after_shift() {
        // This is the test that catches inverted bit-shift direction.
        // Mark counter N, advance past it by a small amount, replay N.
        let mut w = ReplayWindow::new();
        assert!(w.check_and_update(10));
        // Advance window by receiving a higher counter.
        assert!(w.check_and_update(15));
        // Counter 10 is still within the window (age=5) but was already seen.
        assert!(
            !w.check_and_update(10),
            "counter 10 was seen before the shift, must still be rejected after shift"
        );
    }

    #[test]
    fn shift_preserves_seen_bits() {
        // Mark counters spread across multiple bitmap words, then shift
        // by a small amount and verify they're still marked.
        let mut w = ReplayWindow::new();
        let seen = [0u64, 50, 100, 200, 500, 1000, 1500];
        // First set the high-water mark so all fit in the window.
        assert!(w.check_and_update(1500));
        for &c in &seen[..seen.len() - 1] {
            assert!(w.check_and_update(c), "counter {c} should be accepted");
        }
        // Advance by 10 — everything with age < WINDOW_SIZE should survive.
        assert!(w.check_and_update(1510));
        for &c in &seen {
            let age = 1510 - c;
            if age < WINDOW_SIZE {
                assert!(
                    !w.check_and_update(c),
                    "counter {c} (age {age}) was seen and still in window, must be rejected"
                );
            }
        }
    }

    #[test]
    fn shift_by_one() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_update(0));
        assert!(w.check_and_update(1));
        // Counter 0 is age=1, well within window, must still be rejected.
        assert!(
            !w.check_and_update(0),
            "counter 0 must be rejected after shift-by-one"
        );
    }

    #[test]
    fn shift_across_word_boundary() {
        // Bitmap words are 64 bits wide. Mark counters near the boundary
        // between word 0 and word 1, then shift so bits must carry across.
        let mut w = ReplayWindow::new();
        // Start at counter 100 so we have room.
        assert!(w.check_and_update(100));
        // Mark counters at ages 63, 64, 65 from current top (counters 37, 36, 35).
        assert!(w.check_and_update(37));
        assert!(w.check_and_update(36));
        assert!(w.check_and_update(35));
        // Now advance by 3, shifting bits across the word boundary.
        assert!(w.check_and_update(103));
        // Counters 37, 36, 35 now have ages 66, 67, 68 — still in window.
        assert!(
            !w.check_and_update(37),
            "counter 37 must survive shift across word boundary"
        );
        assert!(
            !w.check_and_update(36),
            "counter 36 must survive shift across word boundary"
        );
        assert!(
            !w.check_and_update(35),
            "counter 35 must survive shift across word boundary"
        );
    }

    #[test]
    fn counter_zero() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_update(0), "counter 0 must be accepted on first use");
        assert!(
            !w.check_and_update(0),
            "counter 0 must be rejected on replay"
        );
    }

    #[test]
    fn shift_by_exact_window_size() {
        let mut w = ReplayWindow::new();
        // Seed a bunch of counters.
        for i in 0..100 {
            assert!(w.check_and_update(i));
        }
        // Advance by exactly WINDOW_SIZE — every previous counter is now too old.
        let new_top = 99 + WINDOW_SIZE;
        assert!(w.check_and_update(new_top));
        for i in 0..100 {
            assert!(
                !w.check_and_update(i),
                "counter {i} must be too old after shifting by exact window size"
            );
        }
    }

    #[test]
    fn near_u64_max() {
        // Verify no overflow panics near u64::MAX.
        let mut w = ReplayWindow::new();
        let base = u64::MAX - WINDOW_SIZE - 10;
        assert!(w.check_and_update(base));
        assert!(w.check_and_update(base + 1));
        assert!(w.check_and_update(base + WINDOW_SIZE));
        // base is now at age = WINDOW_SIZE, so it's just outside the window.
        assert!(
            !w.check_and_update(base),
            "counter at exact window edge must be rejected"
        );
        // base + 1 is at age = WINDOW_SIZE - 1, still in window but seen.
        assert!(
            !w.check_and_update(base + 1),
            "counter near u64::MAX must still be tracked correctly"
        );
        // A counter past the current top near u64::MAX should still work.
        assert!(w.check_and_update(u64::MAX - 1));
        assert!(w.check_and_update(u64::MAX));
        assert!(!w.check_and_update(u64::MAX), "u64::MAX duplicate must be rejected");
    }
}
