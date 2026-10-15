//! RFC 9162 §2.1: Merkle tree hashes, inclusion proofs and consistency proofs.

use alloc::vec::Vec;
use sha2::{Digest as _, Sha256};

pub type Hash = [u8; 32];

pub fn leaf_hash(leaf: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(leaf);
    h.finalize().into()
}

pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

pub fn empty_root() -> Hash {
    Sha256::digest([]).into()
}

const MAX: u64 = 9_007_199_254_740_991;

/// RFC 9162 §2.1.3.2.
pub fn verify_inclusion(index: u64, size: u64, leaf: &Hash, proof: &[Hash], root: &Hash) -> bool {
    if size > MAX || index >= size {
        return false;
    }
    let mut fn_ = index;
    let mut sn = size.saturating_sub(1);
    let mut r = *leaf;
    for p in proof {
        if sn == 0 {
            return false;
        }
        if !fn_.is_multiple_of(2) || fn_ == sn {
            r = node_hash(p, &r);
            if fn_.is_multiple_of(2) {
                while fn_.is_multiple_of(2) && fn_ != 0 {
                    fn_ /= 2;
                    sn /= 2;
                }
            }
        } else {
            r = node_hash(&r, p);
        }
        fn_ /= 2;
        sn /= 2;
    }
    sn == 0 && r == *root
}

/// RFC 9162 §2.1.4.2.
pub fn verify_consistency(
    first: u64,
    second: u64,
    first_root: &Hash,
    second_root: &Hash,
    proof: &[Hash],
) -> bool {
    if second > MAX || first > second {
        return false;
    }
    if first == second {
        return proof.is_empty() && first_root == second_root;
    }
    if first == 0 {
        return proof.is_empty();
    }
    if proof.is_empty() {
        return false;
    }
    let mut path: Vec<Hash> = Vec::with_capacity(proof.len().saturating_add(1));
    if first.is_power_of_two() {
        path.push(*first_root);
    }
    path.extend_from_slice(proof);
    let mut fn_ = first.saturating_sub(1);
    let mut sn = second.saturating_sub(1);
    while !fn_.is_multiple_of(2) {
        fn_ /= 2;
        sn /= 2;
    }
    let Some((head, rest)) = path.split_first() else {
        return false;
    };
    let mut fr = *head;
    let mut sr = *head;
    for c in rest {
        if sn == 0 {
            return false;
        }
        if !fn_.is_multiple_of(2) || fn_ == sn {
            fr = node_hash(c, &fr);
            sr = node_hash(c, &sr);
            if fn_.is_multiple_of(2) {
                while fn_.is_multiple_of(2) && fn_ != 0 {
                    fn_ /= 2;
                    sn /= 2;
                }
            }
        } else {
            sr = node_hash(&sr, c);
        }
        fn_ /= 2;
        sn /= 2;
    }
    sn == 0 && fr == *first_root && sr == *second_root
}

/// MTH over leaf hashes (RFC 9162 §2.1.1). For tests and small trees.
pub fn root_of(leaves: &[Hash]) -> Hash {
    match leaves {
        [] => empty_root(),
        [one] => *one,
        _ => {
            let n = leaves.len();
            let mut k = 1usize;
            while k.saturating_mul(2) < n {
                k = k.saturating_mul(2);
            }
            let (left, right) = leaves.split_at(k);
            node_hash(&root_of(left), &root_of(right))
        }
    }
}
