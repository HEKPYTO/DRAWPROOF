use crate::util;

pub fn leaf_hash(data: &[u8]) -> [u8; 32] {
    util::sha256(&[&[0u8][..], data])
}

pub fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    util::sha256(&[&[1u8][..], left, right])
}

pub fn root(leaves: &[[u8; 32]]) -> [u8; 32] {
    match leaves.len() {
        0 => util::sha256(&[]),
        1 => leaves[0],
        len => {
            let split = split_point(len);
            node_hash(&root(&leaves[..split]), &root(&leaves[split..]))
        }
    }
}

pub fn proof(leaves: &[[u8; 32]], index: usize) -> Vec<[u8; 32]> {
    let mut out = Vec::new();
    collect_proof(leaves, index, &mut out);
    out
}

pub fn verify_inclusion(
    leaf: [u8; 32],
    index: u64,
    tree_size: u64,
    proof: &[[u8; 32]],
    root: [u8; 32],
) -> bool {
    if tree_size == 0 || index >= tree_size {
        return false;
    }
    let mut computed = leaf;
    let mut fn_ = index;
    let mut sn = tree_size - 1;
    for sibling in proof {
        if fn_ & 1 == 1 || fn_ == sn {
            computed = node_hash(sibling, &computed);
            while fn_ & 1 == 0 && fn_ != 0 {
                fn_ >>= 1;
                sn >>= 1;
            }
        } else {
            computed = node_hash(&computed, sibling);
        }
        fn_ >>= 1;
        sn >>= 1;
    }
    sn == 0 && computed == root
}

fn split_point(len: usize) -> usize {
    let mut split = 1;
    while split * 2 < len {
        split *= 2;
    }
    split
}

fn collect_proof(leaves: &[[u8; 32]], index: usize, out: &mut Vec<[u8; 32]>) {
    if leaves.len() <= 1 {
        return;
    }
    let split = split_point(leaves.len());
    if index < split {
        collect_proof(&leaves[..split], index, out);
        out.push(root(&leaves[split..]));
    } else {
        collect_proof(&leaves[split..], index - split, out);
        out.push(root(&leaves[..split]));
    }
}
