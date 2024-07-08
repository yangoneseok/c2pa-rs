// Copyright 2023 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

// Unless required by applicable law or agreed to in writing,
// this software is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR REPRESENTATIONS OF ANY KIND, either express or
// implied. See the LICENSE-MIT and LICENSE-APACHE files for the
// specific language governing permissions and limitations under
// each license.

// use std::io::Read;

// use std::io::Read;

use extfmt::Hexlify;

use super::hash_utils::{concat_and_hash, hash_by_alg};
// use crate::assertions::VecByteBuf;
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
#[derive(Default, Clone, PartialEq, Debug, Deserialize, Serialize)]
// pub struct MerkleNode(pub Vec<u8>);

// Implements Merkle tree support corresponding to the C2PA spec variant.  The Merkle tree is not reduced and
// all leaves live at the bottom most level.  If the last layer node is an odd index (lacking a matching pair),
// its node value is propagated to parent layer, no cloning or hashing is expected.  Null tree entries do not contribute to the hashes.
pub struct C2PAMerkleTree {
    pub leaves: Vec<ByteBuf>,
    pub layers: Vec<Vec<ByteBuf>>,
}

#[allow(dead_code)]
impl C2PAMerkleTree {
    pub fn from_leaves(leaves: Vec<ByteBuf>, alg: &str, hash_leaves: bool) -> C2PAMerkleTree {
        let leaves = if hash_leaves {
            leaves
                .into_iter()
                .map(|leaf| {
                    let hash = hash_by_alg(alg, &leaf.as_ref(), None);
                    ByteBuf::from(hash)
                })
                .collect()
        } else {
            leaves // this handles the case when the leaves are already hashed
        };

        let layers = C2PAMerkleTree::generate_tree(alg, &leaves);

        C2PAMerkleTree { leaves, layers }
    }

    // generate layer layout
    pub fn to_layout(num_leaves: usize) -> Vec<usize> {
        let mut layers = Vec::new();

        layers.push(num_leaves);
        let mut current_layer = layers[0];

        while current_layer > 1 {
            let parent_layer_index = layers.len();
            let mut parent_layer_cnt: usize = 0;

            for i in (0..current_layer).step_by(2) {
                if i + 1 == current_layer {
                    parent_layer_cnt += 1;
                    continue;
                }

                parent_layer_cnt += 1;
            }
            layers.push(parent_layer_cnt);
            current_layer = layers[parent_layer_index];
        }

        layers
    }

    pub fn get_root(&self) -> Option<&ByteBuf> {
        Some(self.layers.last()?.first()?)
    }

    fn generate_tree(alg: &str, leaves: &[ByteBuf]) -> Vec<Vec<ByteBuf>> {
        let mut layers = Vec::new();
        layers.push(leaves.to_vec()); // set layer 0
        let mut current_layer = &layers[0];

        while current_layer.len() > 1 {
            let parent_layer_index = layers.len();
            let mut parent_layer = Vec::new();

            for i in (0..current_layer.len()).step_by(2) {
                if i + 1 == current_layer.len() {
                    // just pass the current hash since last node is unbalanced
                    parent_layer.push(ByteBuf::from(current_layer[i].to_vec()));
                    continue;
                }
                let left = &current_layer[i];
                let right = if i + 1 == current_layer.len() {
                    left
                } else {
                    &current_layer[i + 1]
                };

                parent_layer.push(ByteBuf::from(concat_and_hash(
                    alg,
                    &left.to_vec(),
                    Some(&right.to_vec()),
                )));
            }
            layers.push(parent_layer);
            current_layer = &layers[parent_layer_index];
        }
        layers
    }

    pub fn get_proof_by_index(&self, leaf_indx: usize) -> Result<Vec<ByteBuf>> {
        if self.leaves.is_empty() || leaf_indx >= self.leaves.len() {
            return Err(Error::BadParam(
                "Merkle proof index out of range".to_string(),
            ));
        }

        let mut proof: Vec<ByteBuf> = Vec::new();
        let mut index = leaf_indx;

        for i in 0..self.layers.len() {
            let layer = &self.layers[i];
            let is_right = index % 2 == 1;

            if is_right {
                if index - 1 < layer.len() {
                    proof.push(ByteBuf::from(layer[index - 1].to_vec()));
                }
            } else if index + 1 < layer.len() {
                proof.push(ByteBuf::from(layer[index + 1].to_vec()));
            }
            index /= 2;
        }
        Ok(proof)
    }

    pub fn num_layers_required(n: u32) -> i32 {
        let f = 1.0 * n as f32;

        f.log2().ceil() as i32
    }

    pub fn tree_dump(&self) {
        for (i, layer) in self.layers.iter().enumerate() {
            println!("Level: {i}");
            for (j, mn) in layer.iter().enumerate() {
                println!("{} (Node: {j})", Hexlify(&mn.to_vec()));
            }
        }
    }
}

#[cfg(test)]
mod test_c2pa_merkle_tree {
    use super::*;

    #[test]
    fn test_from_leaves() {
        let leaves = vec![
            ByteBuf::from(vec![1, 2, 3]),
            ByteBuf::from(vec![4, 5, 6]),
            ByteBuf::from(vec![7, 8, 9]),
            ByteBuf::from(vec![10, 11, 12]),
        ];

        let tree = C2PAMerkleTree::from_leaves(leaves, "sha256", true);
        println!("{:?}", tree.layers);
        println!("{:?}", tree.leaves);
        assert_eq!(tree.leaves.len(), 4);
        assert_eq!(tree.layers.len(), 3);
    }

    #[test]
    fn test_to_layout() {
        let layout = C2PAMerkleTree::to_layout(4);
        assert_eq!(layout, vec![4, 2, 1]);
    }

    // #[test]
    // fn test_get_root() {
    //     let leaves = vec![MerkleNode(vec![1, 2, 3]), MerkleNode(vec![4, 5, 6])];

    //     let tree = C2PAMerkleTree::from_leaves(leaves, "sha256", true);
    //     let root = tree.get_root();

    //     assert!(root.is_some());
    //     assert_eq!(root.unwrap(), &vec![1, 2, 3, 4, 5, 6]);
    // }

    #[test]
    fn test_get_proof_by_index() {
        let leaves = vec![
            ByteBuf::from(vec![1, 2, 3]),
            ByteBuf::from(vec![4, 5, 6]),
            ByteBuf::from(vec![7, 8, 9]),
            ByteBuf::from(vec![10, 11, 12]),
        ];

        let tree = C2PAMerkleTree::from_leaves(leaves, "sha256", true);
        let proof = tree.get_proof_by_index(1);

        assert!(proof.is_ok());
        let proof = proof.unwrap();
        assert_eq!(proof.len(), 2);
    }

    #[test]
    fn test_num_layers_required() {
        assert_eq!(C2PAMerkleTree::num_layers_required(1), 0);
        assert_eq!(C2PAMerkleTree::num_layers_required(2), 1);
        assert_eq!(C2PAMerkleTree::num_layers_required(4), 2);
        assert_eq!(C2PAMerkleTree::num_layers_required(8), 3);
    }

    #[test]
    fn test_tree_dump() {
        let leaves = vec![ByteBuf::from(vec![1, 2, 3]), ByteBuf::from(vec![4, 5, 6])];

        let tree = C2PAMerkleTree::from_leaves(leaves, "sha256", true);
        tree.tree_dump(); // This just prints the tree layout; no assertions needed
    }
    #[test]
    fn test_adobe_fragment() {
        let test_segment = [
            ByteBuf::from(
                [
                    219, 80, 132, 41, 133, 15, 223, 155, 56, 231, 18, 146, 20, 104, 18, 201, 163,
                    35, 123, 225, 21, 142, 210, 90, 164, 239, 60, 192, 250, 193, 102, 251,
                ]
                .to_vec(),
            ),
            ByteBuf::from(
                [
                    37, 170, 235, 160, 132, 82, 20, 64, 2, 135, 107, 69, 221, 196, 192, 147, 63,
                    13, 63, 70, 177, 89, 71, 188, 3, 131, 18, 88, 168, 195, 54, 115,
                ]
                .to_vec(),
            ),
            ByteBuf::from(
                [
                    114, 175, 64, 129, 126, 204, 93, 207, 142, 120, 254, 132, 7, 51, 11, 161, 177,
                    113, 219, 206, 191, 30, 165, 248, 187, 108, 137, 118, 199, 132, 59, 224,
                ]
                .to_vec(),
            ),
            ByteBuf::from(
                [
                    8, 66, 138, 244, 228, 175, 149, 74, 250, 182, 243, 17, 50, 139, 180, 188, 141,
                    13, 173, 180, 106, 134, 19, 237, 15, 252, 188, 162, 173, 61, 87, 117,
                ]
                .to_vec(),
            ),
            ByteBuf::from(
                [
                    151, 43, 206, 153, 48, 32, 74, 218, 81, 16, 233, 94, 246, 209, 76, 133, 180,
                    168, 13, 153, 105, 147, 227, 210, 38, 244, 197, 34, 164, 224, 138, 131,
                ]
                .to_vec(),
            ),
            ByteBuf::from(
                [
                    200, 172, 113, 192, 215, 244, 43, 58, 69, 198, 218, 155, 93, 17, 67, 195, 65,
                    43, 112, 7, 20, 81, 201, 28, 167, 94, 174, 5, 25, 10, 143, 222,
                ]
                .to_vec(),
            ),
        ];
        let test_merkle_tree = C2PAMerkleTree::from_leaves(test_segment.to_vec(), "sha256", false);
        println!("\n\nMerkle layers : {:?}\n\n", test_merkle_tree.layers);
        println!(
            "\n\nMerkle layers : {:?}\n\n",
            test_merkle_tree.get_proof_by_index(0)
        );
        println!("\n\nMerkle layers : {:?}\n\n", test_merkle_tree.get_root());
    }
}
