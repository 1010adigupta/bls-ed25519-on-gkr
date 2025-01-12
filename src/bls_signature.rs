use circuit_std_rs::gnark::emulated::field_bls12381::e2::GE2;
use super::bls12_381::g1::{G1Affine, G1};
use super::bls12_381::g2::{G2, G2AffP, G2Affine, LineEvaluations};
use super::bls12_381::pairing::Pairing;
use expander_compiler::frontend::*;

pub fn bls_verify_gkr_single<Builder: RootAPI<M31Config>>(
    builder: &mut Builder,
    pubkey: &[[[Variable; 48]; 2]; 2],
    signature: &[[Variable; 48]; 2],
    hash: &[[Variable; 48]; 2],
) {
    let mut pairing = Pairing::new(builder);
    // Convert inputs to internal format
    let pubkey = G2AffP {
        x: GE2::from_vars(pubkey[0][0].to_vec(), pubkey[0][1].to_vec()),
        y: GE2::from_vars(pubkey[1][0].to_vec(), pubkey[1][1].to_vec()),
    };

    let signature = G1Affine::from_vars(signature[0].to_vec(), signature[1].to_vec());

    let hash_msg = G1Affine::from_vars(hash[0].to_vec(), hash[1].to_vec());

    // Verify e(signature, g2) = e(H(m), pubkey)
    // We check this by verifying e(signature, g2) * e(-H(m), pubkey) = 1

    // Compute -H(m)
    let mut g1 = G1::new(builder);
    let neg_hash = g1.neg(builder, &hash_msg);

    // Put pubkey and g2 in G2 format for pairing
    let pubkey_g2 = G2Affine {
        p: pubkey,
        lines: LineEvaluations::default(),
    };

    let mut g2 = G2::new(builder);
    let g2_gen = g2.generator(builder);
    let g2_gen_affine = G2Affine {
        p: g2_gen,
        lines: LineEvaluations::default(),
    };

    // Compute pairings e(signature, g2) * e(-H(m), pubkey)
    let pairs_g1 = vec![signature, neg_hash];
    let mut pairs_g2 = vec![g2_gen_affine, pubkey_g2];

    // Check if product equals 1
    pairing
        .pairing_check(builder, &pairs_g1, &mut pairs_g2)
        .unwrap();
}

// // Function to verify individual BLS signature
// fn verify_single_signature<Builder: RootAPI<M31Config>>(
//     builder: &mut Builder,
//     pubkey: &[[[Variable; 48]; 2]; 2],
//     signature: &[[Variable; 48]; 2],
//     hash: &[[Variable; 48]; 2],
// ) -> bool {
//     let mut fp = Field::new(builder, bls12381_fp{});

//     // 1. Check all inputs are valid field elements
//     for i in 0..2 {
//         for j in 0..2 {
//             let elem = Element::new(pubkey[i][j].to_vec(), 0, false, false, false, Variable::default());
//             fp.check_zero(builder, elem.clone(), None);
//         }
//     }

//     for i in 0..2 {
//         let elem = Element::new(signature[i].to_vec(), 0, false, false, false, Variable::default());
//         fp.check_zero(builder, elem.clone(), None);
//     }

//     for i in 0..2 {
//         let elem = Element::new(hash[i].to_vec(), 0, false, false, false, Variable::default());
//         fp.check_zero(builder, elem.clone(), None);
//     }

//     // 2. Subgroup checks
//     let pubkey = G2AffP {
//         x: GE2::from_vars(pubkey[0][0].to_vec(), pubkey[0][1].to_vec()),
//         y: GE2::from_vars(pubkey[1][0].to_vec(), pubkey[1][1].to_vec()),
//     };
//     let mut g2 = G2::new(builder);

//     let pubkey_order_check = g2.mul_by_order(builder, &pubkey);
//     g2.assert_is_infinity(builder, &pubkey_order_check);

//     let signature = G1Affine::from_vars(
//         signature[0].to_vec(),
//         signature[1].to_vec()
//     );
//     let mut g1 = G1::new(builder);

//     let sig_order_check = g1.mul_by_order(builder, &signature);
//     g1.assert_is_infinity(builder, &sig_order_check);

//     // 3. Map hash to G1
//     let hash_point = g1.hash_to_curve(builder, &[
//         Element::new(hash[0].to_vec(), 0, false, false, false, Variable::default()),
//         Element::new(hash[1].to_vec(), 0, false, false, false, Variable::default())
//     ]);
//     g1.assert_not_infinity(builder, &hash_point);

//     // 4. Pairing check
//     let mut pairing = Pairing::new(builder);
//     let pubkey_g2 = G2Affine {
//         p: pubkey,
//         lines: LineEvaluations::default()
//     };
//     let g2_gen = g2.g2_generator(builder);
//     let neg_hash = g1.neg(builder, &hash_point);

//     let mut pairs_g1 = vec![signature, neg_hash];
//     let mut pairs_g2 = vec![g2_gen, pubkey_g2];

//     pairing.pairing_check(builder, &pairs_g1, &mut pairs_g2).unwrap();
//     true
// }

// Function to accumulate public keys
// fn accumulate_public_keys<Builder: RootAPI<M31Config>>(
//     builder: &mut Builder,
//     num_keys: Variable,
//     pubkeys: &[[[[[Variable; 48]; 2]; 2]]],
//     pubkey_bits: &[Variable],
// ) -> G2AffP {
//     let mut g2 = G2::new(builder);

//     let mut has_prev = builder.constant(0);
//     for i in 0..num_keys.to_usize() {
//         has_prev = builder.or(has_prev, pubkey_bits[i]);
//     }

//     let mut partial = G2AffP {
//         x: GE2::from_vars(pubkeys[0][0][0].to_vec(), pubkeys[0][0][1].to_vec()),
//         y: GE2::from_vars(pubkeys[0][1][0].to_vec(), pubkeys[0][1].to_vec()),
//     };

//     for i in 1..num_keys.to_usize() {
//         let curr_key = G2AffP {
//             x: GE2::from_vars(pubkeys[i][0][0].to_vec(), pubkeys[i][0][1].to_vec()),
//             y: GE2::from_vars(pubkeys[i][1][0].to_vec(), pubkeys[i][1][1].to_vec()),
//         };

//         let sum = g2.add(builder, &partial, &curr_key);
//         let selector = pubkey_bits[i];
//         let result = g2.select(builder, selector, sum, partial);
//         let has_prev_selector = builder.and(has_prev, selector);
//         partial = g2.select(builder, has_prev_selector, result, curr_key);
//     }

//     partial
// }

// // Main aggregate verification circuit
// declare_circuit!(BLSAggregateVerifyCircuit {
//     num_signatures: Variable,              // Number of signatures to verify
//     pubkeys: [[[[[Variable; 48]; 2]; 2]]], // Array of public keys in G2
//     signatures: [[[[Variable; 48]; 2]]],   // Array of signatures in G1
//     messages: [[[[Variable; 48]; 2]]],     // Array of message hashes
//     pubkey_bits: [Variable],               // Bitmask for which keys to include
//     valid: Variable,                       // Output: 1 if valid, 0 if invalid
// });

// impl GenericDefine<M31Config> for BLSAggregateVerifyCircuit<Variable> {
//     fn define<Builder: RootAPI<M31Config>>(&self, builder: &mut Builder) {
//         // First accumulate the public keys based on the bitmask
//         let accumulated_pubkey = accumulate_public_keys(
//             builder,
//             self.num_signatures,
//             &self.pubkeys,
//             &self.pubkey_bits,
//         );

//         // Convert accumulated pubkey to array format for verification
//         let acc_pubkey_arr = [
//             [
//                 accumulated_pubkey.x.a0.to_array(),
//                 accumulated_pubkey.x.a1.to_array(),
//             ],
//             [
//                 accumulated_pubkey.y.a0.to_array(),
//                 accumulated_pubkey.y.a1.to_array(),
//             ],
//         ];

//         // Accumulate signatures
//         let mut g1 = G1::new(builder);
//         let mut accumulated_sig = G1Affine::from_vars(
//             self.signatures[0][0].to_vec(),
//             self.signatures[0][1].to_vec(),
//         );

//         // Add subsequent signatures based on bitmask
//         for i in 1..self.num_signatures.to_usize() {
//             if self.pubkey_bits[i].to_bool() {
//                 let curr_sig = G1Affine::from_vars(
//                     self.signatures[i][0].to_vec(),
//                     self.signatures[i][1].to_vec(),
//                 );
//                 accumulated_sig = g1.add(builder, &accumulated_sig, &curr_sig);
//             }
//         }

//         // Accumulate message hashes
//         let mut accumulated_hash = [[Variable::default(); 48]; 2];
//         for i in 0..2 {
//             for j in 0..48 {
//                 accumulated_hash[i][j] = self.messages[0][i][j];
//             }
//         }

//         for i in 1..self.num_signatures.to_usize() {
//             if self.pubkey_bits[i].to_bool() {
//                 for j in 0..2 {
//                     for k in 0..48 {
//                         accumulated_hash[j][k] =
//                             builder.add(accumulated_hash[j][k], self.messages[i][j][k]);
//                     }
//                 }
//             }
//         }

//         // Verify the aggregate signature
//         let sig_arr = [accumulated_sig.x.to_array(), accumulated_sig.y.to_array()];

//         let is_valid =
//             verify_single_signature(builder, &acc_pubkey_arr, &sig_arr, &accumulated_hash);

//         // Set validity
//         builder.assert_eq(self.valid, builder.constant(if is_valid { 1 } else { 0 }));
//     }
// }

// #[test]
// fn test_bls_aggregate_verify() {
//     let mut hint_registry = HintRegistry::<M31Config>::new();

//     let circuit = BLSAggregateVerifyCircuit::<Variable>::default();
//     let assignment = BLSAggregateVerifyCircuit {
//         num_signatures: Variable::from(2),
//         pubkeys: vec![vec![[[Variable::from(0); 48]; 2]; 2]],
//         signatures: vec![[[Variable::from(0); 48]; 2]],
//         messages: vec![[[Variable::from(0); 48]; 2]],
//         pubkey_bits: vec![Variable::from(1), Variable::from(1)],
//         valid: Variable::from(1),
//     };

//     debug_eval(&circuit, &assignment, hint_registry);
// }
