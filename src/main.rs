mod bls12_381;
mod bls_signature;
use crate::bls12_381::{g1::*, g2::*, pairing::Pairing};
use circuit_std_rs::{
    gnark::{element::Element, emulated::field_bls12381::e2::GE2},
    utils::register_hint,
};
use expander_compiler::{
    circuit::layered::Circuit,
    compile::CompileOptions,
    frontend::{extra::debug_eval, GenericDefine, HintRegistry, M31Config, RootAPI, Variable, M31},
};
use expander_compiler::{circuit::layered::NormalInputType, declare_circuit, frontend::*};
use extra::Serde;
use num_bigint::BigInt;
use num_traits::Num;
use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::sync::Arc;
use std::thread;
use std::time::Instant;

declare_circuit!(BLSSignatureGKRCircuit {
    g1_gen: [[Variable; 48]; 2],
    pub_keys: [[[Variable; 48]; 2]; 512],
    sigs: [[[[Variable; 48]; 2]; 2]; 512],
    msg: [Variable; 32],
});

impl GenericDefine<M31Config> for BLSSignatureGKRCircuit<Variable> {
    fn define<Builder: RootAPI<M31Config>>(&self, builder: &mut Builder) {
        let mut pairing = Pairing::new(builder);
        let g1 = G1Affine {
            x: Element::new(
                self.g1_gen[0].to_vec(),
                0,
                false,
                false,
                false,
                Variable::default(),
            ),
            y: Element::new(
                self.g1_gen[1].to_vec(),
                0,
                false,
                false,
                false,
                Variable::default(),
            ),
        };

        let mut g1_impl = G1::new(builder);
        let g1_neg = g1_impl.neg(builder, &g1);

        let mut agg_pk = G1Affine {
            x: Element::new(
                self.pub_keys[0][0].to_vec(),
                0,
                false,
                false,
                false,
                Variable::default(),
            ),
            y: Element::new(
                self.pub_keys[0][1].to_vec(),
                0,
                false,
                false,
                false,
                Variable::default(),
            ),
        };

        for i in 1..512 {
            let pk = G1Affine {
                x: Element::new(
                    self.pub_keys[i][0].to_vec(),
                    0,
                    false,
                    false,
                    false,
                    Variable::default(),
                ),
                y: Element::new(
                    self.pub_keys[i][1].to_vec(),
                    0,
                    false,
                    false,
                    false,
                    Variable::default(),
                ),
            };

            // Since all public keys are the same in this test, we need to double
            agg_pk = g1_impl.double(builder, &agg_pk);
        }

        let mut agg_sig = G2AffP {
            x: GE2 {
                a0: Element::new(
                    self.sigs[0][0][0].to_vec(),
                    0,
                    false,
                    false,
                    false,
                    Variable::default(),
                ),
                a1: Element::new(
                    self.sigs[0][0][1].to_vec(),
                    0,
                    false,
                    false,
                    false,
                    Variable::default(),
                ),
            },
            y: GE2 {
                a0: Element::new(
                    self.sigs[0][1][0].to_vec(),
                    0,
                    false,
                    false,
                    false,
                    Variable::default(),
                ),
                a1: Element::new(
                    self.sigs[0][1][1].to_vec(),
                    0,
                    false,
                    false,
                    false,
                    Variable::default(),
                ),
            },
        };

        let mut g2 = G2::new(builder);

        for i in 1..512 {
            let sig = G2AffP {
                x: GE2 {
                    a0: Element::new(
                        self.sigs[i][0][0].to_vec(),
                        0,
                        false,
                        false,
                        false,
                        Variable::default(),
                    ),
                    a1: Element::new(
                        self.sigs[i][0][1].to_vec(),
                        0,
                        false,
                        false,
                        false,
                        Variable::default(),
                    ),
                },
                y: GE2 {
                    a0: Element::new(
                        self.sigs[i][1][0].to_vec(),
                        0,
                        false,
                        false,
                        false,
                        Variable::default(),
                    ),
                    a1: Element::new(
                        self.sigs[i][1][1].to_vec(),
                        0,
                        false,
                        false,
                        false,
                        Variable::default(),
                    ),
                },
            };
            // Since all signatures are the same in this test, we need to double
            agg_sig = g2.g2_double(builder, &agg_sig);
        }

        let (hm0, hm1) = g2.hash_to_fp(builder, &self.msg);
        let msg_g2 = g2.map_to_g2(builder, &hm0, &hm1);

        pairing
            .pairing_check(
                builder,
                &[g1_neg, agg_pk],
                &mut [
                    G2Affine {
                        p: agg_sig,
                        lines: LineEvaluations::default(),
                    },
                    G2Affine {
                        p: msg_g2,
                        lines: LineEvaluations::default(),
                    },
                ],
            )
            .unwrap();

        pairing.ext12.ext6.ext2.curve_f.check_mul(builder);
        pairing.ext12.ext6.ext2.curve_f.table.final_check(builder);
        pairing.ext12.ext6.ext2.curve_f.table.final_check(builder);
        pairing.ext12.ext6.ext2.curve_f.table.final_check(builder);
    }
}

#[test]
fn test_aggregate_pairing_check_gkr() {
    println!("testing test_aggregate_pairing_check_gkr.....");
    let mut hint_registry = HintRegistry::<M31>::new();
    register_hint(&mut hint_registry);
    let mut assignment = BLSSignatureGKRCircuit::<M31> {
        g1_gen: [[M31::from(0); 48]; 2],
        pub_keys: [[[M31::from(0); 48]; 2]; 512],
        sigs: [[[[M31::from(0); 48]; 2]; 2]; 512],
        msg: [M31::from(0); 32],
    };

    // Generator point
    let g1_a0_bigint = BigInt::from_str_radix("3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507", 10).unwrap();
    let g1_a1_bigint = BigInt::from_str_radix("1339506544944476473020471379941921221584933875938349620426543736416511423956333506472724655353366534992391756441569", 10).unwrap();
    let g1_gen_x_bytes = g1_a0_bigint.to_bytes_le();
    let g1_gen_y_bytes = g1_a1_bigint.to_bytes_le();

    // Public key values (original)
    let pub_key_a0_bigint = BigInt::from_str_radix("703326716001809064498853055672224052496326539572945177471956754169145471346922036117906423749397590945884354901914", 10).unwrap();
    let pub_key_a1_bigint = BigInt::from_str_radix("3663539438728798306657207296627492219061036278584663040302088465810128029049191527519011271732625440307576496404164", 10).unwrap();
    let pub_key_x_bytes = pub_key_a0_bigint.to_bytes_le();
    let pub_key_y_bytes = pub_key_a1_bigint.to_bytes_le();

    // Signature values (original)
    let sig_b0_a0_bigint = BigInt::from_str_radix("1139568035424369576886504746727692711007568237996931740990083083283390253765157354611656848983901259161392255747051", 10).unwrap();
    let sig_b0_a1_bigint = BigInt::from_str_radix("1254875381135194965686121199970220725987247367099176854373369962826503465173652424031228084897653264386315457499586", 10).unwrap();
    let sig_b1_a0_bigint = BigInt::from_str_radix("3985022954582833583610752589867406089888552465191016224317399257491285114232241437209840121250502955373920952884061", 10).unwrap();
    let sig_b1_a1_bigint = BigInt::from_str_radix("249179071186755291707558993402509484460063614865425349660967954952959359540889904597635495866422932058900651130506", 10).unwrap();
    let sig_x0_bytes = sig_b0_a0_bigint.to_bytes_le();
    let sig_x1_bytes = sig_b0_a1_bigint.to_bytes_le();
    let sig_y0_bytes = sig_b1_a0_bigint.to_bytes_le();
    let sig_y1_bytes = sig_b1_a1_bigint.to_bytes_le();

    // Initialize generator point
    for i in 0..48 {
        assignment.g1_gen[0][i] = M31::from(g1_gen_x_bytes.1[i] as u32);
        assignment.g1_gen[1][i] = M31::from(g1_gen_y_bytes.1[i] as u32);
    }

    // Initialize all 512 public keys with the same values
    for idx in 0..512 {
        for i in 0..48 {
            assignment.pub_keys[idx][0][i] = M31::from(pub_key_x_bytes.1[i] as u32);
            assignment.pub_keys[idx][1][i] = M31::from(pub_key_y_bytes.1[i] as u32);
        }
    }

    // Initialize all 512 signatures with the same values
    for idx in 0..512 {
        for i in 0..48 {
            assignment.sigs[idx][0][0][i] = M31::from(sig_x0_bytes.1[i] as u32);
            assignment.sigs[idx][0][1][i] = M31::from(sig_x1_bytes.1[i] as u32);
            assignment.sigs[idx][1][0][i] = M31::from(sig_y0_bytes.1[i] as u32);
            assignment.sigs[idx][1][1][i] = M31::from(sig_y1_bytes.1[i] as u32);
        }
    }

    // Initialize message
    let msg_bigint = BigInt::from_str_radix(
        "5656565656565656565656565656565656565656565656565656565656565656",
        16,
    )
    .unwrap();
    let msg_bytes = msg_bigint.to_bytes_be();

    for i in 0..32 {
        assignment.msg[i] = M31::from(msg_bytes.1[i] as u32);
    }

    debug_eval(
        &BLSSignatureGKRCircuit::default(),
        &assignment,
        hint_registry,
    );
}

fn compile_and_save_circuit() {
    println!("Beginning compilation....");
    let compile_result = compile_generic(
        &BLSSignatureGKRCircuit::default(),
        CompileOptions::default(),
    )
    .unwrap();

    // Save compile result components
    let file = File::create("circuit.txt").unwrap();
    let writer = BufWriter::new(file);
    compile_result
        .layered_circuit
        .serialize_into(writer)
        .unwrap();

    let file = File::create("witness_solver.txt").unwrap();
    let writer = BufWriter::new(file);
    compile_result
        .witness_solver
        .serialize_into(writer)
        .unwrap();
}

fn main() {
    println!("Beginning compilation....");
    let compile_result = compile_generic(
        &BLSSignatureGKRCircuit::default(),
        CompileOptions::default(),
    )
    .unwrap();
    println!("Compilation finished....");

    println!("Beginning assignment....");
    let start_time = std::time::Instant::now();
    let mut hint_registry = HintRegistry::<M31>::new();
    register_hint(&mut hint_registry);
    let mut assignment = BLSSignatureGKRCircuit::<M31> {
        g1_gen: [[M31::from(0); 48]; 2],
        pub_keys: [[[M31::from(0); 48]; 2]; 512],
        sigs: [[[[M31::from(0); 48]; 2]; 2]; 512],
        msg: [M31::from(0); 32],
    };

    // Generator point
    let g1_a0_bigint = BigInt::from_str_radix("3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507", 10).unwrap();
    let g1_a1_bigint = BigInt::from_str_radix("1339506544944476473020471379941921221584933875938349620426543736416511423956333506472724655353366534992391756441569", 10).unwrap();
    let g1_gen_x_bytes = g1_a0_bigint.to_bytes_le();
    let g1_gen_y_bytes = g1_a1_bigint.to_bytes_le();

    // Public key values (original)
    let pub_key_a0_bigint = BigInt::from_str_radix("703326716001809064498853055672224052496326539572945177471956754169145471346922036117906423749397590945884354901914", 10).unwrap();
    let pub_key_a1_bigint = BigInt::from_str_radix("3663539438728798306657207296627492219061036278584663040302088465810128029049191527519011271732625440307576496404164", 10).unwrap();
    let pub_key_x_bytes = pub_key_a0_bigint.to_bytes_le();
    let pub_key_y_bytes = pub_key_a1_bigint.to_bytes_le();

    // Signature values (original)
    let sig_b0_a0_bigint = BigInt::from_str_radix("1139568035424369576886504746727692711007568237996931740990083083283390253765157354611656848983901259161392255747051", 10).unwrap();
    let sig_b0_a1_bigint = BigInt::from_str_radix("1254875381135194965686121199970220725987247367099176854373369962826503465173652424031228084897653264386315457499586", 10).unwrap();
    let sig_b1_a0_bigint = BigInt::from_str_radix("3985022954582833583610752589867406089888552465191016224317399257491285114232241437209840121250502955373920952884061", 10).unwrap();
    let sig_b1_a1_bigint = BigInt::from_str_radix("249179071186755291707558993402509484460063614865425349660967954952959359540889904597635495866422932058900651130506", 10).unwrap();
    let sig_x0_bytes = sig_b0_a0_bigint.to_bytes_le();
    let sig_x1_bytes = sig_b0_a1_bigint.to_bytes_le();
    let sig_y0_bytes = sig_b1_a0_bigint.to_bytes_le();
    let sig_y1_bytes = sig_b1_a1_bigint.to_bytes_le();

    // Initialize generator point
    for i in 0..48 {
        assignment.g1_gen[0][i] = M31::from(g1_gen_x_bytes.1[i] as u32);
        assignment.g1_gen[1][i] = M31::from(g1_gen_y_bytes.1[i] as u32);
    }

    // Initialize all 512 public keys with the same values
    for idx in 0..512 {
        for i in 0..48 {
            assignment.pub_keys[idx][0][i] = M31::from(pub_key_x_bytes.1[i] as u32);
            assignment.pub_keys[idx][1][i] = M31::from(pub_key_y_bytes.1[i] as u32);
        }
    }

    // Initialize all 512 signatures with the same values
    for idx in 0..512 {
        for i in 0..48 {
            assignment.sigs[idx][0][0][i] = M31::from(sig_x0_bytes.1[i] as u32);
            assignment.sigs[idx][0][1][i] = M31::from(sig_x1_bytes.1[i] as u32);
            assignment.sigs[idx][1][0][i] = M31::from(sig_y0_bytes.1[i] as u32);
            assignment.sigs[idx][1][1][i] = M31::from(sig_y1_bytes.1[i] as u32);
        }
    }

    // Initialize message
    let msg_bigint = BigInt::from_str_radix(
        "5656565656565656565656565656565656565656565656565656565656565656",
        16,
    )
    .unwrap();
    let msg_bytes = msg_bigint.to_bytes_be();

    for i in 0..32 {
        assignment.msg[i] = M31::from(msg_bytes.1[i] as u32);
    }
    let end_time = std::time::Instant::now();
    println!(
        "assigned assignments time: {:?}",
        end_time.duration_since(start_time)
    );
    println!("Assignment finished....");
    let assignments = vec![assignment.clone(); 64];

    println!("Beginning witness generation....");
    let assignment_chunks: Vec<Vec<BLSSignatureGKRCircuit<M31>>> =
        assignments.chunks(16).map(|x| x.to_vec()).collect();
    let witness_solver = Arc::new(compile_result.witness_solver);
    let handles = assignment_chunks
        .into_iter()
        .enumerate()
        .map(|(i, assignments)| {
            let witness_solver = Arc::clone(&witness_solver);
            thread::spawn(move || {
                let mut hint_registry1 = HintRegistry::<M31>::new();
                register_hint(&mut hint_registry1);
                let witness = witness_solver
                    .solve_witnesses_with_hints(&assignments, &mut hint_registry1)
                    .unwrap();
                let file = File::create(format!("witness_{}.txt", i)).unwrap();
                let writer = BufWriter::new(file);
                witness.serialize_into(writer).unwrap();
            })
        })
        .collect::<Vec<_>>();
    for handle in handles {
        handle.join().unwrap();
    }
    let end_time = std::time::Instant::now();
    println!(
        "Generate pairing witness Time: {:?}",
        end_time.duration_since(start_time)
    );
    println!("Witness generation finished....");

    let file = File::create("witness_time.txt").unwrap();
    let mut writer = BufWriter::new(file);

    let file = File::create("circuit.txt").unwrap();
    let writer = BufWriter::new(file);
    compile_result
        .layered_circuit
        .serialize_into(writer)
        .unwrap();

    // let file = File::create("witness.txt").unwrap();
    // let writer = BufWriter::new(file);
    // witnesses.serialize_into(writer).unwrap();

    // let file = File::create("witness_solver.txt").unwrap();
    // let writer = BufWriter::new(file);
    // compile_result.witness_solver.serialize_into(writer).unwrap();
}
