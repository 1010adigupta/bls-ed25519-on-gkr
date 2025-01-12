use circuit_std_rs::gnark::emparam::bls12381_fp;
use circuit_std_rs::gnark::emulated::field_bls12381::e2::CurveF;
use circuit_std_rs::gnark::emulated::field_bls12381::e2::Ext2;
use circuit_std_rs::gnark::emulated::field_bls12381::e2::GE2;
use circuit_std_rs::gnark::hints::register_hint;
use circuit_std_rs::gnark::limbs::*;
use circuit_std_rs::gnark::utils::*;
use circuit_std_rs::gnark::emparam::FieldParams;
use circuit_std_rs::gnark::element::*;
use circuit_std_rs::gnark::emulated::point;
use expander_compiler::frontend::extra::*;
use expander_compiler::{circuit::layered::InputType, frontend::*};
use expander_compiler::frontend::builder::*;
#[derive(Default,Clone)]
pub struct G2AffP {
    pub x: GE2,
    pub y: GE2
}

impl G2AffP {
    pub fn new(x: GE2, y: GE2) -> Self {
        Self {
            x,
            y,
        }
    }
    pub fn from_vars(x0: Vec<Variable>, y0: Vec<Variable>, x1: Vec<Variable>, y1: Vec<Variable>) -> Self {
        Self {
            x: GE2::from_vars(x0, y0),
            y: GE2::from_vars(x1, y1),
        }
    }
}

pub struct G2 {
    pub curve_f: Ext2,
}

impl G2 {
    pub fn new<'a, C: Config, B: RootAPI<C>>(native: &'a mut B) -> Self {
        let curve_f = Ext2::new(native);
        Self {
            curve_f,
        }
    }
    pub fn neg<'a, C: Config, B: RootAPI<C>>(&mut self, native: &'a mut B, p: &G2AffP) -> G2AffP {
        let yr = self.curve_f.neg(native, &p.y);
        G2AffP::new(p.x.clone(), yr)
    }
    pub fn generator<'a, C: Config, B: RootAPI<C>>(&mut self, native: &'a mut B) -> G2AffP {
        // x coordinates in Fp2
        let x0 = value_of::<C, B, bls12381_fp>(native, Box::new("352701069587466618187139116011060144890029952792775240219908644239793785735715026873347600343865175952761926303160".to_string()));
        let x1 = value_of::<C, B, bls12381_fp>(native, Box::new("3059144344244213709971259814753781636986470325476647558659373206291635324768958432433509563104347017837885763365758".to_string()));
        
        // y coordinates in Fp2
        let y0 = value_of::<C, B, bls12381_fp>(native, Box::new("1985150602287291935568054521177171638300868978215655730859378665066344726373823718423869104263333984641494340347905".to_string()));
        let y1 = value_of::<C, B, bls12381_fp>(native, Box::new("927553665492332455747201965776037880757740193453592970025027978793976877002675564980949289727957565575433344219582".to_string()));
    
        G2AffP::new(
            GE2 {
                a0: x0,
                a1: x1
            },
            GE2 {
                a0: y0,
                a1: y1
            }
        )
    }
}

pub struct LineEvaluation {
    pub r0: GE2,
    pub r1: GE2
}
impl Default for LineEvaluation {
    fn default() -> Self {
        LineEvaluation { r0: GE2::default(), r1: GE2::default() }
    }
}
// pub type LineEvaluations = [[Option<Box<LineEvaluation>>; 64 - 1]; 2];
type LineEvaluationArray = [[Option<Box<LineEvaluation>>; 63]; 2];

pub struct LineEvaluations(pub LineEvaluationArray);

impl Default for LineEvaluations {
    fn default() -> Self {
        LineEvaluations([[None; 63]; 2].map(|row:[Option<bls12381_fp>; 63] | row.map(|_| None)))
    }
}
impl LineEvaluations {
    pub fn is_empty(&self) -> bool {
        self.0.iter().all(|row| row.iter().all(|cell| cell.is_none()))
    }
}
pub struct G2Affine {
    pub p: G2AffP,
    pub lines: LineEvaluations
}
