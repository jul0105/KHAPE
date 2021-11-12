use snarkvm_curves::traits::{AffineCurve, ProjectiveCurve};
use snarkvm_curves::edwards_bls12::EdwardsProjective;

// use crate::traits::{AffineCurve, ProjectiveCurve};
use snarkvm_fields::Zero;
use snarkvm_utilities::rand::UniformRand;

use rand::SeedableRng;
use rand_xorshift::XorShiftRng;
use std::ops::{AddAssign, Mul};

fn main() {
    println!("Curves");

    // Exemple from https://github.com/AleoHQ/snarkVM/blob/testnet2/curves/src/traits/tests_curve.rs
    random_multiplication_test::<EdwardsProjective>();
    random_addition_test::<EdwardsProjective>();

}

pub const ITERATIONS: usize = 5;

fn random_multiplication_test<G: ProjectiveCurve>() {
    let mut rng = XorShiftRng::seed_from_u64(1231275789u64);

    for _ in 0..ITERATIONS {
        let mut a = G::rand(&mut rng);
        let mut b = G::rand(&mut rng);
        let a_affine = a.into_affine();
        let b_affine = b.into_affine();

        let s = G::ScalarField::rand(&mut rng);

        // s ( a + b )
        let mut tmp1 = a;
        tmp1.add_assign(b);
        tmp1.mul_assign(s);

        // sa + sb
        a.mul_assign(s);
        b.mul_assign(s);

        let mut tmp2 = a;
        tmp2.add_assign(b);

        // Affine multiplication
        let mut tmp3 = a_affine.mul(s);
        tmp3.add_assign(b_affine.mul(s));

        assert_eq!(tmp1, tmp2);
        assert_eq!(tmp1, tmp3.into());
    }
}


fn random_addition_test<G: ProjectiveCurve>() {
    let mut rng = XorShiftRng::seed_from_u64(1231275789u64);

    for _ in 0..ITERATIONS {
        let a = G::rand(&mut rng);
        let b = G::rand(&mut rng);
        let c = G::rand(&mut rng);
        let a_affine = a.into_affine();
        let b_affine = b.into_affine();
        let c_affine = c.into_affine();

        // a + a should equal the doubling
        {
            let mut aplusa = a;
            aplusa.add_assign(a);

            let mut aplusamixed = a;
            aplusamixed.add_assign_mixed(&a.into_affine());

            let mut adouble = a;
            adouble.double_in_place();

            assert_eq!(aplusa, adouble);
            assert_eq!(aplusa, aplusamixed);
        }

        let mut tmp = vec![G::zero(); 6];

        // (a + b) + c
        tmp[0] = (a + b) + c;

        // a + (b + c)
        tmp[1] = a + (b + c);

        // (a + c) + b
        tmp[2] = (a + c) + b;

        // Mixed addition

        // (a + b) + c
        tmp[3] = a_affine.into_projective();
        tmp[3].add_assign_mixed(&b_affine);
        tmp[3].add_assign_mixed(&c_affine);

        // a + (b + c)
        tmp[4] = b_affine.into_projective();
        tmp[4].add_assign_mixed(&c_affine);
        tmp[4].add_assign_mixed(&a_affine);

        // (a + c) + b
        tmp[5] = a_affine.into_projective();
        tmp[5].add_assign_mixed(&c_affine);
        tmp[5].add_assign_mixed(&b_affine);

        // Comparisons
        for i in 0..6 {
            for j in 0..6 {
                if tmp[i] != tmp[j] {
                    println!("{} \n{}", tmp[i], tmp[j]);
                }
                assert_eq!(tmp[i], tmp[j], "Associativity failed {} {}", i, j);
                assert_eq!(tmp[i].into_affine(), tmp[j].into_affine(), "Associativity failed");
            }

            assert!(tmp[i] != a);
            assert!(tmp[i] != b);
            assert!(tmp[i] != c);

            assert!(a != tmp[i]);
            assert!(b != tmp[i]);
            assert!(c != tmp[i]);
        }
    }
}