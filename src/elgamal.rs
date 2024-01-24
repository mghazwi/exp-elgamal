use ark_std::ops::Mul;
use ark_std::UniformRand;
use ark_ff::BigInteger256;
use ark_ec::CurveGroup;
use ark_ed_on_bn254::EdwardsConfig;
use ark_ed_on_bn254::Fr as Fr;
use ark_std::marker::PhantomData;
use ark_std::rand::Rng;
use crate::Error;
use ark_ec::models::twisted_edwards::Affine;
use std::collections::HashMap;

pub struct ElGamal<C: CurveGroup> {
    _group: PhantomData<C>,
}
#[derive(Clone)]
pub struct Parameters<C: CurveGroup> {
    pub generator: C::Affine,
}

pub type PublicKey<C> = <C as CurveGroup>::Affine;

pub struct SecretKey<C: CurveGroup>(pub C::ScalarField);

pub type Ciphertext<C> = (<C as CurveGroup>::Affine, <C as CurveGroup>::Affine);

pub type W<C> = (<C as CurveGroup>::Affine, <C as CurveGroup>::Affine);

pub fn setup<C: CurveGroup, R: Rng>(rng: &mut R) -> Result<Parameters<C>, Error> {
    // get a random generator
    let generator = C::rand(rng).into();

    Ok(Parameters { generator })
}

pub fn keygen<C: CurveGroup, R: Rng>(
    pp: Parameters<C>,
    rng: &mut R,
) -> Result<(PublicKey<C>, SecretKey<C>), Error> {
    // get a random element from the scalar field
    let secret_key: C::ScalarField = C::ScalarField::rand(rng);

    // compute secret_key*generator to derive the public key
    let public_key = pp.generator.mul(secret_key).into();

    Ok((public_key, SecretKey(secret_key)))
}

pub fn combine_pks<C: CurveGroup>(
    pks: &[PublicKey<C>],
) -> Result<PublicKey<C>, Error> {

    let mut pk_alpha: <C as CurveGroup>::Affine = pks[0];
    for pk in &pks[1..] {
        pk_alpha = (pk_alpha + pk).into();
    }

    Ok(pk_alpha)
}

pub fn add<C: CurveGroup>(
        ciphertext1: &Ciphertext<C>,
        ciphertext2: &Ciphertext<C>,
    ) -> Result<Ciphertext<C>, Error> {
    
    let c1 = ciphertext1.0 + ciphertext2.0;
    let c2 = ciphertext1.1 + ciphertext2.1;

    Ok((c1.into_affine(), c2.into_affine()))
}

pub fn encrypt<C: CurveGroup>(
    pp: &Parameters<C>,
    pk: &PublicKey<C>,
    message: &C::ScalarField,
    r: &C::ScalarField,
) -> Result<Ciphertext<C>, Error> {
    // compute s = r*pk
    let s = pk.mul(r).into();

    // compute c1 = r*generator
    let c1 = pp.generator.mul(r).into();

    // let k = <C as PrimeField>::

    let g_m = pp.generator.mul(message).into();

    // compute c2 = m + s
    let c2 = g_m + s;

    Ok((c1, c2.into_affine()))
}

pub fn gen_re_encryption_share<C: CurveGroup>(
    pp: &Parameters<C>,
    ciphertext: &Ciphertext<C>,
    sk: &SecretKey<C>,
    new_pk: &PublicKey<C>,
    r: &C::ScalarField,
) -> Result<W<C>, Error>{

    let c1: <C as CurveGroup>::Affine = ciphertext.0;
    // w1 = g^r
    let w1 = pp.generator.mul(r).into();
    // w2 = -c1^sk + new_pk^r
    let s = c1.mul(sk.0);
    let s_inv = -s;
    let pk_r = new_pk.mul(r).into();
    let w2 = (s_inv+pk_r).into();

    Ok((w1,w2))
}

pub fn combine_re_encryption_shares<C: CurveGroup>(
    ws: &[W<C>],
) -> Result<W<C>, Error>{

    let mut w_combined = ws[0];

    for w in &ws[1..] {
        w_combined.0 = (w_combined.0 + w.0).into();
        w_combined.1 = (w_combined.1 + w.1).into();
    }

    Ok(w_combined)
}

pub fn re_encrypt<C: CurveGroup>(
    ciphertext: &Ciphertext<C>,
    w: &W<C>,
) -> Result<Ciphertext<C>,Error>{
    let c2: <C as CurveGroup>::Affine = ciphertext.1;

    let new_c2 = (c2 + w.1).into();

    Ok((w.0,new_c2))

}

pub fn decrypt<C: CurveGroup>(
    sk: &SecretKey<C>,
    ciphertext: &Ciphertext<C>,
) -> Result<C::Affine, Error> {
    let c1: <C as CurveGroup>::Affine = ciphertext.0;
    let c2: <C as CurveGroup>::Affine = ciphertext.1;

    // compute s = secret_key * c1
    let s = c1.mul(sk.0);
    let s_inv = -s;

    // compute message = c2 - s
    let m = c2 + s_inv;

    // baby_giant(32, &pp.generator, &a);

    Ok(m.into_affine())
}

pub fn baby_giant(max_bitwidth: u64, a: &Affine<EdwardsConfig>, b: &Affine<EdwardsConfig>) -> u64 {
    let m = 1u64 << (max_bitwidth / 2);

    let mut table = HashMap::new();
    for j in 0u64..m {
        let v = a.mul(Fr::new(BigInteger256::from(j))).into_affine();
        table.insert(v, j);
    }
    let am = a.mul(Fr::new(BigInteger256::from(m))).into_affine();
    let mut gamma = b.clone();

    for i in 0u64..m {
        if let Some(j) = table.get(&gamma) {
            return i*m + j;
        }
        gamma = (gamma - &am).into_affine();
    }

    panic!("No discrete log found");
}

#[cfg(test)]
mod test {
    // use ark_ec::{CurveGroup, AffineRepr};
    // use ark_ec::models::twisted_edwards::Affine;
    // use ark_std::ops::Mul;
    use ark_std::{test_rng, UniformRand};
    use ark_ff::MontFp;
    // use ark_ff::BigInteger256;

    use ark_ed_on_bn254::EdwardsProjective as JubJub;
    use ark_ed_on_bn254::EdwardsAffine as babyj;
    // use ark_ed_on_bn254::EdwardsConfig;
    use ark_ed_on_bn254::Fr as Fr;
    use ark_ed_on_bn254::Fq as Fq;
// 
    use crate::elgamal::*;

    #[test]
    fn test_elgamal_encryption() {
        let rng = &mut test_rng();

        // setup and key generation
        let parameters = setup::<JubJub,_>(rng).unwrap();
        println!("gen: {}",parameters.generator);
        // if we want to define our own generator
        let _gxx:Fq  = MontFp!("11904062828411472290643689191857696496057424932476499415469791423656658550213");
        let _gyy:Fq = MontFp!("9356450144216313082194365820021861619676443907964402770398322487858544118183");
        // check that generator is on curve
        let gx = parameters.generator.x;
        let gy = parameters.generator.y;
        let b = babyj::new(gx, gy);
        assert!(babyj::is_on_curve(&b));
        assert!(babyj::is_in_correct_subgroup_assuming_on_curve(&b));
        // convert to mont
        let _gx_mont = (MontFp!("1") + gy) / (MontFp!("1") - gy); 
        let _gy_mont = (MontFp!("1")+gy)/((MontFp!("1")-gy) * gx);

        // define plaintext
        let plain= Fr::from(4);
        // key gen
        let (pk, sk) = keygen::<JubJub, _>(parameters.clone(), rng).unwrap();
        // randomness
        let r = Fr::rand(rng);
        //encrypt
        let ct = encrypt(&parameters, &pk, &plain, &r).unwrap();
        // decrypt
        let plain_dl = decrypt::<JubJub>(&sk, &ct).unwrap();
        let plain_back = baby_giant(32, &b, &plain_dl);

        assert_eq!(4,plain_back);

        println!("plain_back: {}",plain_back);


    }

    #[test]
    fn test_elgamal_encryption_with_addition() {
        let rng = &mut test_rng();

        // setup and key generation
        let parameters = setup::<JubJub,_>(rng).unwrap();
        println!("gen: {}",parameters.generator);
        // if we want to define our own generator
        let _gxx:Fq  = MontFp!("11904062828411472290643689191857696496057424932476499415469791423656658550213");
        let _gyy:Fq = MontFp!("9356450144216313082194365820021861619676443907964402770398322487858544118183");
        // check that generator is on curve
        let gx = parameters.generator.x;
        let gy = parameters.generator.y;
        let b = babyj::new(gx, gy);
        assert!(babyj::is_on_curve(&b));
        assert!(babyj::is_in_correct_subgroup_assuming_on_curve(&b));
        // convert to mont
        let _gx_mont = (MontFp!("1") + gy) / (MontFp!("1") - gy); 
        let _gy_mont = (MontFp!("1")+gy)/((MontFp!("1")-gy) * gx);

        // define plaintexts
        let plain= Fr::from(4);
        // key gen
        let (pk, sk) = keygen::<JubJub, _>(parameters.clone(), rng).unwrap();
        // randomness
        let r = Fr::rand(rng);
        //encrypt
        let ct = encrypt(&parameters, &pk, &plain, &r).unwrap();
        let ct_added = add::<JubJub>(&ct,&ct.clone()).unwrap();
        // decrypt
        let plain_dl = decrypt::<JubJub>(&sk, &ct_added).unwrap();
        let plain_back = baby_giant(32, &b, &plain_dl);

        assert_eq!(8,plain_back);

        println!("plain_back: {}",plain_back);


    }

    #[test]
    fn test_elgamal_encryption_with_dkg() {
        let rng = &mut test_rng();

        // number of parties
        let n = 2;

        // setup and key generation
        let parameters = setup::<JubJub,_>(rng).unwrap();
        println!("gen: {}",parameters.generator);
        // if we want to define our own generator
        let _gxx:Fq  = MontFp!("11904062828411472290643689191857696496057424932476499415469791423656658550213");
        let _gyy:Fq = MontFp!("9356450144216313082194365820021861619676443907964402770398322487858544118183");
        // check that generator is on curve
        let gx = parameters.generator.x;
        let gy = parameters.generator.y;
        let b = babyj::new(gx, gy);
        assert!(babyj::is_on_curve(&b));
        assert!(babyj::is_in_correct_subgroup_assuming_on_curve(&b));
        // convert to mont
        let _gx_mont = (MontFp!("1") + gy) / (MontFp!("1") - gy); 
        let _gy_mont = (MontFp!("1")+gy)/((MontFp!("1")-gy) * gx);

        // define plaintext
        let plain= Fr::from(4);
        // key gen
        let mut pks = vec![];
        let mut sks = vec![];
        for _i in 0..n {
            let (pk, sk) = keygen::<JubJub, _>(parameters.clone(), rng).unwrap();
            pks.push(pk);
            sks.push(sk);
        }

        // pk_beta
        let (pk_beta, sk_beta) = keygen::<JubJub, _>(parameters.clone(), rng).unwrap();
        // combine pks
        let pk_alpha = combine_pks::<JubJub>(&pks).unwrap();
        // randomness
        let r = Fr::rand(rng);
        //encrypt
        let ct = encrypt(&parameters, &pk_alpha, &plain, &r).unwrap();
        
        // get w shares
        let mut ws = vec![];
        for i in 0..n {
            let r_p = Fr::rand(rng);
            let w = gen_re_encryption_share(&parameters, &ct, &sks[i], &pk_beta, &r_p).unwrap();
            ws.push(w);
        }
        // combine w shares
        let w_combined = combine_re_encryption_shares::<JubJub>(&ws).unwrap();
        
        // re-enc
        let ct_beta = re_encrypt::<JubJub>(&ct, &w_combined).unwrap();

        // decrypt
        let plain_dl = decrypt::<JubJub>(&sk_beta, &ct_beta).unwrap();
        let plain_back = baby_giant(32, &b, &plain_dl);

        assert_eq!(4,plain_back);

        println!("plain_back: {}",plain_back);


    }
}