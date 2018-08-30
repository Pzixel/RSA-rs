#![allow(many_single_char_names)]
#[macro_use]
extern crate lazy_static;
extern crate rand;

use rand::{thread_rng, Rng};

lazy_static! {
    static ref PRIMES: Vec<i64> = {
        let file = include_str!("../primes.txt");
        file.split('\n').filter_map(|x| x.parse().ok()).collect()
    };
}

pub struct PublicKeyClass {
    modulus: i64,
    exponent: i64,
}

pub struct PrivateKeyClass {
    modulus: i64,
    exponent: i64,
}

fn gcd(a: i64, b: i64) -> i64 {
    let mut a = a;
    let mut b = b;
    let mut c;
    while a != 0 {
        c = a;
        a = b % a;
        b = c;
    }
    b
}

fn ext_euclid(a: i64, b: i64) -> i64 {
    let mut a = a;
    let (mut x, mut y, mut u, mut v, mut gcd) = (0, 1, 1, 0, b);
    while a != 0 {
        let q = gcd / a;
        let r = gcd % a;
        let m = x - u * q;
        let n = y - v * q;
        gcd = a;
        a = r;
        x = u;
        y = v;
        u = m;
        v = n;
    }
    y
}

fn rsa_mod_exp(b: i64, e: i64, m: i64) -> Result<i64, &'static str> {
    if b < 0 || e < 0 || m <= 0 {
        return Err("Invalid rsa_mod_exp arguments");
    }
    let b = b % m;
    let num = if e == 0 {
        1
    } else if e == 1 {
        b
    } else if e % 2 == 0 {
        rsa_mod_exp(b * b % m, e / 2, m)? % m
    } else {
        b * rsa_mod_exp(b, e - 1, m)? % m
    };
    Ok(num)
}

pub fn rsa_gen_keys() -> (PublicKeyClass, PrivateKeyClass) {
    const E: i64 = (1 << 8) + 1;
    let (n, phi) = {
        let mut rng = thread_rng();
        loop {
            let p = *rng.choose(&PRIMES).unwrap();
            let q = *rng.choose(&PRIMES).unwrap();
            let n = p * q;
            let phi = (p - 1) * (q - 1);
            if p != 0 && q != 0 && p != q && gcd(phi, E) == 1 {
                break (n, phi);
            }
        }
    };
    let mut d = ext_euclid(phi, E);
    while d < 0 {
        d += phi;
    }

    let public = PublicKeyClass {
        modulus: n,
        exponent: E,
    };
    let private = PrivateKeyClass {
        modulus: n,
        exponent: d,
    };

    (public, private)
}

pub fn rsa_encrypt(message: &[u8], public: &PublicKeyClass) -> Vec<i64> {
    message
        .iter()
        .map(|x| rsa_mod_exp((*x).into(), public.exponent, public.modulus).unwrap())
        .collect()
}

pub fn rsa_decrypt(message: &[i64], private: &PrivateKeyClass) -> Vec<u8> {
    message
        .iter()
        .map(|x| rsa_mod_exp(*x as i64, private.exponent, private.modulus).unwrap() as u8)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let message = b"Hello world";
        let (public, private) = rsa_gen_keys();

        let encrypted = rsa_encrypt(message, &public);
        let decrypted = rsa_decrypt(&encrypted, &private);

        assert_eq!(&decrypted, message);
    }
}
