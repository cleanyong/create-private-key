use clap::{Parser, ValueEnum};
use num_bigint::{BigUint, RandBigInt};
use num_integer::Integer;
use num_traits::One;
use rand::rngs::OsRng;
use rand::Rng;
use std::process;

/// Default RFC 3526 MODP group used when no custom prime is supplied.
const RFC3526_MODP14_PRIME_HEX: &str = concat!(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1",
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD",
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245",
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D",
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F",
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D",
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B",
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9",
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510",
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF"
);

#[derive(ValueEnum, Clone, Copy, Debug)]
enum DhGroup {
    /// RFC 3526 MODP group 14 (2048-bit safe prime, generator 2).
    Modp14,
}

impl DhGroup {
    fn default_prime_hex(self) -> &'static str {
        match self {
            DhGroup::Modp14 => RFC3526_MODP14_PRIME_HEX,
        }
    }

    fn default_generator(self) -> &'static str {
        match self {
            DhGroup::Modp14 => "2",
        }
    }
}

#[derive(ValueEnum, Clone, Copy, Debug)]
enum OutputFormat {
    Hex,
    Decimal,
    Both,
}

/// Command line arguments for the DH private key generator.
#[derive(Parser, Debug)]
#[command(
    name = "create-private-key",
    about = "Generate a Diffie-Hellman private key (and matching public key) for a chosen group"
)]
struct Args {
    /// RFC 3526 MODP group to base parameters on (ignored when --prime is provided).
    #[arg(long, value_enum, default_value_t = DhGroup::Modp14)]
    group: DhGroup,

    /// Diffie-Hellman prime modulus in decimal or hex (hex may start with 0x).
    #[arg(long)]
    prime: Option<String>,

    /// Generator to use (defaults to group generator).
    #[arg(long)]
    generator: Option<String>,

    /// Output format for the private key.
    #[arg(long = "format", value_enum, default_value_t = OutputFormat::Hex)]
    output_format: OutputFormat,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("Error: {err}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = Args::parse();

    let prime = if let Some(ref prime_str) = args.prime {
        parse_biguint(prime_str)?
    } else {
        parse_hex_biguint(args.group.default_prime_hex())
    };

    if prime <= BigUint::from(3u32) {
        return Err("prime modulus must be greater than 3".into());
    }
    if prime.is_even() {
        return Err("prime modulus must be odd".into());
    }

    let generator = if let Some(ref gen_str) = args.generator {
        parse_biguint(gen_str)?
    } else {
        parse_biguint(args.group.default_generator())?
    };

    if generator <= BigUint::one() {
        return Err("generator must be greater than 1".into());
    }
    if generator >= prime {
        return Err("generator must be less than the prime modulus".into());
    }

    let mut rng = OsRng;
    let private_key = generate_private_key(&prime, &mut rng);
    let public_key = generator.modpow(&private_key, &prime);

    println!("prime_bits={}", prime.bits());
    println!("generator={}", generator);

    match args.output_format {
        OutputFormat::Hex => println!("private_key_hex={}", to_even_length_hex(&private_key)),
        OutputFormat::Decimal => println!("private_key_dec={}", private_key.to_str_radix(10)),
        OutputFormat::Both => {
            println!("private_key_hex={}", to_even_length_hex(&private_key));
            println!("private_key_dec={}", private_key.to_str_radix(10));
        }
    }

    println!("public_key_hex={}", to_even_length_hex(&public_key));

    Ok(())
}

fn generate_private_key<R>(prime: &BigUint, rng: &mut R) -> BigUint
where
    R: Rng + ?Sized,
{
    let two = BigUint::from(2u32);
    let one = BigUint::one();
    let upper_exclusive = prime - &one;
    rng.gen_biguint_range(&two, &upper_exclusive)
}

fn parse_biguint(input: &str) -> Result<BigUint, String> {
    let cleaned: String = input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '_')
        .collect();

    if cleaned.is_empty() {
        return Err("value cannot be empty".into());
    }

    let (radix, digits) = if let Some(stripped) = cleaned.strip_prefix("0x").or_else(|| cleaned.strip_prefix("0X")) {
        (16, stripped)
    } else {
        (10, cleaned.as_str())
    };

    BigUint::parse_bytes(digits.as_bytes(), radix)
        .ok_or_else(|| "failed to parse big integer".to_string())
}

fn parse_hex_biguint(hex: &str) -> BigUint {
    let cleaned: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
    BigUint::parse_bytes(cleaned.as_bytes(), 16).expect("invalid hex prime literal")
}

fn to_even_length_hex(value: &BigUint) -> String {
    let hex = format!("{value:X}");
    if hex.len() % 2 == 0 {
        hex
    } else {
        format!("0{hex}")
    }
}
