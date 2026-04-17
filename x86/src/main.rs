use ed25519_dalek::{Signature as DalekSignature, Verifier, VerifyingKey as DalekVerifyingKey};
use fastcrypto::ed25519::Ed25519KeyPair;
use fastcrypto::traits::{KeyPair, Signer, ToFromBytes};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let message = b"hardcoded message from fastcrypto";

    // 1) Generate an Ed25519 keypair and sign with fastcrypto.
    let private_key_bytes = [7u8; 32];
    let keypair = Ed25519KeyPair::from_bytes(&private_key_bytes)?;
    let signature = keypair.sign(message);

    // 2) Verify with ed25519-dalek using the same public key/signature bytes.
    let public_key_bytes: [u8; 32] = keypair.public().as_ref().try_into()?;
    let signature_bytes: [u8; 64] = signature.as_ref().try_into()?;

    let dalek_public_key = DalekVerifyingKey::from_bytes(&public_key_bytes)?;
    let dalek_signature = DalekSignature::from_bytes(&signature_bytes);

    dalek_public_key.verify(message, &dalek_signature)?;
    println!("Signature verified with ed25519-dalek");

    Ok(())
}
