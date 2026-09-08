use anyhow::Result;
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const SESSION_TTL: Duration = Duration::from_secs(7 * 24 * 3600);

const MAX_FAILS: u32 = 5;
const LOCK_TIME: Duration = Duration::from_secs(300);

pub fn rand_hex(n_bytes: usize) -> String {
    let mut b = vec![0u8; n_bytes];
    getrandom::fill(&mut b).expect("system entropy source unavailable");
    b.iter().map(|x| format!("{x:02x}")).collect()
}

const BASE62: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

fn base62_encode(bytes: &[u8]) -> String {
    let mut num: Vec<u8> = bytes.to_vec();
    let mut out: Vec<u8> = Vec::new();
    while num.iter().any(|&b| b != 0) {
        let mut rem = 0u32;
        for b in num.iter_mut() {
            let cur = rem * 256 + u32::from(*b);
            *b = u8::try_from(cur / 62).unwrap_or(0);
            rem = cur % 62;
        }
        out.push(BASE62[rem as usize]);
    }
    if out.is_empty() {
        out.push(BASE62[0]);
    }
    out.reverse();
    String::from_utf8(out).expect("base62 alphabet is ascii")
}

pub fn generate_token() -> String {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).expect("system entropy source unavailable");
    format!("sk_auth_{}", base62_encode(&b))
}

pub fn hash_password(password: &str) -> Result<String> {
    let mut salt_bytes = [0u8; 16];
    getrandom::fill(&mut salt_bytes).map_err(|e| anyhow::anyhow!("system entropy source unavailable: {e}"))?;
    let salt = SaltString::encode_b64(&salt_bytes[..]).map_err(|e| anyhow::anyhow!("failed to generate salt: {e}"))?;
    let phc = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("failed to hash password: {e}"))?;
    Ok(phc.to_string())
}

pub fn verify_password(password: &str, phc: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(phc) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

pub struct Sessions {
    inner: Mutex<HashMap<String, (String, Instant)>>,
}

impl Sessions {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    pub fn create(&self, username: &str) -> String {
        let sid = rand_hex(32);
        let mut g = self.inner.lock().unwrap();
        g.retain(|_, (_, t)| t.elapsed() < SESSION_TTL);
        g.insert(sid.clone(), (username.to_string(), Instant::now()));
        sid
    }

    pub fn get(&self, sid: &str) -> Option<String> {
        let g = self.inner.lock().unwrap();
        g.get(sid)
            .filter(|(_, t)| t.elapsed() < SESSION_TTL)
            .map(|(u, _)| u.clone())
    }

    pub fn remove(&self, sid: &str) {
        self.inner.lock().unwrap().remove(sid);
    }

    pub fn remove_user(&self, username: &str) {
        self.inner
            .lock()
            .unwrap()
            .retain(|_, (u, _)| u != username);
    }
}

pub struct LoginGuard {
    inner: Mutex<HashMap<String, (u32, Instant)>>,
}

impl LoginGuard {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    pub fn locked(&self, key: &str) -> bool {
        let mut g = self.inner.lock().unwrap();
        if let Some((_, until)) = g.get(key) {
            if Instant::now() < *until {
                return true;
            }
            g.remove(key);
        }
        false
    }

    pub fn fail(&self, key: &str) {
        let mut g = self.inner.lock().unwrap();
        let e = g.entry(key.to_string()).or_insert((0, Instant::now()));
        e.0 += 1;
        if e.0 >= MAX_FAILS {
            e.1 = Instant::now() + LOCK_TIME;
        }
    }

    pub fn reset(&self, key: &str) {
        self.inner.lock().unwrap().remove(key);
    }
}
