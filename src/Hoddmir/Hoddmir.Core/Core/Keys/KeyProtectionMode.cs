namespace Hoddmir.Keys;

/// <summary>Determines how the Data Encryption Key (DEK) is protected in the store header.</summary>
public enum KeyProtectionMode : byte
{
    /// <summary>Windows Data Protection API (DPAPI) — Windows only.</summary>
    WindowsDPAPI      = 0,

    /// <summary>PBKDF2-HMAC-SHA-256 with 600 000 iterations.</summary>
    PasswordPBKDF2    = 1,

    /// <summary>Argon2id (recommended). Parameters are calibrated or fixed at store creation.</summary>
    PasswordArgon2id  = 2,
}
