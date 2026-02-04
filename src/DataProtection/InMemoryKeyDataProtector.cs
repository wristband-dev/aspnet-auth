using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

using Microsoft.AspNetCore.DataProtection;

namespace Wristband.AspNet.Auth;

/// <summary>
/// Data protector implementation using AES-256-GCM authenticated encryption with HKDF key derivation.
/// Provides confidentiality, integrity, and authenticity in a single cryptographic operation.
/// </summary>
internal class InMemoryKeyDataProtector : IDataProtector
{
    // Cryptographic constants matching typescript-session for cross-platform compatibility
    private const string Salt = "wristband-session-v1";
    private const string BaseInfo = "aes-gcm-encryption";
    private const int KeySize = 32; // 256 bits
    private const int NonceSize = 12; // 96 bits (recommended for AES-GCM per NIST SP 800-38D)
    private const int TagSize = 16; // 128 bits (GCM authentication tag)
    private const byte Version = 1; // Binary format version for future compatibility
    private const int ClockSkewSeconds = 60; // Clock skew tolerance to handle server time differences

    private readonly string _purpose;
    private readonly string[] _secrets;
    private readonly byte[][] _keys;

    /// <summary>
    /// Initializes a new instance of the <see cref="InMemoryKeyDataProtector"/> class.
    /// Derives encryption keys from the provided secrets using HKDF-SHA256 with purpose-based isolation.
    /// </summary>
    /// <param name="purpose">
    /// The purpose string for key derivation. Different purposes derive cryptographically independent keys
    /// from the same secret, enabling secure key isolation across different features (e.g., cookies, CSRF, anti-forgery tokens).
    /// </param>
    /// <param name="secrets">
    /// Array of secrets to derive keys from. The first secret is used for encryption,
    /// all secrets are used for decryption to support zero-downtime secret rotation.
    /// </param>
    public InMemoryKeyDataProtector(string purpose, string[] secrets)
    {
        _purpose = purpose;
        _secrets = secrets;
        _keys = new byte[secrets.Length][];

        // Derive a unique encryption key for each secret and this specific purpose
        // Purpose-based derivation ensures different features (cookies, CSRF, etc.) use different keys
        for (int i = 0; i < secrets.Length; i++)
        {
            _keys[i] = DeriveKey(secrets[i], purpose);
        }
    }

    /// <summary>
    /// Encrypts plaintext data using AES-256-GCM authenticated encryption.
    /// </summary>
    /// <param name="plaintext">The data to encrypt.</param>
    /// <returns>
    /// Encrypted data in format: [version:1][timestamp:8][nonce:12][auth_tag:16][ciphertext:variable].
    /// </returns>
    /// <exception cref="ArgumentException">If plaintext is null or empty.</exception>
    public byte[] Protect(byte[] plaintext)
    {
        if (plaintext == null || plaintext.Length == 0)
        {
            throw new ArgumentException("Plaintext cannot be null or empty.", nameof(plaintext));
        }

        // Use the first key for encryption (newest secret in rotation scenarios)
        var key = _keys[0];

        // Generate a random 96-bit nonce (IV) for this encryption operation
        // CRITICAL: Never reuse a nonce with the same key in GCM mode
        var nonce = new byte[NonceSize];
        RandomNumberGenerator.Fill(nonce);

        // Prepare buffers for encryption output
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TagSize];

        // Perform AES-GCM encryption
        // GCM provides both confidentiality (encryption) and authenticity (auth tag) in one operation
        using var aes = new AesGcm(key, TagSize);
        aes.Encrypt(nonce, plaintext, ciphertext, tag);

        // Create timestamp (8 bytes, Unix timestamp in seconds, big-endian)
        // Timestamp enables:
        // 1. Detection of future-dated cookies (clock skew attacks)
        // 2. Limiting replay attack window when secrets are rotated
        var timestamp = new byte[8];
        var timestampValue = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        BinaryPrimitives.WriteInt64BigEndian(timestamp, timestampValue);

        // Construct binary format: [version:1][timestamp:8][nonce:12][auth_tag:16][ciphertext:variable]
        // Version byte enables future format changes while maintaining backward compatibility
        var result = new byte[1 + 8 + NonceSize + TagSize + ciphertext.Length];
        result[0] = Version;
        Buffer.BlockCopy(timestamp, 0, result, 1, 8);
        Buffer.BlockCopy(nonce, 0, result, 9, NonceSize);
        Buffer.BlockCopy(tag, 0, result, 21, TagSize);
        Buffer.BlockCopy(ciphertext, 0, result, 37, ciphertext.Length);

        return result;
    }

    /// <summary>
    /// Decrypts and validates protected data using AES-256-GCM.
    /// Validates version, timestamp, and authentication tag before returning plaintext.
    /// </summary>
    /// <param name="protectedData">
    /// Encrypted data in format: [version:1][timestamp:8][nonce:12][auth_tag:16][ciphertext:variable].
    /// </param>
    /// <returns>Decrypted plaintext data.</returns>
    /// <exception cref="CryptographicException">
    /// Thrown if:
    /// - Data is malformed or too small
    /// - Version is unsupported
    /// - Timestamp is from the future (beyond clock skew tolerance)
    /// - Authentication tag validation fails (data tampered or wrong secret)
    /// - All secrets fail to decrypt (wrong secrets or corrupted data).
    /// </exception>
    public byte[] Unprotect(byte[] protectedData)
    {
        // Validate minimum size: version(1) + timestamp(8) + nonce(12) + tag(16) = 37 bytes minimum
        if (protectedData == null || protectedData.Length < 1 + 8 + NonceSize + TagSize)
        {
            throw new CryptographicException("Protected data is invalid or corrupted.");
        }

        // Check version byte to ensure we support this format
        // Future versions might use different nonce sizes, algorithms, etc.
        var version = protectedData[0];
        if (version != Version)
        {
            throw new CryptographicException($"Unsupported data protection version: {version}");
        }

        // Extract timestamp (8 bytes, big-endian Unix timestamp)
        var timestampBytes = new byte[8];
        Buffer.BlockCopy(protectedData, 1, timestampBytes, 0, 8);
        var timestamp = BinaryPrimitives.ReadInt64BigEndian(timestampBytes);
        var currentTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        // Validate timestamp isn't from the future (with clock skew tolerance)
        // This prevents attackers from creating future-dated cookies
        // Clock skew tolerance (60 seconds) handles legitimate server time differences
        if (timestamp > currentTime + ClockSkewSeconds)
        {
            throw new CryptographicException("Protected data timestamp is invalid (from the future).");
        }

        // Note: We intentionally do NOT validate maxAge here because:
        // 1. Browser already deletes expired cookies (Cookie.MaxAge handles this)
        // 2. ASP.NET Cookie Auth validates expiration via AuthenticationTicket.ExpiresUtc
        // 3. IDataProtector.Unprotect() has no maxAge parameter in its contract
        // 4. This keeps the protector general-purpose for non-expiring data (e.g., tokens)

        // Extract encryption components from binary format
        var nonce = new byte[NonceSize];
        var tag = new byte[TagSize];
        var ciphertext = new byte[protectedData.Length - 1 - 8 - NonceSize - TagSize];

        Buffer.BlockCopy(protectedData, 9, nonce, 0, NonceSize);
        Buffer.BlockCopy(protectedData, 21, tag, 0, TagSize);
        Buffer.BlockCopy(protectedData, 37, ciphertext, 0, ciphertext.Length);

        // Try each key in order (supports secret rotation)
        // First key is newest (used for encryption), subsequent keys are old (decrypt-only)
        CryptographicException? lastException = null;
        foreach (var key in _keys)
        {
            try
            {
                var plaintext = new byte[ciphertext.Length];
                using var aes = new AesGcm(key, TagSize);

                // AES-GCM decryption automatically validates the authentication tag
                // If tag validation fails, it throws CryptographicException (data tampered or wrong key)
                aes.Decrypt(nonce, ciphertext, tag, plaintext);

                // Success! Return decrypted data
                return plaintext;
            }
            catch (CryptographicException ex)
            {
                // This key failed (wrong secret or auth tag validation failed)
                // Save exception and try next key
                lastException = ex;
            }
        }

        // All keys failed - either wrong secrets, corrupted data, or tampered data
        // Throw generic error to avoid leaking which secret failed (timing attack prevention)
        throw new CryptographicException(
            "Failed to decrypt data with any of the provided secrets. " +
            "Data may be corrupted or encrypted with a different secret.",
            lastException);
    }

    /// <summary>
    /// Creates a new data protector with a sub-purpose for hierarchical key derivation.
    /// </summary>
    /// <param name="purpose">Additional purpose string to append to the current purpose.</param>
    /// <returns>A new IDataProtector with combined purpose string.</returns>
    /// <example>
    /// var cookieProtector = provider.CreateProtector("Authentication.Cookies");
    /// var csrfProtector = cookieProtector.CreateProtector("CSRF");
    /// // csrfProtector has purpose: "Authentication.Cookies.CSRF".
    /// </example>
    public IDataProtector CreateProtector(string purpose)
    {
        if (string.IsNullOrWhiteSpace(purpose))
        {
            throw new ArgumentException("Purpose cannot be null or whitespace.", nameof(purpose));
        }

        // Combine current purpose with new purpose (e.g., "cookies" + "csrf" = "cookies.csrf")
        // This creates a hierarchy of purposes, each with its own derived key
        var combinedPurpose = $"{_purpose}.{purpose}";

        // Create new protector with combined purpose and original secrets
        // Keys will be re-derived with the new combined purpose
        return new InMemoryKeyDataProtector(combinedPurpose, _secrets);
    }

    /// <summary>
    /// Derives a cryptographic key from a secret using HKDF-SHA256.
    /// HKDF (RFC 5869) is the standard approach for deriving keys from high-entropy secrets.
    /// </summary>
    /// <param name="secret">The input secret string.</param>
    /// <param name="purpose">Purpose string for domain separation (prevents key reuse across contexts).</param>
    /// <returns>A 256-bit derived key suitable for AES-GCM encryption.</returns>
    private static byte[] DeriveKey(string secret, string purpose)
    {
        // Convert inputs to bytes
        var secretBytes = Encoding.UTF8.GetBytes(secret);
        var saltBytes = Encoding.UTF8.GetBytes(Salt);

        // Combine base info with purpose for domain separation
        // This ensures different purposes (e.g., "cookies" vs "csrf") get different keys
        var info = $"{BaseInfo}.{purpose}";
        var infoBytes = Encoding.UTF8.GetBytes(info);

        // Use HKDF to derive a 256-bit key
        var key = new byte[KeySize];
        HKDF.DeriveKey(HashAlgorithmName.SHA256, secretBytes, key, saltBytes, infoBytes);

        return key;
    }
}
