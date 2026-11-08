namespace Hoddmir.Storage
{
    /// <summary>
    /// Result of a <see cref="EncryptedEntryStore.VerifyAsync"/> call.
    /// </summary>
    /// <param name="TotalRecords">Total number of records scanned (Put + Delete).</param>
    /// <param name="ValidRecords">Records that passed authentication and validation.</param>
    /// <param name="CorruptedRecords">Records that failed authentication or validation.</param>
    /// <param name="TruncatedRecords">
    /// Records that could not be fully read (incomplete write or truncated file).
    /// A non-zero value here typically indicates a crash during a previous write.
    /// </param>
    /// <param name="CorruptedKeys">
    /// The known keys or file offsets of records that failed verification.
    /// Empty when <see cref="CorruptedRecords"/> is zero.
    /// </param>
    /// <param name="TruncatedOffsets">
    /// File offsets at which truncation was detected.
    /// Empty when <see cref="TruncatedRecords"/> is zero.
    /// </param>
    public record VerifyResult(int TotalRecords,
                               int ValidRecords,
                               int CorruptedRecords,
                               int TruncatedRecords,
                               IReadOnlyList<string> CorruptedKeys,
                               IReadOnlyList<long> TruncatedOffsets)
    {
        /// <summary>
        /// <c>true</c> if every record verified successfully and no truncation was detected.
        /// </summary>
        public bool IsHealthy => CorruptedRecords == 0 && TruncatedRecords == 0;

        /// <summary>Human-readable summary.</summary>
        public override string ToString() =>
            IsHealthy
                ? $"Store healthy: {ValidRecords}/{TotalRecords} records OK."
                : $"Store UNHEALTHY: {ValidRecords}/{TotalRecords} OK, " +
                  $"{CorruptedRecords} corrupted, {TruncatedRecords} truncated.";
    }

}
