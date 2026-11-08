namespace Hoddmir.Storage
{
    /// <summary>
    /// Result of a <see cref="EncryptedEntryStore.VerifyAsync"/> call.
    /// </summary>
    /// <param name="TotalRecords">Total number of records scanned (Put + Delete).</param>
    /// <param name="ValidRecords">Records that passed authentication and validation.</param>
    /// <param name="CorruptedRecords">Records that failed authentication or validation.</param>
    /// <param name="TruncatedRecords">
    /// Records or an incomplete header that could not be fully read.
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
        /// <summary>Indicates that the complete header differs from the authenticated header of the open store.</summary>
        public bool IsHeaderCorrupted { get; init; }

        /// <summary>Indicates that the valid log prefix differs from the committed state of the open store.</summary>
        public bool IsLogChanged { get; init; }

        /// <summary>Indicates that the header and all records passed verification.</summary>
        public bool IsHealthy => !this.IsHeaderCorrupted && !this.IsLogChanged &&
                                 this.CorruptedRecords == 0 && this.TruncatedRecords == 0;

        /// <summary>Human-readable summary.</summary>
        public override string ToString() =>
            this.IsHealthy
                ? $"Store healthy: {this.ValidRecords}/{this.TotalRecords} records OK."
                : $"Store UNHEALTHY: {this.ValidRecords}/{this.TotalRecords} OK, " +
                  $"{this.CorruptedRecords} corrupted, {this.TruncatedRecords} truncated." +
                  (this.IsHeaderCorrupted ? " Header corrupted." : string.Empty) +
                  (this.IsLogChanged ? " Committed log changed." : string.Empty);
    }

}
