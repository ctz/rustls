//! Compression related operations

use crate::msgs::enums::CertificateCompressionAlgorithm;
use std::io::Result;

/// A certificate compression algorithm described
/// as a pair of compression and decompression
/// functions used to compress and decompress a certificate
pub struct CertificateCompression {
    /// compression algorithm
    pub alg: CertificateCompressionAlgorithm,

    /// compression function
    pub compress: CertificateCompress,

    /// decompression function
    pub decompress: CertificateDecompress,
}

type CompressionFn = Box<dyn (Fn(Vec<u8>, &[u8]) -> Result<Vec<u8>>) + Send + Sync>;

/// A compression function which returns the compressed representation
/// of the input
pub struct CertificateCompress(CompressionFn);

impl CertificateCompress {
    /// Create a new CertificateCompress
    pub fn new(compression_fn: CompressionFn) -> Self {
        Self(compression_fn)
    }

    /// Call the compression function
    pub(crate) fn compress(&self, writer: Vec<u8>, input: &[u8]) -> Result<Vec<u8>> {
        self.0(writer, input)
    }
}

type DecompressionFn = CompressionFn;

/// A decompression function which returns the decompressed representation
/// of the input. The input to this function is a pre-allocated vector
/// of the expected length of the uncompressed input
pub struct CertificateDecompress(DecompressionFn);

impl CertificateDecompress {
    /// Create a new CertificateDecompress
    pub fn new(decompression_fn: DecompressionFn) -> Self {
        Self(decompression_fn)
    }

    /// Call the decompression function
    pub(crate) fn decompress(&self, writer: Vec<u8>, input: &[u8]) -> Result<Vec<u8>> {
        self.0(writer, input)
    }
}
