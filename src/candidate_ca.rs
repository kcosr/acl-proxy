use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use http_access_types::PolicyGeneration;

use crate::runtime::ActivationCancellation;
use crate::tls::TlsActivationError;
use crate::tls_io_runtime::TlsIoRuntime;

/// Generation-bound custom-CA material shared by every candidate consumer.
pub(crate) struct CandidateCaResolver {
    tls_io_runtime: Arc<TlsIoRuntime>,
    cancellation: ActivationCancellation,
    generation: PolicyGeneration,
    material: BTreeMap<PathBuf, Arc<[Vec<u8>]>>,
    #[cfg(test)]
    file_reads: usize,
}

impl CandidateCaResolver {
    pub(crate) fn new(
        tls_io_runtime: Arc<TlsIoRuntime>,
        cancellation: ActivationCancellation,
        generation: PolicyGeneration,
    ) -> Self {
        Self {
            tls_io_runtime,
            cancellation,
            generation,
            material: BTreeMap::new(),
            #[cfg(test)]
            file_reads: 0,
        }
    }

    pub(crate) fn generation(&self) -> PolicyGeneration {
        self.generation
    }

    pub(crate) fn cancellation(&self) -> &ActivationCancellation {
        &self.cancellation
    }

    pub(crate) async fn resolve(
        &mut self,
        normalized_path: &Path,
    ) -> Result<Arc<[Vec<u8>]>, TlsActivationError> {
        self.check_cancellation()?;
        if let Some(material) = self.material.get(normalized_path) {
            return Ok(Arc::clone(material));
        }

        #[cfg(test)]
        {
            self.file_reads += 1;
        }
        let certificates = self
            .tls_io_runtime
            .load_custom_ca(
                normalized_path.to_path_buf(),
                self.generation,
                &self.cancellation,
            )
            .await?;
        self.check_cancellation()?;
        let material: Arc<[Vec<u8>]> = certificates.into();
        self.material
            .insert(normalized_path.to_path_buf(), Arc::clone(&material));
        Ok(material)
    }

    fn check_cancellation(&self) -> Result<(), TlsActivationError> {
        if self.cancellation.is_cancelled() {
            Err(TlsActivationError::ActivationCancelled)
        } else {
            Ok(())
        }
    }

    #[cfg(test)]
    pub(crate) fn file_reads(&self) -> usize {
        self.file_reads
    }
}
