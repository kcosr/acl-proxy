use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use http_access_runtime::SystemTlsRootSet;
use http_access_types::PolicyGeneration;

use crate::runtime::ActivationCancellation;
use crate::tls::TlsActivationError;
use crate::tls_io_runtime::TlsIoRuntime;

/// Generation-bound TLS trust material shared by every candidate consumer.
pub(crate) struct CandidateTlsResolver {
    tls_io_runtime: Arc<TlsIoRuntime>,
    cancellation: ActivationCancellation,
    generation: PolicyGeneration,
    custom_material: BTreeMap<PathBuf, Arc<[Vec<u8>]>>,
    system_material: Arc<[Vec<u8>]>,
    system_roots: Option<SystemTlsRootSet>,
    #[cfg(test)]
    file_reads: usize,
}

impl CandidateTlsResolver {
    pub(crate) async fn activate(
        tls_io_runtime: Arc<TlsIoRuntime>,
        cancellation: ActivationCancellation,
        generation: PolicyGeneration,
    ) -> Result<Self, TlsActivationError> {
        let (certificates, system_roots) = tls_io_runtime
            .load_system_roots(generation, &cancellation)
            .await?;
        if cancellation.is_cancelled() {
            return Err(TlsActivationError::ActivationCancelled);
        }
        Ok(Self {
            tls_io_runtime,
            cancellation,
            generation,
            custom_material: BTreeMap::new(),
            system_material: certificates.into(),
            system_roots: Some(system_roots),
            #[cfg(test)]
            file_reads: 0,
        })
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
        if let Some(material) = self.custom_material.get(normalized_path) {
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
        self.custom_material
            .insert(normalized_path.to_path_buf(), Arc::clone(&material));
        Ok(material)
    }

    pub(crate) fn system_material(&self) -> &[Vec<u8>] {
        &self.system_material
    }

    pub(crate) fn take_system_roots(&mut self) -> Result<SystemTlsRootSet, TlsActivationError> {
        self.system_roots
            .take()
            .ok_or(TlsActivationError::Configuration)
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
