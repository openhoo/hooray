use std::sync::{Arc, Mutex};

use tokio::sync::Semaphore;

use crate::store::{Store, StoreError};

use super::ApiError;

/// One SQLite connection is shared by API requests. Wait for its turn on the
/// async runtime; only the admitted operation needs a blocking worker thread.
pub(super) struct Database {
    connection: Mutex<Store>,
    turn: Arc<Semaphore>,
}

impl Database {
    pub(super) fn new(store: Store) -> Self {
        Self {
            connection: Mutex::new(store),
            turn: Arc::new(Semaphore::new(1)),
        }
    }

    pub(super) async fn call<T, F>(self: &Arc<Self>, operation: F) -> Result<T, ApiError>
    where
        T: Send + 'static,
        F: FnOnce(&mut Store) -> Result<T, StoreError> + Send + 'static,
    {
        // A cancelled waiter drops its operation before it reaches SQLite.
        // After admission, the worker retains the permit even if the HTTP
        // request is dropped: an in-flight write can finish its transaction.
        let turn = self
            .turn
            .clone()
            .acquire_owned()
            .await
            .expect("private semaphore is never closed");
        let database = self.clone();
        tokio::task::spawn_blocking(move || {
            let _turn = turn;
            let mut connection = database
                .connection
                .lock()
                .map_err(|_| ApiError::internal("store_unavailable", "store lock is poisoned"))?;
            operation(&mut connection).map_err(ApiError::from)
        })
        .await
        .map_err(|_| ApiError::internal("store_unavailable", "store operation was cancelled"))?
    }
}
