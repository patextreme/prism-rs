use axum::{routing::get, Router};
use prism_core::{
    dlt::{DltSource, OperationMetadata},
    store::{OperationStore, OperationStoreError},
};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};
use tokio::net::TcpListener;

mod handler;

pub struct PrismNodeApp<Store, Src> {
    store: Arc<Store>,
    source: Src,
}

impl<Store, Src> PrismNodeApp<Store, Src>
where
    Store: OperationStore + Send + Sync + 'static,
    Src: DltSource,
{
    pub fn new(store: Store, source: Src) -> Self {
        Self {
            store: Arc::new(store),
            source,
        }
    }

    pub async fn run(self, bind: Ipv4Addr, port: u16) {
        let sync_app = CardanoSyncApp {
            store: self.store.clone(),
            source: self.source,
        };
        let server_app = ServerApp { store: self.store };
        let exit = tokio::try_join!(sync_app.run(), server_app.run(bind, port));
        log::info!("PrismNodeApp terminated. Exit reason {:?}", exit);
    }
}

struct ServerApp<Store> {
    store: Arc<Store>,
}

impl<Store> ServerApp<Store>
where
    Store: OperationStore + Send + Sync + 'static,
{
    pub async fn run(self, bind: Ipv4Addr, port: u16) -> anyhow::Result<()> {
        let app = Router::new()
            .route("/", get(|| async { "hello" }))
            .route("/dids/:didRef", get(handler::get_dids))
            .with_state(self.store);

        let listener = TcpListener::bind(&SocketAddr::new(IpAddr::V4(bind), port)).await?;

        log::info!("Starting http server on {}:{}", bind, port);
        axum::serve(listener, app).await?;
        Ok(())
    }
}

struct CardanoSyncApp<Store, Src> {
    store: Arc<Store>,
    source: Src,
}

impl<Store, Src> CardanoSyncApp<Store, Src>
where
    Store: OperationStore,
    Src: DltSource,
{
    pub async fn run(self) -> anyhow::Result<()> {
        let mut rx = self
            .source
            .receiver()
            .expect("Unable to create a DLT source");

        while let Some(published_atala_object) = rx.recv().await {
            let block = published_atala_object.atala_object.block_content;
            let block_metadata = published_atala_object.block_metadata;
            let signed_operations = block.map(|i| i.operations).unwrap_or_default();
            for (idx, signed_operation) in signed_operations.into_iter().enumerate() {
                let insert_result = self
                    .store
                    .insert(
                        signed_operation,
                        OperationMetadata {
                            block_metadata: block_metadata.clone(),
                            osn: idx as u32,
                        },
                    )
                    .await;

                match insert_result {
                    Err(OperationStoreError::EmptyOperation) => {}
                    Err(e) => log::error!("{:?}", e),
                    _ => {}
                };
            }
        }
        Ok(())
    }
}
