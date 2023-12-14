use std::str::FromStr;

use crate::{
    app::PrismNodeApp,
    cli::{Cli, Commands, DbArgs, MigrateArgs, ServerArgs, SetCursorArgs},
};
use anyhow::Context;
use prism_core::{
    crypto::codec::HexStr,
    dlt::cardano::OuraN2NSource,
    store::{DltCursor, DltCursorStore},
};
use prism_storage::db::PrismDB;

pub async fn execute_command(cli: &Cli) -> anyhow::Result<()> {
    match &cli.command {
        Commands::Migrate(args) => execute_migration(args).await,
        Commands::Server(args) => execute_server(args).await,
        Commands::SetCursor(args) => execute_set_cursor(args).await,
    }
}

async fn execute_migration(args: &MigrateArgs) -> anyhow::Result<()> {
    do_migrate(&args.db_args).await?;
    Ok(())
}

async fn execute_server(args: &ServerArgs) -> anyhow::Result<()> {
    let cardano_addr = &args.cardano_args.address;
    log::info!(
        "Using cardano node address {} as data source.",
        cardano_addr
    );

    // TODO: support custom network
    let store = do_migrate(&args.db_args).await?;
    let source = OuraN2NSource::since_persisted_cursor_or_origin(
        store.clone(),
        cardano_addr,
        &args.cardano_args.network.to_iden(),
    )
    .await
    .context("Unable to create a OuraN2NSource")?;
    let node_app = PrismNodeApp::new(store, source);
    node_app.run(args.bind, args.port).await;
    Ok(())
}

async fn do_migrate(db_args: &DbArgs) -> anyhow::Result<PrismDB> {
    log::info!("Executing database migration");
    let db_url = &db_args.db_url;
    let prism_db = PrismDB::connect_url(db_url).await.unwrap();
    prism_db.migrate().await?;
    log::info!("Applied migration successfully");
    Ok(prism_db)
}

async fn execute_set_cursor(args: &SetCursorArgs) -> anyhow::Result<()> {
    let store = do_migrate(&args.db_args).await?;
    let cursor = DltCursor {
        slot: args.slot,
        block_hash: HexStr::from_str(&args.blockhash)
            .context("Unable to parse hexstring as bytes")?
            .as_bytes()
            .into(),
    };
    store.set_cursor(cursor).await?;
    log::info!("Set cursor successfully");
    Ok(())
}
