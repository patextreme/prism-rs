use clap::{Args, Parser, Subcommand, ValueEnum};
use prism_core::dlt::cardano::NetworkIdentifier;
use std::net::Ipv4Addr;

#[derive(Parser)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Run database migration
    Migrate(MigrateArgs),
    /// Run PRISM node server
    Server(ServerArgs),
    /// Set cardano sync cursor
    SetCursor(SetCursorArgs),
}

#[derive(Args)]
pub struct MigrateArgs {
    #[clap(flatten)]
    pub db_args: DbArgs,
}

#[derive(Args)]
pub struct ServerArgs {
    #[clap(flatten)]
    pub db_args: DbArgs,
    #[clap(flatten)]
    pub cardano_args: CardanoArgs,
    /// PRISM node HTTP server bind address
    #[arg(long, default_value = "0.0.0.0", value_name = "ADDR")]
    pub bind: Ipv4Addr,
    /// PRISM node HTTP server listening port
    #[arg(short, long, default_value_t = 8080)]
    pub port: u16,
}

#[derive(Args)]
pub struct DbArgs {
    /// Database URL (e.g. sqlite://mydata.db)
    #[arg(long = "db", value_name = "DB_URL", default_value = "sqlite::memory:")]
    pub db_url: String,
}

#[derive(Args)]
pub struct CardanoArgs {
    /// Address of the Cardano node to consume events from
    #[arg(
        long = "cardano_addr",
        value_name = "CARDANO_ADDR",
        default_value = "relays-new.cardano-mainnet.iohk.io:3001"
    )]
    pub address: String,
    /// Network config of the connected node
    #[arg(long, default_value = "mainnet")]
    pub network: NetworkIdentifierCliEnum,
}

#[derive(Clone, ValueEnum)]
pub enum NetworkIdentifierCliEnum {
    Mainnet,
    Preprod,
}

impl NetworkIdentifierCliEnum {
    pub fn to_iden(&self) -> NetworkIdentifier {
        match self {
            NetworkIdentifierCliEnum::Mainnet => NetworkIdentifier::Mainnet,
            NetworkIdentifierCliEnum::Preprod => NetworkIdentifier::PreProd,
        }
    }
}

#[derive(Args)]
pub struct SetCursorArgs {
    #[clap(flatten)]
    pub db_args: DbArgs,
    /// Cursor slot
    pub slot: u64,
    /// Cursor block hash in hexadecimal string
    pub blockhash: String,
}
