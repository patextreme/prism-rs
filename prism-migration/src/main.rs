use prism_migration::Migrator;
pub use sea_orm_migration::prelude::*;

#[tokio::main]
async fn main() {
    cli::run_cli(Migrator).await;
}
