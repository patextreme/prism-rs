use rocket::response::Redirect;
use rocket::{get, uri, State};

use crate::http::response::SsrPage;
use crate::http::views;
use crate::AppState;

#[get("/")]
pub async fn index() -> Redirect {
    let redirect_uri = uri!(resolver(Option::<String>::None));
    Redirect::temporary(redirect_uri)
}

#[get("/resolver?<did>")]
pub async fn resolver(did: Option<String>, state: &State<AppState>) -> SsrPage {
    let network = state.network.clone();
    let result = match did.as_ref() {
        Some(did) => {
            let result = state
                .did_service
                .resolve_did(did)
                .await
                .map_err(|e| e.to_string())
                .map(|(result, debug)| {
                    let debug: Vec<_> = debug
                        .into_iter()
                        .map(|(meta, op, e)| (meta, op, e.map(|e| e.to_string())))
                        .collect();
                    (result, debug)
                });
            Some(result)
        }
        None => None,
    };
    SsrPage(views::resolver::ResolverPage(did, result, network))
}

#[get("/explorer")]
pub async fn explorer(state: &State<AppState>) -> SsrPage {
    let cursor = state.cursor_rx.as_ref().and_then(|rx| rx.borrow().to_owned());
    let dids = state.did_service.get_all_dids().await.unwrap(); // FIXME: unwrap
    let network = state.network.clone();
    SsrPage(views::explorer::ExplorerPage(cursor, dids, network))
}
pub mod hx {
    use rocket::form::Form;
    use rocket::{post, State};

    use crate::http::contract::form::HxRpcForm;
    use crate::http::contract::hx::HxRpc;
    use crate::http::response::SsrComponent;
    use crate::http::views;
    use crate::AppState;

    #[post("/hx/rpc", data = "<form>")]
    pub async fn rpc(form: Form<HxRpcForm>, state: &State<AppState>) -> SsrComponent {
        let rpc = serde_json::from_str::<HxRpc>(&form.rpc).unwrap(); // FIXME: unwrap
        match rpc {
            HxRpc::GetExplorerDltCursor {} => {
                let cursor = state.cursor_rx.as_ref().and_then(|rx| rx.borrow().to_owned());
                SsrComponent(views::explorer::DltCursorStat(views::explorer::DltCursorStatProps {
                    cursor,
                }))
            }
            HxRpc::GetExplorerDidList {} => {
                let dids = state.did_service.get_all_dids().await.unwrap(); // FIXME: unwrap
                SsrComponent(views::explorer::DidList(views::explorer::DidListProps { dids }))
            }
        }
    }
}
