use std::sync::Arc;

use axum::Router;

use crate::data_plane::DataPlane;

pub fn router(_data_plane: Arc<DataPlane>) -> Router {
    unimplemented!("RED: Axum reverse-proxy routes")
}
