//! Scalar functions exposed by the bgp worker.

mod community;
mod path;

use vgi::Worker;

/// Register every scalar function on the worker.
pub fn register(worker: &mut Worker) {
    worker.register_scalar(path::PathLength);
    worker.register_scalar(path::OriginAsn);
    worker.register_scalar(path::AsPathPrepends);
    worker.register_scalar(path::PathContains);
    worker.register_scalar(community::CommunityParse);
    worker.register_scalar(community::IsLargeCommunity);
}
