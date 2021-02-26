#[derive(Debug, Clone)]
pub enum Error {
    MissingAuthentication {
        realm: String,
        back: Option<String>,
        scope: Option<Vec<String>>,
    },
    InvalidToken {
        realm: String,
        scope: Option<Vec<String>>,
        description: String,
    },
    InsufficientScope {
        realm: String,
        scope: Option<Vec<String>>,
        description: String,
    },
}
impl warp::reject::Reject for Error {}

impl Error {
    pub fn into_rejection(self) -> warp::Rejection {
        warp::reject::custom(self)
    }
}
