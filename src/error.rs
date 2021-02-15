
#[derive(Debug, Clone)]
pub enum Error {
    MissingSessionCookie {
        back: String,
    },
}
impl warp::reject::Reject for Error {}

impl Error {
    pub fn into_rejection(self) -> warp::Rejection {
        warp::reject::custom(self)
    }
}

pub(crate) fn missing_cookie(pq: String) -> Error {
    Error::MissingSessionCookie {
        back: pq,
    }
}
