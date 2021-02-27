use http::header;
use http::header::InvalidHeaderValue;
use http::HeaderValue;
use std::convert::TryInto;

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

// Helper conversion that allows us to turn auth error into WWW-Authenticate
// header value directly.
impl TryInto<HeaderValue> for &Error {
    type Error = InvalidHeaderValue;

    // This implements https://tools.ietf.org/html/rfc6750#section-3
    fn try_into(self) -> Result<HeaderValue, Self::Error> {
        let v = match self {
            Error::MissingAuthentication { realm, scope, .. } => {
                format!(r#"Bearer realm="{}" scope="{}""#, realm, scopes(scope))
            }
            Error::InvalidToken {
                realm,
                scope,
                description,
            } => format!(
                r#"Bearer realm="{}" scope="{}" error_code="invalid_token" error_description="{}""#,
                realm,
                scopes(scope),
                description
            ),
            Error::InsufficientScope {
                realm,
                scope,
                description,
            } => format!(
                r#"Bearer realm="{}" scope="{}" error_code="insufficient_scope" error_description="{}""#,
                realm,
                scopes(scope),
                description
            ),
        };
        header::HeaderValue::from_str(&v)
    }
}

// Helper function for turning optional scopes list into
// arg to format!() when constructing the redirect URI
fn scopes(scopes: &Option<Vec<String>>) -> String {
    // TODO Try to do this without the clone
    let s = scopes.clone();
    // return "" or scopes="a,b,c"
    s.map_or("".into(), |v| format!(r#"scope="{}""#, v.join(",")))
}
