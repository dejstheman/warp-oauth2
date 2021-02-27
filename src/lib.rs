use headers::authorization::Authorization;
use headers::authorization::Bearer;
use headers::Header;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use warp::cookie;
use warp::Filter;

pub mod error;
pub use error::Error;

pub trait Context {
    fn audience(&self) -> String;
    fn issuer(&self) -> String;
    fn pubkey(&self, kid: &str) -> Option<Vec<u8>>;
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

// Abstraction of the subject of the intended operation (the user, the identity)
#[derive(Debug, Clone)]
pub struct Principal {
    pub id: String,
}

/// Takes a T and injects it into the filter chain so it can be
/// used as parameter in map or and_then combined handlers.
pub(crate) fn with_one<T: Clone + Send>(
    t: T,
) -> impl Filter<Extract = (T,), Error = Infallible> + Clone {
    warp::any().map(move || t.clone())
}

type QueryParameters = Option<String>;

/// Warp filter that extracts query parameters from the request, if they exist.
pub(crate) fn query_params_filter(
) -> impl Filter<Extract = (QueryParameters,), Error = std::convert::Infallible> + Clone {
    warp::query::raw()
        .map(Some)
        .or_else(|_| async { Ok::<(QueryParameters,), std::convert::Infallible>((None,)) })
}

/// Helper filter to extract the full request URI for constructing
/// redirects during auth flow. You need to supply scheme and authority
/// as a string in the form https://example.org or https://example.org:443
/// Do not add a trailing slash.
pub(crate) fn request_path_and_query(
) -> impl Filter<Extract = (String,), Error = Infallible> + Clone {
    warp::path::full().and(query_params_filter()).map(
        move |full_path: warp::path::FullPath, query: Option<String>| match query {
            Some(s) => format!("{}?{}", full_path.as_str(), &s),
            None => format!("{}", full_path.as_str()),
        },
    )
}

///
///
/// # Example:
///
/// ```
/// use warp_oauth2::extract_token;
/// let token = extract_token(Some("Bearer abcdefgh".into())).unwrap();
/// assert_eq!(token,"abcdefgh")
/// ```
///
pub fn extract_token(maybe_value: Option<String>) -> Option<String> {
    maybe_value.map(|value| {
        let v = headers::HeaderValue::from_str(&value)
            .expect("TODO try to avoid this by passing in header value");
        let vc = vec![&v];
        let value: Authorization<Bearer> =
            headers::Authorization::decode(&mut vc.into_iter()).unwrap();
        String::from(value.0.token())
    })
}

pub fn authenticate_cookie<T: Context + Clone + Send>(
    provider: T,
    cookie_name: &'static str,
) -> impl Filter<Extract = (Principal,), Error = warp::Rejection> + Clone {
    warp::any()
        .and(with_one(provider.clone()))
        .and(request_path_and_query())
        .and(cookie::optional(cookie_name))
        .and_then(|provider, path_and_query, maybe_cookie| {
            validate(provider, Some(path_and_query), maybe_cookie)
        })
}

pub fn authenticate_bearer<T: Context + Clone + Send>(
    provider: T,
) -> impl Filter<Extract = (Principal,), Error = warp::Rejection> + Clone {
    warp::any()
        .and(warp::header::optional("authorization"))
        .map(extract_token)
        .and(with_one(provider.clone()))
        .and_then(|maybe_token: Option<String>, provider: T| validate(provider, None, maybe_token))
}

async fn validate<T: Context + Clone>(
    provider: T,
    request_path_and_query: Option<String>,
    maybe_token: Option<String>,
) -> Result<Principal, warp::Rejection> {
    let mut audiences = std::collections::HashSet::new();
    audiences.insert(provider.audience());
    let validation = Validation {
        aud: Some(audiences),
        iss: Some(provider.issuer()),
        algorithms: vec![Algorithm::RS256],
        ..Validation::default()
    };
    match maybe_token {
        None => Err(error::missing_authentication(
            "aply".into(),
            request_path_and_query,
            None,
        )),
        Some(token) => {
            let header = jsonwebtoken::decode_header(&token).expect("TODO");
            match header.kid {
                None => {
                    // TODO wrong error
                    Err(error::missing_authentication(
                        "aply".into(),
                        request_path_and_query,
                        None,
                    ))
                }
                Some(kid) => {
                    let pubkey = provider.pubkey(&kid).expect("TODO");
                    match decode::<Claims>(
                        &token,
                        &DecodingKey::from_rsa_pem(&pubkey).unwrap(),
                        &validation,
                    ) {
                        Ok(tokdat) => Ok(Principal {
                            id: tokdat.claims.sub,
                        }),
                        Err(err) => Err(error::invalid_token(
                            "aply".into(),
                            request_path_and_query,
                            None,
                            err.to_string(),
                        )),
                    }
                }
            }
        }
    }
}

// #[cfg(test)]
// mod tests {
//     #[test]
//     fn it_works() {
//         assert_eq!(2 + 3, 4);
//     }
// }
