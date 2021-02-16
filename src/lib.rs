use jsonwebtoken::{Algorithm, decode, DecodingKey, Validation};
use jsonwebtoken::errors::ErrorKind;
use serde::{Deserialize, Serialize};
use warp::cookie;
use warp::Filter;
use std::convert::Infallible;
use error::*;

pub mod error;
pub use error::Error;


#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

pub trait Context {
    fn audience(&self) -> String;
    fn issuer(&self) -> String;
    fn pubkey(&self, kid: &str) -> Vec<u8>;
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
) -> impl Filter<Extract=(T, ), Error=Infallible> + Clone {
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
pub(crate) fn request_path_and_query() -> impl Filter<Extract = (String,), Error = Infallible> + Clone {
    warp::path::full()
        .and(query_params_filter())
        .map(move |full_path: warp::path::FullPath, query: Option<String>| {
            match query {
                Some(s) => format!("{}?{}", full_path.as_str(), &s),
                None => format!("{}", full_path.as_str())
            }
        })
}

// This filter is designed to by the first in the chain to authenticate
// the user.
pub fn authenticate<T:Context + Clone + Send>(
    provider: T,
    cookie_name: &'static str
) -> impl Filter<Extract = (Principal,), Error = warp::Rejection> + Clone {
    warp::any()
        .and(with_one(provider.clone()))
        .and(request_path_and_query())
        .and(cookie::optional(cookie_name))
        .and_then(|provider, path_and_query, maybe_cookie| {
            validate_optional_token(provider, path_and_query, maybe_cookie)
        })
}

async fn validate_optional_token<T:Context + Clone>(
    provider: T,
    request_path_and_query: String,
    maybe_token: Option<String>,
) -> Result<Principal, warp::Rejection>
{
    let mut audiences = std::collections::HashSet::new();
    audiences.insert(provider.audience());
    match maybe_token {
        None => Err(missing_cookie(request_path_and_query).into_rejection()),
        Some(token) => {
            let header = jsonwebtoken::decode_header(&token).unwrap();
            match header.kid {
                None => Err(missing_cookie(request_path_and_query).into_rejection()),
                Some(kid) => {
                    let pubkey = provider.pubkey(&kid);
                    let validation = Validation {
                        aud: Some(audiences),
                        iss: Some(provider.issuer()),
                        algorithms: vec![Algorithm::RS256],
                        ..Validation::default()
                    };
                    let token_data = match decode::<Claims>(
                        &token,
                        &DecodingKey::from_rsa_pem(&pubkey).unwrap(),
                        &validation,
                    ) {
                        Ok(c) => c,
                        // TODO Handle these as redirects to loginor 404 or forbidden
                        Err(err) => match *err.kind() {
                            ErrorKind::InvalidToken => panic!("Token is invalid"), // Example on how to handle a specific error
                            ErrorKind::InvalidIssuer => panic!("Issuer is invalid"), // Example on how to handle a specific error
                            _ => {
                                dbg!(err);
                                panic!("Some other errors")
                            }
                        },
                    };
                    println!("{:?}", token_data.claims);
                    println!("{:?}", token_data.header);
                    Ok(Principal {
                        id: token_data.claims.sub
                    })
                }
            }
        }
    }
}


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
