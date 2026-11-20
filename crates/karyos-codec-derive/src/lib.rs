// SPDX-License-Identifier: Apache-2.0

//! The derive macro of the Karyos message codec (ADR-0036; karyos#661),
//! compile time only: its dependencies (`syn`, `quote`, `proc-macro2`)
//! never reach a runtime graph, which `make codec-derive-check` checks.
//!
//! `#[derive(Message)]` writes, for a struct of fixed fields, the
//! `decode` and `encode` a hand-written message of the `karyos-codec`
//! runtime has:
//!
//! ```text
//! #[derive(Message)]
//! #[message(template = STOP_RECORDING)]
//! pub struct StopRecording {
//!     #[field(offset = 0)]
//!     pub correlation_id: u64,
//!     #[field(offset = 8, check = id)]
//!     pub recording_id: u64,
//! }
//! ```
//!
//! - `template` names the message's `karyos_codec::Template`.
//! - Each field is `u8`, `u16`, `u32`, `u64` or `i32`, at `offset` in the
//!   fixed block.
//! - `check` names a function `fn(&'static str, T) -> Result<T,
//!   CodecError>`, called with the field's name on decode and on encode.
//!
//! The generated `fn decode(block, decoder)` checks that nothing follows
//! the block, then reads every field; `pub fn encode(&self, out)` writes
//! them in declaration order. Variable fields, groups and fields mapped to
//! enums stay hand written for now.

use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::quote;
use syn::{Data, DeriveInput, Fields, Ident, LitInt, Path, Type, parse_macro_input};

/// Derives `decode` and `encode` for a message of fixed fields.
#[proc_macro_derive(Message, attributes(message, field))]
pub fn derive_message(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match expand(&input) {
        Ok(tokens) => tokens.into(),
        Err(error) => error.to_compile_error().into(),
    }
}

/// One fixed field.
struct Field {
    name: Ident,
    /// The `Block` and `Encoder` method of its type.
    method: Ident,
    offset: usize,
    check: Option<Path>,
}

fn expand(input: &DeriveInput) -> syn::Result<proc_macro2::TokenStream> {
    let template = template(input)?;
    let Data::Struct(data) = &input.data else {
        return Err(syn::Error::new_spanned(
            &input.ident,
            "Message derives for a struct only",
        ));
    };
    let Fields::Named(named) = &data.fields else {
        return Err(syn::Error::new_spanned(
            &input.ident,
            "Message derives for named fields only",
        ));
    };
    if !input.generics.params.is_empty() {
        return Err(syn::Error::new_spanned(
            &input.generics,
            "Message derives for a struct without generics",
        ));
    }
    let fields = named
        .named
        .iter()
        .map(field)
        .collect::<syn::Result<Vec<_>>>()?;
    overlaps(&fields)?;
    let ident = &input.ident;
    let reads = fields.iter().map(|field| {
        let Field {
            name,
            method,
            offset,
            check,
        } = field;
        let label = name.to_string();
        let read = quote! { block.#method(#offset)? };
        match check {
            Some(check) => quote! { #name: #check(#label, #read)? },
            None => quote! { #name: #read },
        }
    });
    let writes = fields.iter().map(|field| {
        let Field {
            name,
            method,
            offset,
            check,
        } = field;
        let label = name.to_string();
        let value = match check {
            Some(check) => quote! { #check(#label, self.#name)? },
            None => quote! { self.#name },
        };
        quote! { encoder.#method(#offset, #value)?; }
    });
    let ends = fields.iter().map(|field| {
        let message = format!(
            "field `{}` runs past the template's block length",
            field.name
        );
        let end = field.offset.saturating_add(size(&field.method));
        quote! {
            ::core::assert!(#end <= #template.block_length as usize, #message);
        }
    });
    Ok(quote! {
        // Every field within the block, checked when the crate compiles
        // (karyos#1066).
        const _: () = { #(#ends)* };

        impl #ident {
            fn decode(
                block: ::karyos_codec::Block<'_>,
                decoder: ::karyos_codec::Decoder<'_>,
            ) -> ::core::result::Result<Self, ::karyos_codec::CodecError> {
                decoder.finish()?;
                ::core::result::Result::Ok(Self { #(#reads,)* })
            }

            /// Encodes into `out`; returns the message's length.
            ///
            /// # Errors
            ///
            /// `CodecError::Truncated` when `out` is short, and a field
            /// check's error.
            pub fn encode(
                &self,
                out: &mut [u8],
            ) -> ::core::result::Result<usize, ::karyos_codec::CodecError> {
                let mut encoder = ::karyos_codec::Encoder::new(out, &#template)?;
                #(#writes)*
                encoder.finish()
            }
        }
    })
}

/// The `#[message(template = PATH)]` of `input`.
fn template(input: &DeriveInput) -> syn::Result<Path> {
    let mut template = None;
    for attr in input
        .attrs
        .iter()
        .filter(|attr| attr.path().is_ident("message"))
    {
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("template") {
                template = Some(meta.value()?.parse::<Path>()?);
                Ok(())
            } else {
                Err(meta.error("expected `template = PATH`"))
            }
        })?;
    }
    template
        .ok_or_else(|| syn::Error::new_spanned(&input.ident, "missing #[message(template = PATH)]"))
}

/// A field with its `#[field(offset = N, check = PATH)]`.
fn field(field: &syn::Field) -> syn::Result<Field> {
    let Some(name) = field.ident.clone() else {
        return Err(syn::Error::new_spanned(field, "a named field"));
    };
    let method = method(&field.ty)?;
    let mut offset = None;
    let mut check = None;
    for attr in field
        .attrs
        .iter()
        .filter(|attr| attr.path().is_ident("field"))
    {
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("offset") {
                offset = Some(meta.value()?.parse::<LitInt>()?.base10_parse::<usize>()?);
                Ok(())
            } else if meta.path.is_ident("check") {
                check = Some(meta.value()?.parse::<Path>()?);
                Ok(())
            } else {
                Err(meta.error("expected `offset = N` or `check = PATH`"))
            }
        })?;
    }
    let Some(offset) = offset else {
        return Err(syn::Error::new_spanned(
            &name,
            "missing #[field(offset = N)]",
        ));
    };
    Ok(Field {
        name,
        method,
        offset,
        check,
    })
}

/// The width in bytes of a field read by `method`.
fn size(method: &Ident) -> usize {
    match method.to_string().as_str() {
        "u8" => 1,
        "u16" => 2,
        "u32" | "i32" => 4,
        _ => 8,
    }
}

/// Refuses two fields whose byte ranges overlap, naming both.
fn overlaps(fields: &[Field]) -> syn::Result<()> {
    for (index, first) in fields.iter().enumerate() {
        let first_end = first.offset.saturating_add(size(&first.method));
        for second in fields.iter().skip(index.saturating_add(1)) {
            let second_end = second.offset.saturating_add(size(&second.method));
            if first.offset < second_end && second.offset < first_end {
                return Err(syn::Error::new_spanned(
                    &second.name,
                    format!("fields `{}` and `{}` overlap", first.name, second.name),
                ));
            }
        }
    }
    Ok(())
}

/// The `Block` and `Encoder` method that reads and writes `ty`.
fn method(ty: &Type) -> syn::Result<Ident> {
    const SUPPORTED: [&str; 5] = ["u8", "u16", "u32", "u64", "i32"];
    if let Type::Path(path) = ty
        && path.qself.is_none()
        && let Some(ident) = path.path.get_ident()
        && SUPPORTED.iter().any(|name| ident == name)
    {
        return Ok(Ident::new(&ident.to_string(), Span::call_site()));
    }
    Err(syn::Error::new_spanned(
        ty,
        "a fixed field is u8, u16, u32, u64 or i32",
    ))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests, as ADR-0007 allows")]

    use super::*;

    fn error(input: DeriveInput) -> String {
        match expand(&input) {
            Ok(tokens) => format!("expanded: {tokens}"),
            Err(error) => error.to_string(),
        }
    }

    #[test]
    fn a_message_expands_to_decode_and_encode_in_field_order() {
        let input: DeriveInput = syn::parse_quote! {
            #[message(template = T)]
            struct M {
                #[field(offset = 8, check = id)]
                b: u64,
                #[field(offset = 0)]
                a: i32,
            }
        };
        let tokens = expand(&input).unwrap().to_string();
        let b = tokens
            .find("encoder . u64 (8usize , id (\"b\" , self . b) ?) ?")
            .unwrap();
        let a = tokens.find("encoder . i32 (0usize , self . a) ?").unwrap();
        assert!(b < a, "{tokens}");
        assert!(
            tokens.contains("b : id (\"b\" , block . u64 (8usize) ?) ?"),
            "{tokens}"
        );
        assert!(tokens.contains("Encoder :: new (out , & T)"), "{tokens}");
    }

    #[test]
    fn a_wrong_shape_is_a_compile_error() {
        let cases: [(DeriveInput, &str); 5] = [
            (
                syn::parse_quote! { struct M { #[field(offset = 0)] a: u64 } },
                "missing #[message(template = PATH)]",
            ),
            (
                syn::parse_quote! { #[message(template = T)] struct M { a: u64 } },
                "missing #[field(offset = N)]",
            ),
            (
                syn::parse_quote! {
                    #[message(template = T)] struct M { #[field(offset = 0)] a: i64 }
                },
                "a fixed field is u8, u16, u32, u64 or i32",
            ),
            (
                syn::parse_quote! { #[message(template = T)] enum M { A } },
                "Message derives for a struct only",
            ),
            (
                syn::parse_quote! {
                    #[message(template = T)] struct M { #[field(offset = 0, size = 1)] a: u8 }
                },
                "expected `offset = N` or `check = PATH`",
            ),
        ];
        let overlap: DeriveInput = syn::parse_quote! {
            #[message(template = T)]
            struct M { #[field(offset = 0)] a: u64, #[field(offset = 4)] b: u32 }
        };
        assert_eq!(error(overlap), "fields `a` and `b` overlap");
        for (input, expected) in cases {
            assert_eq!(error(input), expected);
        }
    }
}
