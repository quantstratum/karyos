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
//! them in declaration order. Also (karyos#1029): one lifetime; a
//! variable field `#[field(var, min = EXPR, max = EXPR)]` of type `&str`
//! or `&[u8]`, read and written after the block in declaration order; a
//! field of any type `#[field(offset = N, width = N, with = PATH)]`
//! through `PATH::read(&block, offset)` and `PATH::write(&mut encoder,
//! offset, &value)`; and a message check `#[message(check = PATH)]`,
//! `fn(&Self) -> Result<(), CodecError>`, after decoding and before
//! encoding. Also (karyos#1104): a field tied across several block
//! ranges, `#[field(with = PATH, spans = [(OFFSET, WIDTH), ...])]`,
//! through `PATH::read(&block)` and `PATH::write(&mut encoder, &value)`:
//! one value whose bytes sit at offsets that are not adjacent (a mode and
//! its on-lap byte, a sync policy and its interval). Also (karyos#1104,
//! the group records): a tied field's `PATH::write(&mut encoder, self)`
//! takes the whole message, so two fields that share a byte (a flags
//! byte) are written together; a variable tied field `#[field(with =
//! PATH, spans = [...], var)]` (its spans may be empty), read through
//! `PATH::read(&block, &mut decoder)` and written through
//! `PATH::write(&mut encoder, self)` in the variable fields' order; a
//! versioned message `#[message(versioned)]` whose `decode` takes `v2:
//! bool` and whose fields `#[field(offset = N, since = 2)]` read as their
//! default from a version 1 block; and reserved bytes `#[message(zero =
//! [(OFFSET, WIDTH), ...])]`, refused unless zero on decode and left zero
//! on encode. A block several templates share takes `#[message(templates =
//! [PATH, ...])]` in place of `template`: its fields are checked against
//! every one, and its `encode(&self, out, template)` (crate visible) takes
//! the template the caller encodes.

use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::quote;
use syn::{
    Data, DeriveInput, Expr, Fields, GenericParam, Ident, LitInt, Path, Type, parse_macro_input,
};

/// Derives `decode` and `encode` for a codec message.
#[proc_macro_derive(Message, attributes(message, field))]
pub fn derive_message(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match expand(&input) {
        Ok(tokens) => tokens.into(),
        Err(error) => error.to_compile_error().into(),
    }
}

/// How one field is read and written.
enum Kind {
    /// An integer at `offset`, through the `Block` and `Encoder` method of
    /// its type, with an optional `check`.
    Fixed {
        method: Ident,
        offset: usize,
        check: Option<Path>,
        /// Read only from a version 2 block (`since = 2`), else its
        /// default (karyos#1104).
        since: bool,
    },
    /// Any type at `offset`, `width` bytes wide, through
    /// `with::read(&block, offset)` and `with::write(&mut encoder, offset,
    /// &value)` (karyos#1029).
    With {
        with: Path,
        offset: usize,
        width: usize,
    },
    /// Any type over several block ranges `spans` (offset, width), through
    /// `with::read(&block)` and `with::write(&mut encoder, self)`, the
    /// whole message (karyos#1104).
    Tied {
        with: Path,
        spans: Vec<(usize, usize)>,
    },
    /// Any type over the block ranges `spans` (none or more) and the
    /// variable data, through `with::read(&block, &mut decoder)` and
    /// `with::write(&mut encoder, self)`, in the variable fields' order
    /// (karyos#1104).
    TiedVar {
        with: Path,
        spans: Vec<(usize, usize)>,
    },
    /// A variable field, `min` to `max` bytes, text (`&str`) or bytes
    /// (`&[u8]`), in declaration order after the block (karyos#1029).
    Var {
        min: Box<Expr>,
        max: Box<Expr>,
        text: bool,
    },
}

/// One field.
struct Field {
    name: Ident,
    kind: Kind,
}

impl Field {
    /// The block ranges it takes: none for a variable field.
    fn spans(&self) -> Vec<(usize, usize)> {
        match &self.kind {
            Kind::Fixed { method, offset, .. } => {
                vec![(*offset, offset.saturating_add(size(method)))]
            }
            Kind::With { offset, width, .. } => vec![(*offset, offset.saturating_add(*width))],
            Kind::Tied { spans, .. } | Kind::TiedVar { spans, .. } => spans
                .iter()
                .map(|(offset, width)| (*offset, offset.saturating_add(*width)))
                .collect(),
            Kind::Var { .. } => Vec::new(),
        }
    }

    /// Whether it reads from the variable data.
    const fn reads_var(&self) -> bool {
        matches!(self.kind, Kind::Var { .. } | Kind::TiedVar { .. })
    }
}

/// The `#[message(...)]` of a struct.
struct Message {
    /// The template, or the templates a shared block serves.
    templates: Vec<Path>,
    /// Whether `encode` takes the template (`templates = [...]`).
    shared: bool,
    check: Option<Path>,
    /// Its `decode` takes `v2: bool` (karyos#1104).
    versioned: bool,
    /// Reserved block ranges, zero (karyos#1104).
    zero: Vec<(usize, usize)>,
}

fn expand(input: &DeriveInput) -> syn::Result<proc_macro2::TokenStream> {
    let Message {
        templates,
        shared,
        check,
        versioned,
        zero,
    } = message(input)?;
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
    // One lifetime at most, which the variable fields borrow.
    let mut lifetime = None;
    for param in &input.generics.params {
        match param {
            GenericParam::Lifetime(param) if lifetime.is_none() => {
                lifetime = Some(param.lifetime.clone());
            }
            _ => {
                return Err(syn::Error::new_spanned(
                    &input.generics,
                    "Message derives for a struct with at most one lifetime",
                ));
            }
        }
    }
    let fields = named
        .named
        .iter()
        .map(field)
        .collect::<syn::Result<Vec<_>>>()?;
    if !versioned
        && let Some(field) = fields
            .iter()
            .find(|field| matches!(field.kind, Kind::Fixed { since: true, .. }))
    {
        return Err(syn::Error::new_spanned(
            &field.name,
            "a field with `since` needs #[message(versioned)]",
        ));
    }
    overlaps(&fields, &zero)?;
    let ident = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    let input_lifetime = lifetime.map_or_else(|| quote! { '_ }, |lifetime| quote! { #lifetime });
    let vars = fields.iter().filter_map(|field| {
        let name = &field.name;
        let label = name.to_string();
        match &field.kind {
            Kind::Var { min, max, text } => Some(if *text {
                quote! { let #name = decoder.str(#label, #min, #max)?; }
            } else {
                quote! { let #name = decoder.bytes(#label, #min, #max)?; }
            }),
            Kind::TiedVar { with, .. } => {
                Some(quote! { let #name = #with::read(&block, &mut decoder)?; })
            }
            _ => None,
        }
    });
    let v2_read = Ident::new("__karyos_v2", Span::mixed_site());
    let reads = fields.iter().map(|field| {
        let name = &field.name;
        let label = name.to_string();
        match &field.kind {
            Kind::Fixed {
                method,
                offset,
                check,
                since,
            } => {
                let read = match check {
                    Some(check) => quote! { #check(#label, block.#method(#offset)?)? },
                    None => quote! { block.#method(#offset)? },
                };
                if *since {
                    quote! {
                        #name: if #v2_read { #read } else { ::core::default::Default::default() }
                    }
                } else {
                    quote! { #name: #read }
                }
            }
            Kind::With { with, offset, .. } => quote! { #name: #with::read(&block, #offset)? },
            Kind::Tied { with, .. } => quote! { #name: #with::read(&block)? },
            Kind::Var { .. } | Kind::TiedVar { .. } => quote! { #name },
        }
    });
    let writes = fields.iter().map(|field| {
        let name = &field.name;
        let label = name.to_string();
        match &field.kind {
            Kind::Fixed {
                method,
                offset,
                check,
                ..
            } => {
                let value = match check {
                    Some(check) => quote! { #check(#label, self.#name)? },
                    None => quote! { self.#name },
                };
                quote! { encoder.#method(#offset, #value)?; }
            }
            Kind::With { with, offset, .. } => {
                quote! { #with::write(&mut encoder, #offset, &self.#name)?; }
            }
            Kind::Tied { with, .. } => quote! { #with::write(&mut encoder, self)?; },
            Kind::Var { .. } | Kind::TiedVar { .. } => quote! {},
        }
    });
    let var_writes = fields.iter().filter_map(|field| match &field.kind {
        Kind::Var { min, max, text } => {
            let name = &field.name;
            let label = name.to_string();
            let value = if *text {
                quote! { self.#name.as_bytes() }
            } else {
                quote! { self.#name }
            };
            Some(quote! { encoder.bytes(#label, #min, #max, #value)?; })
        }
        Kind::TiedVar { with, .. } => Some(quote! { #with::write(&mut encoder, self)?; }),
        _ => None,
    });
    let ends = fields.iter().flat_map(|field| {
        let message = format!(
            "field `{}` runs past the template's block length",
            field.name
        );
        let templates = &templates;
        field
            .spans()
            .into_iter()
            .flat_map(move |(_, end)| {
                let message = message.clone();
                templates.iter().map(move |template| {
                    quote! {
                        ::core::assert!(#end <= #template.block_length as usize, #message);
                    }
                })
            })
            .collect::<Vec<_>>()
    });
    let zero_ends = zero.iter().flat_map(|(offset, width)| {
        let end = offset.saturating_add(*width);
        templates.iter().map(move |template| {
            quote! {
                ::core::assert!(
                    #end <= #template.block_length as usize,
                    "a reserved range runs past the template's block length"
                );
            }
        })
    });
    // One template, or the one the caller passes for a shared block.
    let (encode_head, encode_template) = match (shared, templates.first()) {
        (false, Some(template)) => (
            quote! {
                /// Encodes into `out`; returns the message's length.
                ///
                /// # Errors
                ///
                /// `CodecError::Truncated` when `out` is short, and a field's
                /// or the message's check error.
                pub fn encode(
                    &self,
                    out: &mut [u8],
                ) -> ::core::result::Result<usize, ::karyos_codec::CodecError>
            },
            quote! { &#template },
        ),
        _ => (
            quote! {
                /// Encodes into `out` as `template`, one of the templates
                /// the block serves; returns the message's length.
                ///
                /// # Errors
                ///
                /// `CodecError::Truncated` when `out` is short, and a field's
                /// or the message's check error.
                pub(crate) fn encode(
                    &self,
                    out: &mut [u8],
                    template: &::karyos_codec::Template,
                ) -> ::core::result::Result<usize, ::karyos_codec::CodecError>
            },
            quote! { template },
        ),
    };
    // Each reserved byte zero, refused otherwise (karyos#1104).
    let zero_checks = zero.iter().map(|(offset, width)| {
        let end = offset.saturating_add(*width);
        quote! {
            for at in #offset..#end {
                if block.u8(at)? != 0 {
                    return ::core::result::Result::Err(
                        ::karyos_codec::CodecError::ValueOutOfRange { field: "reserved" },
                    );
                }
            }
        }
    });
    // Hygienic, so no field named `v2` shadows it (karyos#1104).
    let v2 = Ident::new("__karyos_v2", Span::mixed_site());
    let version = if versioned {
        quote! { #v2: bool, }
    } else {
        quote! {}
    };
    // A versioned message with no versioned field still takes `v2`.
    let version_used = if versioned
        && !fields
            .iter()
            .any(|field| matches!(field.kind, Kind::Fixed { since: true, .. }))
    {
        quote! { let _ = #v2; }
    } else {
        quote! {}
    };
    // `mut` only when a variable field reads from the decoder.
    let decoder_binding = if fields.iter().any(Field::reads_var) {
        quote! { mut decoder }
    } else {
        quote! { decoder }
    };
    let (decode_check, encode_check) = match &check {
        Some(check) => (quote! { #check(&message)?; }, quote! { #check(self)?; }),
        None => (quote! {}, quote! {}),
    };
    Ok(quote! {
        // Every field within the block, checked when the crate compiles
        // (karyos#1066).
        const _: () = { #(#ends)* #(#zero_ends)* };

        impl #impl_generics #ident #ty_generics #where_clause {
            fn decode(
                block: ::karyos_codec::Block<#input_lifetime>,
                #decoder_binding: ::karyos_codec::Decoder<#input_lifetime>,
                #version
            ) -> ::core::result::Result<Self, ::karyos_codec::CodecError> {
                #version_used
                #(#vars)*
                decoder.finish()?;
                #(#zero_checks)*
                let message = Self { #(#reads,)* };
                #decode_check
                ::core::result::Result::Ok(message)
            }

            #encode_head {
                let mut encoder = ::karyos_codec::Encoder::new(out, #encode_template)?;
                #encode_check
                #(#writes)*
                #(#var_writes)*
                encoder.finish()
            }
        }
    })
}

/// The `#[message(template = PATH, check = PATH)]` of `input`.
fn message(input: &DeriveInput) -> syn::Result<Message> {
    let mut template = None;
    let mut shared: Option<Vec<Path>> = None;
    let mut check = None;
    let mut versioned = false;
    let mut zero = None;
    for attr in input
        .attrs
        .iter()
        .filter(|attr| attr.path().is_ident("message"))
    {
        attr.parse_nested_meta(|meta| {
            // An option given twice is refused: the second would replace
            // the first (karyos#1104).
            let once = |taken: bool| {
                if taken {
                    Err(meta.error("a message option given twice"))
                } else {
                    Ok(())
                }
            };
            if meta.path.is_ident("template") {
                once(template.is_some())?;
                template = Some(meta.value()?.parse::<Path>()?);
                Ok(())
            } else if meta.path.is_ident("check") {
                once(check.is_some())?;
                check = Some(meta.value()?.parse::<Path>()?);
                Ok(())
            } else if meta.path.is_ident("templates") {
                once(shared.is_some())?;
                let value = meta.value()?;
                let list;
                syn::bracketed!(list in value);
                let paths = list.parse_terminated(Path::parse_mod_style, syn::Token![,])?;
                shared = Some(paths.into_iter().collect());
                Ok(())
            } else if meta.path.is_ident("versioned") {
                once(versioned)?;
                versioned = true;
                Ok(())
            } else if meta.path.is_ident("zero") {
                once(zero.is_some())?;
                zero = Some(parse_spans(meta.value()?)?);
                Ok(())
            } else {
                Err(meta.error(
                    "expected `template = PATH`, `templates = [PATH, ...]`, `check = PATH`, `versioned` or `zero = [(N, N), ...]`",
                ))
            }
        })?;
    }
    let (templates, shared) = match (template, shared) {
        (Some(template), None) => (vec![template], false),
        (None, Some(templates)) if !templates.is_empty() => (templates, true),
        (None, None) => {
            return Err(syn::Error::new_spanned(
                &input.ident,
                "missing #[message(template = PATH)]",
            ));
        }
        _ => {
            return Err(syn::Error::new_spanned(
                &input.ident,
                "#[message] takes `template = PATH` or `templates = [PATH, ...]`, one of them",
            ));
        }
    };
    Ok(Message {
        templates,
        shared,
        check,
        versioned,
        zero: zero.unwrap_or_default(),
    })
}

/// Whether `ty` is `&str` (`Some(true)`) or `&[u8]` (`Some(false)`).
fn borrowed(ty: &Type) -> Option<bool> {
    let Type::Reference(reference) = ty else {
        return None;
    };
    match &*reference.elem {
        Type::Path(path) if path.path.is_ident("str") => Some(true),
        Type::Slice(slice) => match &*slice.elem {
            Type::Path(path) if path.path.is_ident("u8") => Some(false),
            _ => None,
        },
        _ => None,
    }
}

/// A field with its `#[field(...)]`.
fn field(field: &syn::Field) -> syn::Result<Field> {
    let Some(name) = field.ident.clone() else {
        return Err(syn::Error::new_spanned(field, "a named field"));
    };
    let (mut offset, mut check, mut with, mut width) = (None, None, None, None);
    let mut spans: Option<Vec<(usize, usize)>> = None;
    let (mut var, mut min, mut max) = (false, None, None);
    let mut since = None;
    for attr in field
        .attrs
        .iter()
        .filter(|attr| attr.path().is_ident("field"))
    {
        attr.parse_nested_meta(|meta| {
            // An option given twice is refused: the second would replace
            // the first, and skip its checks (karyos#1104).
            let once = |taken: bool| {
                if taken {
                    Err(meta.error("an option given twice"))
                } else {
                    Ok(())
                }
            };
            if meta.path.is_ident("offset") {
                once(offset.is_some())?;
                offset = Some(meta.value()?.parse::<LitInt>()?.base10_parse::<usize>()?);
            } else if meta.path.is_ident("check") {
                once(check.is_some())?;
                check = Some(meta.value()?.parse::<Path>()?);
            } else if meta.path.is_ident("with") {
                once(with.is_some())?;
                with = Some(meta.value()?.parse::<Path>()?);
            } else if meta.path.is_ident("width") {
                once(width.is_some())?;
                width = Some(meta.value()?.parse::<LitInt>()?.base10_parse::<usize>()?);
            } else if meta.path.is_ident("spans") {
                once(spans.is_some())?;
                spans = Some(parse_spans(meta.value()?)?);
            } else if meta.path.is_ident("var") {
                once(var)?;
                var = true;
            } else if meta.path.is_ident("min") {
                once(min.is_some())?;
                min = Some(meta.value()?.parse::<Expr>()?);
            } else if meta.path.is_ident("max") {
                once(max.is_some())?;
                max = Some(meta.value()?.parse::<Expr>()?);
            } else if meta.path.is_ident("since") {
                once(since.is_some())?;
                let version = meta.value()?.parse::<LitInt>()?;
                if version.base10_parse::<u16>()? != 2 {
                    return Err(syn::Error::new(version.span(), "`since = 2`, the only later version"));
                }
                since = Some(());
            } else {
                return Err(meta.error(
                    "expected `offset = N`, `check = PATH`, `with = PATH`, `width = N`, `spans = [(N, N), ...]`, `var`, `min = EXPR`, `max = EXPR` or `since = 2`",
                ));
            }
            Ok(())
        })?;
    }
    // Every option belongs to one kind: one that kind does not read is
    // refused, never dropped (karyos#1104).
    if since.is_some() && (var || with.is_some() || spans.is_some()) {
        return Err(syn::Error::new_spanned(
            &name,
            "`since` belongs to a fixed field",
        ));
    }
    if var && let Some(with) = with {
        if offset.is_some() || check.is_some() || width.is_some() || min.is_some() || max.is_some()
        {
            return Err(syn::Error::new_spanned(
                &name,
                "a variable tied field takes `with`, `spans` and `var` only: its module checks its value",
            ));
        }
        return Ok(Field {
            name,
            kind: Kind::TiedVar {
                with,
                spans: spans.unwrap_or_default(),
            },
        });
    }
    if var {
        if offset.is_some()
            || check.is_some()
            || with.is_some()
            || width.is_some()
            || spans.is_some()
        {
            return Err(syn::Error::new_spanned(
                &name,
                "a variable field takes `var`, `min` and `max` only",
            ));
        }
        let Some(text) = borrowed(&field.ty) else {
            return Err(syn::Error::new_spanned(
                &field.ty,
                "a variable field is &str or &[u8]",
            ));
        };
        let (Some(min), Some(max)) = (min, max) else {
            return Err(syn::Error::new_spanned(
                &name,
                "a variable field needs `min` and `max`",
            ));
        };
        return Ok(Field {
            name,
            kind: Kind::Var {
                min: Box::new(min),
                max: Box::new(max),
                text,
            },
        });
    }
    if let Some(spans) = spans {
        let Some(with) = with else {
            return Err(syn::Error::new_spanned(
                &name,
                "a field with `spans` needs `with = PATH`",
            ));
        };
        if offset.is_some()
            || width.is_some()
            || check.is_some()
            || min.is_some()
            || max.is_some()
            || spans.is_empty()
        {
            return Err(syn::Error::new_spanned(
                &name,
                "a tied field takes `with` and one or more `spans` only: its module checks its value",
            ));
        }
        return Ok(Field {
            name,
            kind: Kind::Tied { with, spans },
        });
    }
    let Some(offset) = offset else {
        return Err(syn::Error::new_spanned(
            &name,
            "missing #[field(offset = N)]",
        ));
    };
    if min.is_some() || max.is_some() {
        return Err(syn::Error::new_spanned(
            &name,
            "`min` and `max` belong to a variable field",
        ));
    }
    if let Some(with) = with {
        if check.is_some() {
            return Err(syn::Error::new_spanned(
                &name,
                "a `with` field takes no `check`: its module checks its value",
            ));
        }
        let Some(width) = width else {
            return Err(syn::Error::new_spanned(
                &name,
                "a `with` field needs `width = N`",
            ));
        };
        return Ok(Field {
            name,
            kind: Kind::With {
                with,
                offset,
                width,
            },
        });
    }
    Ok(Field {
        name,
        kind: Kind::Fixed {
            method: method(&field.ty)?,
            offset,
            check,
            since: since.is_some(),
        },
    })
}

/// The `[(OFFSET, WIDTH), ...]` of a tied field, parsed without syn's
/// `full` feature.
fn parse_spans(input: syn::parse::ParseStream<'_>) -> syn::Result<Vec<(usize, usize)>> {
    let list;
    syn::bracketed!(list in input);
    let mut spans = Vec::new();
    while !list.is_empty() {
        let pair;
        let parens = syn::parenthesized!(pair in list);
        let offset = pair.parse::<LitInt>()?.base10_parse::<usize>()?;
        pair.parse::<syn::Token![,]>()?;
        let width = pair.parse::<LitInt>()?.base10_parse::<usize>()?;
        if !pair.is_empty() || width == 0 {
            return Err(syn::Error::new(
                parens.span.join(),
                "a span is `(OFFSET, WIDTH)`, WIDTH > 0",
            ));
        }
        spans.push((offset, width));
        if list.is_empty() {
            break;
        }
        list.parse::<syn::Token![,]>()?;
    }
    Ok(spans)
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

/// Refuses two fields whose byte ranges overlap, naming both, and a field
/// over a reserved range.
fn overlaps(fields: &[Field], zero: &[(usize, usize)]) -> syn::Result<()> {
    let mut taken: Vec<(usize, usize, &Ident)> = Vec::new();
    for field in fields {
        for (start, end) in field.spans() {
            if zero
                .iter()
                .any(|(offset, width)| start < offset.saturating_add(*width) && *offset < end)
            {
                return Err(syn::Error::new_spanned(
                    &field.name,
                    format!("field `{}` overlaps a reserved range", field.name),
                ));
            }
        }
    }
    for field in fields {
        for (start, end) in field.spans() {
            if let Some((_, _, first)) = taken
                .iter()
                .find(|(taken_start, taken_end, _)| start < *taken_end && *taken_start < end)
            {
                return Err(syn::Error::new_spanned(
                    &field.name,
                    if **first == field.name {
                        format!("field `{}`'s spans overlap", field.name)
                    } else {
                        format!("fields `{first}` and `{}` overlap", field.name)
                    },
                ));
            }
            taken.push((start, end, &field.name));
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

    /// karyos#1029: a lifetime, a `with` field, a variable field and a
    /// message check.
    #[test]
    fn a_message_with_variable_and_with_fields_expands() {
        let input: DeriveInput = syn::parse_quote! {
            #[message(template = T, check = Self::check)]
            struct M<'a> {
                #[field(offset = 0, width = 1, with = codes)]
                code: Code,
                #[field(var, min = 0, max = 16)]
                text: &'a str,
                #[field(var, min = 1, max = 4)]
                raw: &'a [u8],
            }
        };
        let tokens = expand(&input).unwrap().to_string();
        for part in [
            "impl < 'a > M < 'a >",
            "Block < 'a >",
            "mut decoder",
            "let text = decoder . str (\"text\" , 0 , 16) ?",
            "let raw = decoder . bytes (\"raw\" , 1 , 4) ?",
            "code : codes :: read (& block , 0usize) ?",
            "Self :: check (& message) ?",
            "encoder . bytes (\"text\" , 0 , 16 , self . text . as_bytes ()) ?",
        ] {
            assert!(tokens.contains(part), "{part}: {tokens}");
        }
        let bad: DeriveInput = syn::parse_quote! {
            #[message(template = T)]
            struct M { #[field(var, min = 0, max = 1)] a: u64 }
        };
        assert_eq!(error(bad), "a variable field is &str or &[u8]");
        let no_width: DeriveInput = syn::parse_quote! {
            #[message(template = T)]
            struct M { #[field(offset = 0, with = codes)] a: Code }
        };
        assert_eq!(error(no_width), "a `with` field needs `width = N`");
    }

    /// karyos#1104: a field tied across ranges that are not adjacent.
    #[test]
    fn a_tied_field_reads_and_writes_through_its_module() {
        let input: DeriveInput = syn::parse_quote! {
            #[message(template = T)]
            struct M {
                #[field(offset = 0)]
                a: u64,
                #[field(with = policy, spans = [(8, 8), (16, 1)])]
                p: Policy,
            }
        };
        let tokens = expand(&input).unwrap().to_string();
        for part in [
            "p : policy :: read (& block) ?",
            "policy :: write (& mut encoder , self) ?",
            "16usize <= T . block_length",
            "17usize <= T . block_length",
        ] {
            assert!(tokens.contains(part), "{part}: {tokens}");
        }
        let no_with: DeriveInput = syn::parse_quote! {
            #[message(template = T)]
            struct M { #[field(spans = [(0, 1)])] a: A }
        };
        assert_eq!(error(no_with), "a field with `spans` needs `with = PATH`");
        let with_offset: DeriveInput = syn::parse_quote! {
            #[message(template = T)]
            struct M { #[field(offset = 0, with = t, spans = [(0, 1)])] a: A }
        };
        assert_eq!(
            error(with_offset),
            "a tied field takes `with` and one or more `spans` only: its module checks its value"
        );
        // An option the field's kind does not read is refused, not dropped.
        let tied_check: DeriveInput = syn::parse_quote! {
            #[message(template = T)]
            struct M { #[field(with = t, spans = [(0, 1)], check = c)] a: A }
        };
        assert_eq!(
            error(tied_check),
            "a tied field takes `with` and one or more `spans` only: its module checks its value"
        );
        let var_spans: DeriveInput = syn::parse_quote! {
            #[message(template = T)]
            struct M { #[field(var, min = 0, max = 4, spans = [(0, 1)])] a: &'a [u8] }
        };
        assert_eq!(
            error(var_spans),
            "a variable field takes `var`, `min` and `max` only"
        );
        let var_check: DeriveInput = syn::parse_quote! {
            #[message(template = T)]
            struct M { #[field(var, min = 0, max = 4, check = c)] a: &'a [u8] }
        };
        assert_eq!(
            error(var_check),
            "a variable field takes `var`, `min` and `max` only"
        );
        let with_check: DeriveInput = syn::parse_quote! {
            #[message(template = T)]
            struct M { #[field(offset = 0, with = t, width = 4, check = c)] a: A }
        };
        assert_eq!(
            error(with_check),
            "a `with` field takes no `check`: its module checks its value"
        );
        let fixed_max: DeriveInput = syn::parse_quote! {
            #[message(template = T)]
            struct M { #[field(offset = 0, max = 4)] a: u32 }
        };
        assert_eq!(
            error(fixed_max),
            "`min` and `max` belong to a variable field"
        );
        // An option given twice, in one attribute or two, is refused.
        let twice: DeriveInput = syn::parse_quote! {
            #[message(template = T)]
            struct M { #[field(with = t, spans = [(0, 1)], spans = [(0, 4), (2, 1)])] a: A }
        };
        assert_eq!(error(twice), "an option given twice");
        let twice_apart: DeriveInput = syn::parse_quote! {
            #[message(template = T)]
            struct M {
                #[field(with = t, spans = [(0, 1)])]
                #[field(spans = [(64, 1)])]
                a: A,
            }
        };
        assert_eq!(error(twice_apart), "an option given twice");
        let self_overlap: DeriveInput = syn::parse_quote! {
            #[message(template = T)]
            struct M { #[field(with = t, spans = [(0, 4), (2, 1)])] a: A }
        };
        assert_eq!(error(self_overlap), "field `a`'s spans overlap");
    }

    /// karyos#1104: a variable tied field reads with the decoder in the
    /// variable fields' order and writes with the message.
    #[test]
    fn a_variable_tied_field_reads_with_the_decoder_in_order() {
        let input: DeriveInput = syn::parse_quote! {
            #[message(template = T)]
            struct M<'a> {
                #[field(offset = 0)]
                a: u64,
                #[field(with = payload, spans = [(8, 4)], var)]
                p: Payload<'a>,
                #[field(with = extension, var)]
                e: Option<&'a [u8; 4]>,
            }
        };
        let tokens = expand(&input).unwrap().to_string();
        let p = tokens
            .find("let p = payload :: read (& block , & mut decoder) ?")
            .unwrap();
        let e = tokens
            .find("let e = extension :: read (& block , & mut decoder) ?")
            .unwrap();
        assert!(p < e, "{tokens}");
        let pw = tokens
            .find("payload :: write (& mut encoder , self) ?")
            .unwrap();
        let ew = tokens
            .find("extension :: write (& mut encoder , self) ?")
            .unwrap();
        assert!(pw < ew, "{tokens}");
        assert!(tokens.contains("mut decoder"), "{tokens}");
        assert!(tokens.contains("12usize <= T . block_length"), "{tokens}");
        let with_offset: DeriveInput = syn::parse_quote! {
            #[message(template = T)]
            struct M<'a> { #[field(with = p, var, offset = 0)] a: A<'a> }
        };
        assert_eq!(
            error(with_offset),
            "a variable tied field takes `with`, `spans` and `var` only: its module checks its value"
        );
    }

    /// karyos#1104: a versioned message's decode takes `v2`, and a field
    /// `since = 2` reads its default from a version 1 block.
    #[test]
    fn a_versioned_field_reads_its_default_before_version_2() {
        let input: DeriveInput = syn::parse_quote! {
            #[message(template = T, versioned)]
            struct M {
                #[field(offset = 0)]
                a: u64,
                #[field(offset = 8, since = 2)]
                image: u64,
            }
        };
        let tokens = expand(&input).unwrap().to_string();
        for part in [
            "__karyos_v2 : bool ,",
            "image : if __karyos_v2 { block . u64 (8usize) ? } else { :: core :: default :: Default :: default () }",
            "encoder . u64 (8usize , self . image) ?",
        ] {
            assert!(tokens.contains(part), "{part}: {tokens}");
        }
        let plain: DeriveInput = syn::parse_quote! {
            #[message(template = T, versioned)]
            struct M { #[field(offset = 0)] a: u64 }
        };
        assert!(
            expand(&plain)
                .unwrap()
                .to_string()
                .contains("let _ = __karyos_v2 ;")
        );
        // A field named `v2` does not shadow the version: the generated
        // parameter is hygienic, and the field reads as any other.
        let named: DeriveInput = syn::parse_quote! {
            #[message(template = T, versioned)]
            struct M<'a> {
                #[field(var, min = 0, max = 4)]
                v2: &'a [u8],
                #[field(offset = 0, since = 2)]
                image: u64,
            }
        };
        let tokens = expand(&named).unwrap().to_string();
        assert!(tokens.contains("let v2 = decoder . bytes"), "{tokens}");
        assert!(tokens.contains("image : if __karyos_v2 {"), "{tokens}");
        let unversioned: DeriveInput = syn::parse_quote! {
            #[message(template = T)]
            struct M { #[field(offset = 0, since = 2)] a: u64 }
        };
        assert_eq!(
            error(unversioned),
            "a field with `since` needs #[message(versioned)]"
        );
        let three: DeriveInput = syn::parse_quote! {
            #[message(template = T, versioned)]
            struct M { #[field(offset = 0, since = 3)] a: u64 }
        };
        assert_eq!(error(three), "`since = 2`, the only later version");
        let tied: DeriveInput = syn::parse_quote! {
            #[message(template = T, versioned)]
            struct M { #[field(with = t, spans = [(0, 1)], since = 2)] a: A }
        };
        assert_eq!(error(tied), "`since` belongs to a fixed field");
    }

    /// karyos#1104: reserved ranges are refused unless zero, checked
    /// against the block length, and no field may cover them.
    #[test]
    fn a_reserved_range_is_checked_zero_and_kept_free() {
        let input: DeriveInput = syn::parse_quote! {
            #[message(template = T, zero = [(8, 4)])]
            struct M { #[field(offset = 0)] a: u64 }
        };
        let tokens = expand(&input).unwrap().to_string();
        for part in [
            "for at in 8usize .. 12usize",
            "ValueOutOfRange { field : \"reserved\" }",
            "12usize <= T . block_length",
        ] {
            assert!(tokens.contains(part), "{part}: {tokens}");
        }
        let covered: DeriveInput = syn::parse_quote! {
            #[message(template = T, zero = [(4, 4)])]
            struct M { #[field(offset = 0)] a: u64 }
        };
        assert_eq!(error(covered), "field `a` overlaps a reserved range");
        // A second `zero` would replace the first: refused, as is any
        // message option given twice.
        for twice in [
            syn::parse_quote! {
                #[message(template = T, zero = [(8, 4)], zero = [(0, 1)])]
                struct M { #[field(offset = 0)] a: u8 }
            },
            syn::parse_quote! {
                #[message(template = T)]
                #[message(template = U)]
                struct M { #[field(offset = 0)] a: u8 }
            },
            syn::parse_quote! {
                #[message(template = T, versioned, versioned)]
                struct M { #[field(offset = 0)] a: u8 }
            },
        ] {
            assert_eq!(error(twice), "a message option given twice");
        }
        let unknown: DeriveInput = syn::parse_quote! {
            #[message(template = T, zeros = [(4, 4)])]
            struct M { #[field(offset = 0)] a: u64 }
        };
        assert_eq!(
            error(unknown),
            "expected `template = PATH`, `templates = [PATH, ...]`, `check = PATH`, `versioned` or `zero = [(N, N), ...]`"
        );
    }

    /// karyos#1104: a block several templates share is checked against
    /// each, and encodes as the template its caller passes.
    #[test]
    fn a_shared_block_encodes_as_the_template_passed() {
        let input: DeriveInput = syn::parse_quote! {
            #[message(templates = [A, B])]
            struct M { #[field(offset = 0)] a: u64 }
        };
        let tokens = expand(&input).unwrap().to_string();
        for part in [
            "8usize <= A . block_length",
            "8usize <= B . block_length",
            "pub (crate) fn encode (& self , out : & mut [u8] , template : & :: karyos_codec :: Template ,)",
            "Encoder :: new (out , template) ?",
        ] {
            assert!(tokens.contains(part), "{part}: {tokens}");
        }
        let both: DeriveInput = syn::parse_quote! {
            #[message(template = A, templates = [A, B])]
            struct M { #[field(offset = 0)] a: u64 }
        };
        assert_eq!(
            error(both),
            "#[message] takes `template = PATH` or `templates = [PATH, ...]`, one of them"
        );
        let none: DeriveInput = syn::parse_quote! {
            #[message(templates = [])]
            struct M { #[field(offset = 0)] a: u64 }
        };
        assert_eq!(
            error(none),
            "#[message] takes `template = PATH` or `templates = [PATH, ...]`, one of them"
        );
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
                "expected `offset = N`, `check = PATH`, `with = PATH`, `width = N`, `spans = [(N, N), ...]`, `var`, `min = EXPR`, `max = EXPR` or `since = 2`",
            ),
        ];
        let overlap: DeriveInput = syn::parse_quote! {
            #[message(template = T)]
            struct M { #[field(offset = 0)] a: u64, #[field(offset = 4)] b: u32 }
        };
        assert_eq!(error(overlap), "fields `a` and `b` overlap");
        let tied_overlap: DeriveInput = syn::parse_quote! {
            #[message(template = T)]
            struct M {
                #[field(offset = 8)] a: u64,
                #[field(with = t, spans = [(0, 1), (12, 1)])] b: B,
            }
        };
        assert_eq!(error(tied_overlap), "fields `a` and `b` overlap");
        for (input, expected) in cases {
            assert_eq!(error(input), expected);
        }
    }
}
