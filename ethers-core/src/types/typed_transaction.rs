use super::transaction::NUM_TX_FIELDS;
use crate::{
    types::{Address, Bytes, Signature, TransactionRequest, H256, U64},
    utils::keccak256,
};

use rlp::RlpStream;
use rlp_derive::RlpEncodable;
use serde::{Deserialize, Serialize};

const NUM_EIP2930_FIELDS: usize = NUM_TX_FIELDS + 1;

/// Access list
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize, RlpEncodable)]
pub struct AccessList(Vec<AccessListItem>);

impl From<Vec<AccessListItem>> for AccessList {
    fn from(src: Vec<AccessListItem>) -> AccessList {
        AccessList(src)
    }
}

/// Access list item
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize, RlpEncodable)]
#[serde(rename_all = "camelCase")]
pub struct AccessListItem {
    /// Accessed address
    pub address: Address,
    /// Accessed storage keys
    pub storage_keys: Vec<H256>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(tag = "type")]
pub enum TransactionEnvelope {
    // 0x00
    #[serde(rename = "0x00")]
    Legacy(TransactionRequest),
    // 0x01
    #[serde(rename = "0x01")]
    Eip2930(Eip2930TransactionRequest),
}

impl TransactionEnvelope {
    /// Hashes the transaction's data with the provided chain id
    pub fn sighash<T: Into<U64>>(&self, chain_id: T) -> H256 {
        let encoded = match self {
            TransactionEnvelope::Legacy(ref tx) => {
                let mut encoded = vec![0];
                encoded.extend_from_slice(tx.rlp(chain_id).as_ref());
                encoded
            }
            TransactionEnvelope::Eip2930(ref tx) => {
                let mut encoded = vec![1];
                encoded.extend_from_slice(tx.rlp(chain_id).as_ref());
                encoded
            }
        };
        keccak256(encoded).into()
    }
}

impl From<TransactionRequest> for TransactionEnvelope {
    fn from(src: TransactionRequest) -> TransactionEnvelope {
        TransactionEnvelope::Legacy(src)
    }
}

impl From<Eip2930TransactionRequest> for TransactionEnvelope {
    fn from(src: Eip2930TransactionRequest) -> TransactionEnvelope {
        TransactionEnvelope::Eip2930(src)
    }
}

/// An EIP-2930 transaction is a legacy transaction including an [`AccessList`].
#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub struct Eip2930TransactionRequest {
    #[serde(flatten)]
    pub tx: TransactionRequest,
    pub access_list: AccessList,
}

impl Eip2930TransactionRequest {
    pub fn new(tx: TransactionRequest, access_list: AccessList) -> Self {
        Self { tx, access_list }
    }

    pub fn rlp<T: Into<U64>>(&self, chain_id: T) -> Bytes {
        let mut rlp = RlpStream::new();
        rlp.begin_list(NUM_EIP2930_FIELDS);
        self.tx.rlp_base(&mut rlp);

        // append the access list in addition to the base rlp encoding
        rlp.append(&self.access_list);

        // append the signature fields
        rlp.append(&chain_id.into());
        rlp.append(&0u8);
        rlp.append(&0u8);
        rlp.out().freeze().into()
    }

    /// Produces the RLP encoding of the transaction with the provided signature
    pub fn rlp_signed(&self, signature: &Signature) -> Bytes {
        let mut rlp = RlpStream::new();
        rlp.begin_list(NUM_EIP2930_FIELDS);
        self.tx.rlp_base(&mut rlp);

        // append the access list in addition to the base rlp encoding
        rlp.append(&self.access_list);

        // append the signature
        rlp.append(&signature.v);
        rlp.append(&signature.r);
        rlp.append(&signature.s);
        rlp.out().freeze().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_legacy_tx() {
        let tx = TransactionRequest::new()
            .to(Address::zero())
            .value(U256::from(100));
        let tx = TransactionEnvelope::from(tx);
        let serialized = serde_json::to_string(&tx).unwrap();

        // deserializes to either the envelope type or the inner type
        let de: TransactionEnvelope = serde_json::from_str(&serialized).unwrap();
        assert_eq!(tx, de);

        let de: TransactionRequest = serde_json::from_str(&serialized).unwrap();
        assert_eq!(tx, TransactionEnvelope::Legacy(de));
    }

    #[test]
    fn serde_eip2930_tx() {
        let access_list = vec![AccessListItem {
            address: Address::zero(),
            storage_keys: vec![H256::zero()],
        }];
        let tx = TransactionRequest::new()
            .to(Address::zero())
            .value(U256::from(100))
            .with_access_list(access_list);
        let tx = TransactionEnvelope::from(tx);
        let serialized = serde_json::to_string(&tx).unwrap();
        dbg!(&serialized);

        // deserializes to either the envelope type or the inner type
        let de: TransactionEnvelope = serde_json::from_str(&serialized).unwrap();
        assert_eq!(tx, de);

        let de: Eip2930TransactionRequest = serde_json::from_str(&serialized).unwrap();
        assert_eq!(tx, TransactionEnvelope::Eip2930(de));
    }
}
