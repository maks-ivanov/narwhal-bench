use std::{fmt::Debug, time::SystemTime};

use super::asset::AssetId;

#[derive(Copy, Clone, Debug)]
pub enum OrderSide {
    Bid,
    Ask,
}

#[derive(Debug, Clone)]
pub struct Order {
    pub order_id: u64,
    pub base_asset: AssetId,
    pub quote_asset: AssetId,
    pub side: OrderSide,
    pub price: u64,
    pub quantity: u64,
}

#[derive(Eq, PartialEq, Debug, Copy, Clone)]
pub enum OrderType {
    Market,
    Limit,
}

#[derive(Debug)]
pub enum Success {
    Accepted {
        order_id: u64,
        order_type: OrderType,
        ts: SystemTime,
    },

    Filled {
        order_id: u64,
        side: OrderSide,
        order_type: OrderType,
        price: u64,
        quantity: u64,
        ts: SystemTime,
    },

    PartiallyFilled {
        order_id: u64,
        side: OrderSide,
        order_type: OrderType,
        price: u64,
        quantity: u64,
        ts: SystemTime,
    },

    Amended {
        order_id: u64,
        price: u64,
        quantity: u64,
        ts: SystemTime,
    },

    Cancelled {
        order_id: u64,
        ts: SystemTime,
    },
}

#[derive(Debug)]
pub enum Failed {
    Validation(String),
    DuplicateOrderID(u64),
    NoMatch(u64),
    OrderNotFound(u64),
}
pub type OrderProcessingResult = Vec<Result<Success, Failed>>;
