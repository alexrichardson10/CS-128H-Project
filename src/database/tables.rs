use crate::database::ColumnType::*;
use crate::database::Schema;

pub fn init_tables() -> Vec<(String, Schema)> {
    let user = Schema{cols: vec![
        (String::from("UserID"), PKey),
        (String::from("UserName"), CharVec),
        (String::from("PswdHash"), CharVec),
        (String::from("Score"), UInt),
    ]};
    vec![
        (String::from("User"), user),
    ]
}