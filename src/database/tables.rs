use crate::database::{Row, Schema, DbError, Column, ColumnType::*};

pub fn init_tables() -> Vec<(String, Schema)> {
    let user = Schema{cols: vec![CharVec,CharVec,UInt]};
    vec![
        (String::from("user"), user),
    ]
}

pub struct User {
    pub username: String,
    pub pswdhash: String,
    pub score: u32,
}

impl TableStruct for User {

    fn from(data: Row) -> Result<Self, DbError> {
        if data.datacols.len() != 3 {
            return Err(DbError::ColFormat);
        }

        let mut datacols = data.datacols.into_iter();
        let username = match datacols.next().unwrap() {
            Column::CharVec(un) => un,
            _ => return Err(DbError::ColFormat),
        };
        let pswdhash = match datacols.next().unwrap() {
            Column::CharVec(hash) => hash,
            _ => return Err(DbError::ColFormat),
        };
        let score = match datacols.next().unwrap() {
            Column::UInt(score) => score,
            _ => return Err(DbError::ColFormat),
        };
        Ok(User{username: username, pswdhash: pswdhash, score: score})
    }

    fn to(self) -> Row {
        Row{
            datacols: vec![
            Column::CharVec(self.username),
            Column::CharVec(self.pswdhash),
            Column::UInt(self.score),
        ]
        }
    }

}

pub trait TableStruct: Sized {
    fn from(data: Row) -> Result<Self, DbError>;

    fn to(self) -> Row;
}
