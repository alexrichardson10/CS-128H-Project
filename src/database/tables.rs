use crate::database::ColumnType::*;
use crate::database::Column;
use crate::database::DbError;
use crate::database::Schema;
use crate::database::Row;

pub fn init_tables() -> Vec<(String, Schema)> {
    let user = Schema{cols: vec![
        (String::from("UserName"), CharVec),
        (String::from("PswdHash"), CharVec),
        (String::from("Score"), UInt),
    ]};
    vec![
        (String::from("user"), user),
    ]
}

pub struct User {
    pub username: String,
    pswdhash: String,
    score: u32,
}

impl TableStruct for User {

    fn from(data: &Row) -> Result<Self, DbError> {
        if data.datacols.len() != 3 {
            return Err(DbError::ColFormat);
        }
        match &data.datacols[..] {
            [ 
                Column::CharVec(un), 
                Column::CharVec(hash), 
                Column::UInt(score)
            ] => 
                Ok(User{
                    username: un.clone(),
                    pswdhash: hash.clone(),
                    score: *score,
                }),
            _ => Err(DbError::ColFormat),
        }
    }

    fn to(&self) -> Row {
        Row{
            datacols: vec![
            Column::CharVec(self.username.clone()),
            Column::CharVec(self.pswdhash.clone()),
            Column::UInt(self.score),
        ]
        }
    }

}

pub trait TableStruct: Sized {
    fn from(data: &Row) -> Result<Self, DbError>;

    fn to(&self) -> Row;
}
