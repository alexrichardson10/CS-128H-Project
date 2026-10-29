use crate::database::ColumnType::*;
use crate::database::Column;
use crate::database::DbError;
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

pub struct User {
    userid: u32,
    pub username: String,
    pswdhash: String,
    score: u32,
}

impl User {
    fn new() -> Self {
        User{userid: 0, username: String::new(), pswdhash: String::new(), score: 0}
    }

    pub fn from(data: &[Column]) -> Result<Self, DbError> {
        if data.len() != 4 {
            return Err(DbError::ColFormat);
        }
        match data {
            [Column::PKey(id), 
                Column::CharVec(un), 
                Column::CharVec(hash), 
                Column::UInt(score)] => Ok(User{
                    userid: *id,
                    username: un.clone(),
                    pswdhash: hash.clone(),
                    score: *score,
                }),
            _ => Err(DbError::ColFormat),
        }
    }

    pub fn to(&self) -> Vec<Column> {
        vec![
            Column::PKey(self.userid),
            Column::CharVec(self.username.clone()),
            Column::CharVec(self.pswdhash.clone()),
            Column::UInt(self.score),
        ]
    }

}
