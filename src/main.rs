use cs_128h_project::database::{self, DbError};
use cs_128h_project::database::tables::{User};

fn main() -> Result<(), DbError> {
    let usertable = String::from("user");
    let db: database::Database = database::new_database(String::from("maindb"))?;
    let user_table = db.read_table(&usertable)?;
    let user1 = User::from(&user_table[0][..])?;
    println!("{}", user1.username);



    Ok(())
}
