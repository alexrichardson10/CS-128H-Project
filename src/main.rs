use cs_128h_project::database::{self, DbError, Table};
use cs_128h_project::database::tables::{User};

fn main() -> Result<(), DbError> {
    let usertable = String::from("user");
    let db: database::Database = database::new_database(String::from("maindb"))?;
    let user_table: Table<User> = db.read_table(&usertable)?;

    for row in user_table.rows() {
        println!("{}: {}", row.0, row.1.username);
    }

    Ok(())
}
