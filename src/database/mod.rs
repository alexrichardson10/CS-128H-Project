
use std::path::Path;
use std::fs;
use std::str::FromStr;

pub fn new_database(name: String) -> Result<Database, std::io::Error> {
    let pathname = path_for_database(&name);
    let path = Path::new(&pathname);
    fs::create_dir(path)?;
    Ok(Database{folder: name, tables: vec![]})
}

pub struct Database {
    folder: String,
    tables: Vec<Schema>
}

impl Database {
    fn get_ftable(&self, input: &String) -> Result<&Schema, String> {
        match self.tables.iter().find(|x| x.tablename == *input) {
            Some(found) => Ok(found),
            None => Err(String::from("Could not find the foreign table")),
        }
    }

    fn add_schema(&mut self, schema: Schema) {
        self.tables.push(schema);
    }
}

fn path_for_database(name: &str) -> String {
    let path: String = format!("database/{}", name);
    path
}

enum Column {
    PKey(u32),
    FKey(u32, String),
    UInt(u32),
    Int(i32),
    CharVec(String),
    Double(f64),
}

enum ColumnType {
    PKey,
    FKey(String),
    UInt,
    Int,
    CharVec,
    Double,
}


impl ColumnType {

    fn map_string(&self, input: &String) -> Result<Column, ()> {
        match self {
            ColumnType::PKey => return Ok(Column::PKey(parse_as(input)?)),
            ColumnType::FKey(table) => return Ok(Column::FKey(parse_as(input)?, table.clone())),
            ColumnType::UInt => return Ok(Column::UInt(parse_as(input)?)),
            ColumnType::Int => return Ok(Column::Int(parse_as(input)?)),
            ColumnType::Double => return Ok(Column::Double(parse_as(input)?)),
            ColumnType::CharVec => return Ok(Column::CharVec(input.clone())),
        };
    }

}

fn parse_as<T: FromStr>(input: &String) -> Result<T, ()> {
    match input.parse::<T>() {
        Ok(thing) => Ok(thing),
        Err(_) => Err(())
    }
}

struct Schema {
    tablename: String,
    cols: Vec<ColumnType>,
}
