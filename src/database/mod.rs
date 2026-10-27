
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::fs::{self, File};
use std::str::FromStr;


mod tables;

pub fn new_database(name: String) -> Result<Database, std::io::Error> {
    let pathname = path_for_database(&name);
    let path = Path::new(&pathname);
    if !path.exists() { fs::create_dir(path)?; }
    let mut new_db = Database{folder: name, tables: vec![]};
    new_db.tables = tables::init_tables();
    Ok(new_db)
}

pub struct Database {
    folder: String,
    tables: Vec<(String, Schema)>
}

impl Database {
    fn get_table(&self, input: &String) -> Result<&Schema, String> {
        match self.tables.iter().find(|x| x.0 == *input) {
            Some(found) => Ok(&found.1),
            None => Err(String::from("Could not find the foreign table")),
        }
    }

    fn read_table(&self, tablename: &String) -> Result<Vec<Vec<Column>>, String> {
        let table_pathname = format!("{}/{}", path_for_database(&self.folder), tablename);
        let file = match File::open(table_pathname) {
            Ok(f) => f,
            Err(_) => return Err(String::from("File could not be opened")),
        };
        let reader = BufReader::new(file);
        let mut out:Vec<Vec<Column>> = vec![];

        let schema = match self.get_table(tablename) {
            Ok(s) => s,
            Err(_) => return Err(String::from("Could not find the requested schema")),
        };
        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => return Err(String::from("Could not read line")),
            };
            let cols: Vec<&str> = line.split(',').collect();
            if cols.len() != schema.cols.len() { return Err(String::from("Cols found did not match expected schema"))};
            let mut row = vec![];
            for (coltype, col) in cols.iter().enumerate() {
                row.push(schema.cols[coltype].1.map_string(col)?);
            }
            out.push(row);
        }
        Ok(out)
    }

}

fn path_for_database(name: &String) -> String {
    let path: String = format!("database/{}", name);
    path
}

enum Column {
    PKey(u32),
    FKey(u32),
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

    fn map_string(&self, input: &str) -> Result<Column, String> {
        match self {
            ColumnType::PKey => return Ok(Column::PKey(parse_as(input)?)),
            ColumnType::FKey(_) => return Ok(Column::FKey(parse_as(input)?)),
            ColumnType::UInt => return Ok(Column::UInt(parse_as(input)?)),
            ColumnType::Int => return Ok(Column::Int(parse_as(input)?)),
            ColumnType::Double => return Ok(Column::Double(parse_as(input)?)),
            ColumnType::CharVec => return Ok(Column::CharVec(String::from(input))),
        };
    }

}

fn parse_as<T: FromStr>(input: &str) -> Result<T, String> {
    match input.parse::<T>() {
        Ok(thing) => Ok(thing),
        Err(_) => Err(String::from("Could not parse input")),
    }
}

struct Schema {
    cols: Vec<(String, ColumnType)>, 
}
