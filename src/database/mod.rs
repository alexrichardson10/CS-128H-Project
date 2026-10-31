
use std::collections::HashMap;
use std::hash::Hash;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::fs::{self, File};
use std::str::FromStr;

use crate::database::tables::TableStruct;


pub mod tables;

pub fn new_database(name: String) -> Result<Database, DbError> {
    let pathname = path_for_database(&name);
    let path = Path::new(&pathname);
    if !path.exists() { fs::create_dir(path)?; }
    let mut new_db = Database{folder: name, tables: vec![]};
    new_db.tables = tables::init_tables();
    Ok(new_db)
}

pub struct Database {
    pub folder: String,
    tables: Vec<(String, Schema)>
}

impl Database {
    fn get_table(&self, input: &String) -> Result<&Schema, DbError> {
        match self.tables.iter().find(|x| x.0 == *input) {
            Some(found) => Ok(&found.1),
            None => Err(DbError::TableNotFound),
        }
    }

    pub fn read_table<T: TableStruct>(&self, tablename: &String) -> Result<Table<T>, DbError> {
        let table_pathname = format!("{}/{}", path_for_database(&self.folder), tablename);
        let file = match File::open(table_pathname) {
            Ok(f) => f,
            Err(_) => return Err(DbError::FileNotFound),
        };
        let reader = BufReader::new(file);
        
        let schema = self.get_table(tablename)?;
        let mut table: HashMap<u32, T> = HashMap::new();
        let mut totaloffset: u64 = 0;
        for line in reader.lines() {
            let line = line?;

            let cols: Vec<&str> = line.split(',').collect();
            if cols.len() != (schema.cols.len() + 1) { return Err(DbError::ColFormat)};

            let pk: u32 = parse_as(cols[0])?;
            let mut row = Row::new();
            for (coltype, col) in cols[1..].iter().enumerate() {
                row.datacols.push(schema.cols[coltype].1.map_string(col)?);
            }
            table.insert(pk, T::from(&row)?);
        }
        Ok(Table{table: table, to_delete: vec![], to_append: vec![]})
    }

    pub fn write_table<T: TableStruct>(&self, tablename: &String, table: Table<T>) -> Result<(), DbError> {
        let schema = self.get_table(tablename)?;


        Ok(())
    }

}

fn path_for_database(name: &String) -> String {
    let path: String = format!("data/{}", name);
    path
}

pub enum Column {
    FKey(u32),
    UInt(u32),
    Int(i32),
    CharVec(String),
    Double(f64),
}

enum ColumnType {
    FKey(String),
    UInt,
    Int,
    CharVec,
    Double,
}


impl ColumnType {

    fn map_string(&self, input: &str) -> Result<Column, DbError> {
        match self {
            ColumnType::FKey(_) => return Ok(Column::FKey(parse_as(input)?)),
            ColumnType::UInt => return Ok(Column::UInt(parse_as(input)?)),
            ColumnType::Int => return Ok(Column::Int(parse_as(input)?)),
            ColumnType::Double => return Ok(Column::Double(parse_as(input)?)),
            ColumnType::CharVec => return Ok(Column::CharVec(String::from(input))),
        };
    }

}

fn parse_as<T: FromStr>(input: &str) -> Result<T, DbError> {
    match input.parse::<T>() {
        Ok(thing) => Ok(thing),
        Err(_) => Err(DbError::Parse),
    }
}

struct Schema {
    cols: Vec<(String, ColumnType)>, 
}

pub struct Row {
    datacols: Vec<Column>,
}

impl Row {
    pub fn new() -> Self {
        Row{datacols: vec![]}
    }
}

pub struct Table<T: TableStruct> {
    table: HashMap<u32, T>,
    to_append: Vec<u32>,
    to_delete: Vec<u32>,
    byte_offset_map: HashMap<u64, u64>,
}

impl<T: TableStruct> Table<T> {
    pub fn rows(&self) -> Vec<(&u32, &T)> {
        let mut out = vec![];
        for (key, row) in &self.table {
            out.push((key, row));
        }
        out
    }

    pub fn add(&mut self, new_row: T) -> u32 {
        let newpk = self.table.keys().copied().max().unwrap_or(0) + 1;
        self.table.insert(newpk, new_row);
        self.to_append.push(newpk);
        newpk
    }

    /// Remove from memory, mark for deletion
    pub fn remove(&mut self, pk: u32) {
        self.table.remove(&pk);
        self.to_delete.push(pk);
    }

    /// Removes row with the given pk, and returns the pk to the new, edited row.
    /// The original row is removed and marked for deletion. New row will be appended to eof.
    pub fn edit(&mut self, new_row: (u32, T)) -> u32 {
        self.remove(new_row.0);
        self.to_delete.push(new_row.0);
        let newpk = self.add(new_row.1);
        self.to_append.push(newpk);
        newpk
    }
}

#[derive(Debug)]
pub enum DbError {
    Read,
    Parse,
    Write,
    ColFormat,
    GeneralIO,
    FileNotFound,
    TableNotFound,
    RowNotFound,
}

impl From<std::io::Error> for DbError {
    fn from(_t: std::io::Error) -> Self {
        DbError::GeneralIO
    }
}