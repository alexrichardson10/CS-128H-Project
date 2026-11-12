
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::path::Path;
use std::fs::{self, File, OpenOptions};
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
        let table_pathname = self.table_path(tablename);
        let file = match File::open(table_pathname) {
            Ok(f) => f,
            Err(_) => return Err(DbError::FileNotFound),
        };
        let mut reader = BufReader::new(file);
        
        let schema = self.get_table(tablename)?;
        let mut table: HashMap<u32, T> = HashMap::new();
        let mut offset_map: HashMap<u32, u64> = HashMap::new();
        let mut totaloffset: u64 = 0;
        let mut line = String::new();
        while reader.read_line(&mut line)? != 0 {
            // check if row is deleted
            if !line.starts_with('D') {
                let cols: Vec<&str> = line.trim_end().split(',').collect();
                if cols.len() != (schema.cols.len() + 1) { return Err(DbError::ColFormat)};
    
                let pk: u32 = parse_as(cols[0])?;
                let mut row = Row::new();
                for (coltype, col) in cols[1..].iter().enumerate() {
                    row.datacols.push(schema.cols[coltype].1.map_string(col)?);
                }
                table.insert(pk, T::from(&row)?);
                offset_map.insert(pk, totaloffset);
            }
            totaloffset += line.len() as u64;
            line.clear();
        }
        Ok(Table{table: table, to_delete: vec![], to_append: vec![], byte_offset_map: offset_map})
    }

    pub fn write_table<T: TableStruct>(&self, tablename: &String, table: Table<T>) -> Result<(), DbError> {
        let _schema = self.get_table(tablename)?;

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(self.table_path(tablename))?;

        //deletion loop
        for delete_key in table.to_delete {
            let offset = match table.byte_offset_map.get(&delete_key) {
                Some(offset) => *offset,
                None => continue, // skip a key if it does not exist in byte offset map
            };
            file.seek(SeekFrom::Start(offset))?;
            file.write_all(b"D")?;
        }

        //addition loop
        for append_key in table.to_append {
            let tablestruct = &table.table[&append_key];
            let rowstr = tablestruct.to().to_row_string(append_key);
            file.seek(SeekFrom::End(0))?;
            file.write_all(rowstr.as_bytes())?;
        }

        Ok(())
    }

    fn table_path(&self, tablename: &String) -> String {
        format!("{}/{}", path_for_database(&self.folder), tablename)
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

impl Column {
    pub fn into(&self) -> String {
        match self {
            Column::FKey(x) => x.to_string(),
            Column::UInt(x) => x.to_string(),
            Column::Int(x) => x.to_string(),
            Column::CharVec(x) => x.to_string(),
            Column::Double(x) => x.to_string(),
        }
    }
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

pub struct Schema {
    cols: Vec<(String, ColumnType)>,
}

pub struct Row {
    datacols: Vec<Column>,
}

impl Row {
    pub fn new() -> Self {
        Row{datacols: vec![]}
    }

    pub fn to_row_string(&self, pk: u32) -> String {
        let mut out = String::new();
        out += pk.to_string().as_str();
        for col in &self.datacols {
            out.push(',');
            out += col.into().as_str();
        }
        out.push('\n');
        out
    }
}

pub struct Table<T: TableStruct> {
    table: HashMap<u32, T>,
    to_append: Vec<u32>,
    to_delete: Vec<u32>,
    byte_offset_map: HashMap<u32, u64>,
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