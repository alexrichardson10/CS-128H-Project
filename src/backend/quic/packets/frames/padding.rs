#[derive(Debug, Clone)]
/// The decision was made to coalesce multiple padding frames into one longer one.
/// This shouldn't have much of an impact other than making it easier to store.
pub struct Padding {
    pub count: usize,
}

impl Padding {
    pub fn new(data: &Vec<u8>, position: &mut usize) -> Padding {
        let mut count: usize = 0;

        while *position < data.len() {
            if data[*position] == 0x00 {
                count += 1;
                *position += 1;
            } else {
                break
            };
        }

        Padding {
            count
        }
    }
}