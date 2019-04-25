use nom::*;

const REQUEST_STRUCTURE_SIZE: u16 = 4;

pub fn parse_request(data: &[u8]) -> IResult<&[u8], ()> {
    println!("LOGGING OFF");
    do_parse!(data,
        verify!(le_u16, |x| x == REQUEST_STRUCTURE_SIZE) >>
        take!(2) >>
        (())
    )
}
