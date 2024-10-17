pub fn split_range(port_range: u32, threads: u32) -> Vec<u32> {
    let result = port_range / threads;
    let remain = port_range % threads;

    let mut ranges: Vec<u32> = Vec::new();
    let mut total: u32 = 0;
    for _ in 0..threads {
        total = total + result;
        ranges.push(total);
    }
    if remain > 0 {
        ranges.push(total+remain);
    }
    return ranges;
}