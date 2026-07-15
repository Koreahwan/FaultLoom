use core::fmt;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct ProtocolTime {
    unix_micros: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProtocolTimeError {
    InvalidFormat,
    OutOfRange,
}

impl ProtocolTime {
    pub(crate) fn parse_canonical(value: &str) -> Result<Self, ProtocolTimeError> {
        let bytes = value.as_bytes();
        if bytes.len() != 27
            || bytes[4] != b'-'
            || bytes[7] != b'-'
            || bytes[10] != b'T'
            || bytes[13] != b':'
            || bytes[16] != b':'
            || bytes[19] != b'.'
            || bytes[26] != b'Z'
        {
            return Err(ProtocolTimeError::InvalidFormat);
        }
        let year = decimal(&bytes[0..4])?;
        let month = decimal(&bytes[5..7])?;
        let day = decimal(&bytes[8..10])?;
        let hour = decimal(&bytes[11..13])?;
        let minute = decimal(&bytes[14..16])?;
        let second = decimal(&bytes[17..19])?;
        let fraction = decimal(&bytes[20..26])?;
        if !(1970..=9999).contains(&year)
            || !(1..=12).contains(&month)
            || day == 0
            || day > days_in_month(year, month)
            || hour > 23
            || minute > 59
            || second > 59
        {
            return Err(ProtocolTimeError::OutOfRange);
        }
        let days = days_before_year(year)?
            .checked_add(days_before_month(year, month))
            .and_then(|total| total.checked_add(day - 1))
            .ok_or(ProtocolTimeError::OutOfRange)?;
        let seconds = days
            .checked_mul(86_400)
            .and_then(|total| total.checked_add(hour * 3_600))
            .and_then(|total| total.checked_add(minute * 60))
            .and_then(|total| total.checked_add(second))
            .ok_or(ProtocolTimeError::OutOfRange)?;
        let unix_micros = seconds
            .checked_mul(1_000_000)
            .and_then(|total| total.checked_add(fraction))
            .ok_or(ProtocolTimeError::OutOfRange)?;
        Ok(Self { unix_micros })
    }

    pub(crate) const fn from_unix_micros(unix_micros: u64) -> Self {
        Self { unix_micros }
    }

    pub(crate) fn from_unix_millis(unix_millis: u64) -> Result<Self, ProtocolTimeError> {
        unix_millis
            .checked_mul(1_000)
            .map(Self::from_unix_micros)
            .ok_or(ProtocolTimeError::OutOfRange)
    }

    pub(crate) const fn floor_millis(self) -> u64 {
        self.unix_micros / 1_000
    }

    pub(crate) const fn ceil_millis(self) -> u64 {
        let remainder = if self.unix_micros.is_multiple_of(1_000) {
            0
        } else {
            1
        };
        self.floor_millis() + remainder
    }

    pub(crate) const fn checked_add_micros(self, delta: u64) -> Option<Self> {
        match self.unix_micros.checked_add(delta) {
            Some(unix_micros) => Some(Self { unix_micros }),
            None => None,
        }
    }
}

impl fmt::Display for ProtocolTimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFormat => {
                formatter.write_str("timestamp is not canonical UTC microseconds")
            }
            Self::OutOfRange => formatter.write_str("timestamp is outside the supported range"),
        }
    }
}

impl std::error::Error for ProtocolTimeError {}

fn decimal(bytes: &[u8]) -> Result<u64, ProtocolTimeError> {
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return Err(ProtocolTimeError::InvalidFormat);
    }
    bytes.iter().try_fold(0_u64, |value, byte| {
        value
            .checked_mul(10)
            .and_then(|total| total.checked_add(u64::from(byte - b'0')))
            .ok_or(ProtocolTimeError::OutOfRange)
    })
}

const fn leap_year(year: u64) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

const fn days_in_month(year: u64, month: u64) -> u64 {
    match month {
        2 if leap_year(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

fn days_before_year(year: u64) -> Result<u64, ProtocolTimeError> {
    let previous = year.checked_sub(1).ok_or(ProtocolTimeError::OutOfRange)?;
    let through_previous = previous
        .checked_mul(365)
        .and_then(|days| days.checked_add(previous / 4))
        .and_then(|days| days.checked_sub(previous / 100))
        .and_then(|days| days.checked_add(previous / 400))
        .ok_or(ProtocolTimeError::OutOfRange)?;
    let through_1969 = 1969 * 365 + 1969 / 4 - 1969 / 100 + 1969 / 400;
    through_previous
        .checked_sub(through_1969)
        .ok_or(ProtocolTimeError::OutOfRange)
}

const fn days_before_month(year: u64, month: u64) -> u64 {
    let ordinary = match month {
        1 => 0,
        2 => 31,
        3 => 59,
        4 => 90,
        5 => 120,
        6 => 151,
        7 => 181,
        8 => 212,
        9 => 243,
        10 => 273,
        11 => 304,
        12 => 334,
        _ => 0,
    };
    let leap_day = if month > 2 && leap_year(year) { 1 } else { 0 };
    ordinary + leap_day
}
