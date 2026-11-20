//! Timestamp contracts shared by the scanner, policy engine and history store.
use time::format_description::well_known::Rfc3339;
use time::macros::format_description;
use time::{Date, OffsetDateTime, UtcDateTime};

/// A wire timestamp retains the offset for civil dates and preserves an explicit
/// leap second. POSIX time alone cannot order :60 between :59 and the next minute.
#[derive(Debug, Clone, Copy)]
pub(crate) struct WireTimestamp {
    base: OffsetDateTime,
    leap: bool,
}

#[derive(Debug, thiserror::Error)]
#[error("invalid RFC 3339 timestamp")]
pub struct InvalidTimestamp;

impl From<OffsetDateTime> for WireTimestamp {
    fn from(base: OffsetDateTime) -> Self {
        Self { base, leap: false }
    }
}

impl WireTimestamp {
    pub(crate) fn parse(value: &str) -> Result<Self, InvalidTimestamp> {
        if !matches!(value.as_bytes().get(10), Some(b'T' | b't' | b' ')) {
            return Err(InvalidTimestamp);
        }
        let leap = value.as_bytes().get(17..19) == Some(b"60");
        // time's RFC 3339 parser rounds a leap second to :59.999999999.
        // Parse its date/offset normally while keeping the actual subsecond.
        // Older reports also accepted U+2212 as the sign in a final −HH:MM
        // offset. Only translate it there; the parser still validates HH:MM.
        const MINUS: &str = "\u{2212}";
        let offset_sign = value
            .len()
            .checked_sub(MINUS.len() + "00:00".len())
            .filter(|&i| i >= 19 && value.get(i..).is_some_and(|s| s.starts_with(MINUS)));
        let adjusted = (leap || offset_sign.is_some()).then(|| {
            let mut text = value.to_owned();
            if leap {
                text.replace_range(17..19, "59");
            }
            if let Some(i) = offset_sign {
                text.replace_range(i..i + MINUS.len(), "-");
            }
            text
        });
        let input = adjusted.as_deref().unwrap_or(value);
        let base = OffsetDateTime::parse(input, &Rfc3339).map_err(|_| InvalidTimestamp)?;
        Ok(Self { base, leap })
    }

    pub(crate) fn civil_date(self) -> Date {
        self.base.date()
    }

    pub(crate) fn order_key(self) -> (i64, bool, u32) {
        (
            self.base.unix_timestamp(),
            self.leap,
            self.base.nanosecond(),
        )
    }

    pub(crate) fn utc_millis(self) -> String {
        let utc = self.base.to_utc();
        if !self.leap {
            return utc_millis(utc);
        }
        utc.format(format_description!(
            "[year]-[month]-[day]T[hour]:[minute]:60.[subsecond digits:3]Z"
        ))
        .expect("UTC fields always satisfy this fixed format")
    }

    /// Number of complete elapsed days. Only an explicitly supplied leap second
    /// participates in the calculation; ordinary UNIX instants use elapsed time.
    pub(crate) fn age_days_at(self, now: UtcDateTime) -> i64 {
        let base = self.base.to_utc();
        let mut elapsed = now - base;
        // The existing risk model counts calendar-day differences plus the UTC
        // times of day, counting a leap tick only when crossing it.
        if self.leap && now.time().as_hms() <= base.time().as_hms() {
            elapsed -= time::Duration::SECOND;
        }
        elapsed.whole_days()
    }
}

/// Parse a scanner instant. UTC instants use POSIX semantics and cannot encode
/// a leap second; policy documents and report timestamps use WireTimestamp.
pub fn parse_utc(value: &str) -> Result<UtcDateTime, InvalidTimestamp> {
    let value = WireTimestamp::parse(value)?;
    if value.leap {
        Err(InvalidTimestamp)
    } else {
        Ok(value.base.to_utc())
    }
}

pub(crate) fn calendar_date(value: &str) -> Option<Date> {
    // Evidence date fields historically accept unpadded numbers and leading
    // whitespace before each numeric field. Wire timestamps stay strict.
    let mut fields = value.rsplitn(3, '-');
    let day = fields.next()?.trim_start();
    let month = fields.next()?.trim_start();
    let year = fields.next()?.trim_start();
    let digits = |field: &str, max: usize| {
        !field.is_empty() && field.len() <= max && field.bytes().all(|byte| byte.is_ascii_digit())
    };
    let year_digits = year.strip_prefix(['-', '+']);
    if !digits(day, 2)
        || !digits(month, 2)
        || !digits(
            year_digits.unwrap_or(year),
            if year_digits.is_some() { usize::MAX } else { 4 },
        )
    {
        return None;
    }
    let year: i32 = year.parse().ok()?;
    // The previous engine supported this inclusive calendar range.
    if !(-262_143..=262_142).contains(&year) {
        return None;
    }
    Date::from_calendar_date(
        year,
        month.parse::<u8>().ok()?.try_into().ok()?,
        day.parse().ok()?,
    )
    .ok()
}

pub(crate) fn utc_millis(value: UtcDateTime) -> String {
    value
        .format(format_description!(
            "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z"
        ))
        .expect("UTC fields always satisfy this fixed format")
}

pub fn utc_seconds(value: UtcDateTime) -> String {
    value
        .format(format_description!(
            "[year]-[month]-[day]T[hour]:[minute]:[second]Z"
        ))
        .expect("UTC fields always satisfy this fixed format")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_preserves_civil_date_but_elapsed_days_use_the_utc_instant() {
        let published = WireTimestamp::parse("2026-01-02t00:30:01.001+01:00").unwrap();
        assert_eq!(published.civil_date(), time::macros::date!(2026 - 01 - 02));
        assert_eq!(published.utc_millis(), "2026-01-01T23:30:01.001Z");
        assert_eq!(
            published.age_days_at(parse_utc("2026-01-02T23:30:01Z").unwrap()),
            0
        );
        assert_eq!(
            published.age_days_at(parse_utc("2026-01-02T23:30:01.001Z").unwrap()),
            1
        );
    }

    #[test]
    fn legacy_evidence_dates_allow_unpadded_fields_without_relaxing_the_wire_format() {
        assert_eq!(
            calendar_date(" 2026- 1- 2"),
            Some(time::macros::date!(2026 - 01 - 02))
        );
        assert_eq!(
            calendar_date("1-1-1"),
            Some(time::macros::date!(0001 - 01 - 01))
        );
        for invalid in [
            "2026-1-2 ",
            "2026-0-10",
            "2026-02-30",
            "99999-1-1",
            "+262143-01-01",
        ] {
            assert!(calendar_date(invalid).is_none(), "{invalid}");
        }
        assert!(WireTimestamp::parse("2026-1-2T00:00:00Z").is_err());
    }

    #[test]
    fn wire_syntax_requires_valid_separator_offset_and_fraction() {
        assert_eq!(
            WireTimestamp::parse("1970-01-01 01:00:00+01:00")
                .unwrap()
                .utc_millis(),
            "1970-01-01T00:00:00.000Z"
        );
        for invalid in [
            "2026-01-01@12:00:00Z",
            "2026-01-01T12:00:00.",
            "2026-01-01T12:00:00",
            "2026-01-01T12:00:00+24:00",
            "2026−01-01T12:00:00Z",
            "2026-01-01T12:00:00.1−2Z",
            "2026-01-01T12:00:00−24:00",
            "2026-01-01T12:00:00−00:60",
            "2026-02-30T12:00:00Z",
            "bad",
        ] {
            assert!(WireTimestamp::parse(invalid).is_err(), "{invalid}");
        }
        assert!(parse_utc("2016-12-31T23:59:60Z").is_err());
    }
}
