use std::time::{SystemTime, UNIX_EPOCH};

const SECONDS_PER_DAY: u64 = 86_400;

pub fn epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default()
}

pub fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let shifted = days + 719_468;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    } / 146_097;
    let day_of_era = (shifted - era * 146_097) as u64;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era as i64 + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * shifted_month + 2) / 5 + 1) as u32;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    } as u32;

    (if month <= 2 { year + 1 } else { year }, month, day)
}

pub fn iso_date(days: i64) -> String {
    let (year, month, day) = civil_from_days(days);

    format!("{year:04}-{month:02}-{day:02}")
}

pub fn today() -> String {
    iso_date((epoch_seconds() / SECONDS_PER_DAY) as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_epoch_is_the_first_of_january_1970() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
    }

    #[test]
    fn known_days_convert_to_known_dates() {
        assert_eq!(civil_from_days(19_723), (2024, 1, 1));
        assert_eq!(civil_from_days(20_705), (2026, 9, 9));
        assert_eq!(civil_from_days(11_688), (2002, 1, 1));
    }

    #[test]
    fn a_leap_day_is_a_day_of_its_own() {
        assert_eq!(civil_from_days(19_782), (2024, 2, 29));
        assert_eq!(civil_from_days(19_783), (2024, 3, 1));
    }

    #[test]
    fn a_century_that_is_not_a_leap_year_has_no_leap_day() {
        assert_eq!(civil_from_days(47_540), (2100, 2, 28));
        assert_eq!(civil_from_days(47_541), (2100, 3, 1));
    }

    #[test]
    fn a_century_divisible_by_four_hundred_does_have_one() {
        assert_eq!(civil_from_days(11_016), (2000, 2, 29));
    }

    #[test]
    fn dates_before_the_epoch_still_convert() {
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
        assert_eq!(civil_from_days(-719_468), (0, 3, 1));
    }

    #[test]
    fn every_day_of_a_leap_year_round_trips_in_order() {
        let mut previous = civil_from_days(19_723);

        for offset in 1..366 {
            let current = civil_from_days(19_723 + offset);

            assert!(current > previous, "day {offset} went backwards");
            assert!((1..=12).contains(&current.1));
            assert!((1..=31).contains(&current.2));
            previous = current;
        }
    }

    #[test]
    fn an_iso_date_is_zero_padded() {
        assert_eq!(iso_date(0), "1970-01-01");
        assert_eq!(iso_date(20_705), "2026-09-09");
    }

    #[test]
    fn today_is_a_well_formed_iso_date() {
        let today = today();

        assert_eq!(today.len(), 10);
        assert_eq!(today.matches('-').count(), 2);
        assert!(today.starts_with("20"));
    }
}
