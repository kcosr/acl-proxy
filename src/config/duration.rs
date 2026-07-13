use std::fmt;
use std::time::Duration;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer};

const MAX_FINITE_DURATION: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) struct PositiveDuration(Duration);

impl PositiveDuration {
    pub(super) const fn get(self) -> Duration {
        self.0
    }
}

impl<'de> Deserialize<'de> for PositiveDuration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PositiveDurationVisitor;

        impl Visitor<'_> for PositiveDurationVisitor {
            type Value = PositiveDuration;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a positive duration string with an explicit unit")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let duration = humantime::parse_duration(value).map_err(E::custom)?;
                if duration.is_zero() {
                    return Err(E::custom("duration must be greater than zero"));
                }
                if duration > MAX_FINITE_DURATION {
                    return Err(E::custom("duration must not exceed 24h"));
                }
                Ok(PositiveDuration(duration))
            }
        }

        deserializer.deserialize_str(PositiveDurationVisitor)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum DrainTimeout {
    Bounded(PositiveDuration),
    Unbounded,
}

impl DrainTimeout {
    pub(super) const fn bounded(self) -> Option<Duration> {
        match self {
            Self::Bounded(duration) => Some(duration.get()),
            Self::Unbounded => None,
        }
    }
}

impl<'de> Deserialize<'de> for DrainTimeout {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct DrainTimeoutVisitor;

        impl Visitor<'_> for DrainTimeoutVisitor {
            type Value = DrainTimeout;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a positive duration string or \"unbounded\"")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if value == "unbounded" {
                    return Ok(DrainTimeout::Unbounded);
                }
                let duration = humantime::parse_duration(value).map_err(E::custom)?;
                if duration.is_zero() {
                    return Err(E::custom("duration must be greater than zero"));
                }
                if duration > MAX_FINITE_DURATION {
                    return Err(E::custom("duration must not exceed 24h"));
                }
                Ok(DrainTimeout::Bounded(PositiveDuration(duration)))
            }
        }

        deserializer.deserialize_str(DrainTimeoutVisitor)
    }
}

pub(super) fn seconds(value: u64) -> PositiveDuration {
    PositiveDuration(Duration::from_secs(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Deserialize)]
    struct PositiveFixture {
        value: PositiveDuration,
    }

    #[derive(Deserialize)]
    struct DrainFixture {
        value: DrainTimeout,
    }

    #[test]
    fn positive_duration_requires_a_string_unit_and_nonzero_value() {
        let parsed: PositiveFixture = toml::from_str("value = \"250ms\"").unwrap();
        assert_eq!(parsed.value.get(), Duration::from_millis(250));

        let maximum: PositiveFixture = toml::from_str("value = \"24h\"").unwrap();
        assert_eq!(maximum.value.get(), MAX_FINITE_DURATION);

        for invalid in [
            "value = 30",
            "value = \"0s\"",
            "value = \"30\"",
            "value = \"24h 1ns\"",
            "value = \"unbounded\"",
        ] {
            assert!(
                toml::from_str::<PositiveFixture>(invalid).is_err(),
                "{invalid}"
            );
        }
    }

    #[test]
    fn drain_timeout_accepts_only_positive_durations_or_exact_unbounded() {
        let bounded: DrainFixture = toml::from_str("value = \"2m\"").unwrap();
        assert_eq!(bounded.value.bounded(), Some(Duration::from_secs(120)));

        let unbounded: DrainFixture = toml::from_str("value = \"unbounded\"").unwrap();
        assert_eq!(unbounded.value.bounded(), None);

        for invalid in [
            "value = \"Unbounded\"",
            "value = \"0ms\"",
            "value = \"25h\"",
        ] {
            assert!(
                toml::from_str::<DrainFixture>(invalid).is_err(),
                "{invalid}"
            );
        }
    }
}
