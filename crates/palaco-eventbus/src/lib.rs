#![forbid(unsafe_code)]
#![deny(warnings, clippy::unwrap_used, clippy::todo)]

/// Minimal event publication contract for PALACO components.
///
/// Implementations transport events only. They do not grant authority,
/// authorize actions, or make governance decisions.
pub trait EventBus<Event> {
    /// Error returned when the event cannot be published.
    type Error;

    /// Publishes an event to the configured event stream.
    fn publish(&mut self, event: Event) -> Result<(), Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::EventBus;

    #[derive(Debug, PartialEq, Eq)]
    struct TestEvent(&'static str);

    #[derive(Default)]
    struct RecordingBus {
        events: Vec<TestEvent>,
    }

    impl EventBus<TestEvent> for RecordingBus {
        type Error = std::convert::Infallible;

        fn publish(&mut self, event: TestEvent) -> Result<(), Self::Error> {
            self.events.push(event);
            Ok(())
        }
    }

    #[test]
    fn event_bus_publishes_events_without_authority_operations() {
        let mut bus = RecordingBus::default();
        let published = bus.publish(TestEvent("lifecycle")).is_ok();

        assert!(published);
        assert_eq!(bus.events, vec![TestEvent("lifecycle")]);
    }
}
