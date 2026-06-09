import win32evtlog

server = 'localhost'
log_type = 'Security'

hand = win32evtlog.OpenEventLog(server, log_type)

flags = (
    win32evtlog.EVENTLOG_BACKWARDS_READ
    | win32evtlog.EVENTLOG_SEQUENTIAL_READ
)

event_counts = {}

events_read = 0

while events_read < 500:

    events = win32evtlog.ReadEventLog(hand, flags, 0)

    if not events:
        break

    for event in events:

        event_id = event.EventID & 0xFFFF

        event_counts[event_id] = event_counts.get(event_id, 0) + 1

        events_read += 1

        if events_read >= 500:
            break

print("\n=== Event ID Summary ===\n")

for event_id, count in sorted(event_counts.items()):
    print(f"Event ID {event_id}: {count}")