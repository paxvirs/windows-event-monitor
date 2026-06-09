import win32evtlog

server = 'localhost'
log_type = 'Security'

event_descriptions = {
    4624: "Successful Logon",
    4625: "Failed Logon",
    4672: "Special Privileges Assigned",
    4798: "User Group Membership Enumerated",
    4799: "Local Group Membership Enumerated",
    5379: "Credential Manager Credentials Read",
    5382: "Credential Manager Credentials Retrieved"
}

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

print("\n=== Security Event Analysis ===\n")

for event_id, count in sorted(event_counts.items()):

    description = event_descriptions.get(
        event_id,
        "Unknown Event"
    )

    print(f"Event ID {event_id}")
    print(f"Description: {description}")
    print(f"Occurrences: {count}")
    print("-" * 40)
