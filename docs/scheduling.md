# Scheduling and time zones

`CronSchedule(expression, timezone_name="UTC")` evaluates the five-field cron in the named IANA time zone and returns UTC instants. Day-of-month and day-of-week use cron OR semantics.

During a daylight-saving spring-forward gap, a nonexistent local wall time is skipped. During a fall-back fold, the schedule returns the first matching instant and the next call returns the second only when its UTC instant is strictly later. Hosts should persist UTC run instants and pass aware datetimes.
