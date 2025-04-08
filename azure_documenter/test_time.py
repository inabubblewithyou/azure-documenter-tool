from datetime import datetime, timezone

# Get current time in UTC
utc_time = datetime.now(timezone.utc)
utc_timestamp = utc_time.strftime("%Y%m%d_%H%M%S")

# Get current local time
local_time = datetime.now()
local_timestamp = local_time.strftime("%Y%m%d_%H%M%S")

print(f"Local time: {local_time}")
print(f"Local timestamp: {local_timestamp}")
print(f"UTC time: {utc_time}")
print(f"UTC timestamp: {utc_timestamp}")
print(f"UTC offset: {local_time.astimezone().utcoffset()}") 