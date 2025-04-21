import redis

redis_admin = redis.Redis(host='localhost', port=46216, decode_responses=True)
excluded_users = "un1, un2"
print(excluded_users)
result = redis_admin.execute_command("AUDITUSERS")
print(f"\nresult: {result}")
result = redis_admin.execute_command("AUDIT.SETEXCLUDEUSERS", "")
print(f"\nresult: {result}")
result = redis_admin.execute_command("AUDITUSERS")
print(f"\nresult: {result}")
result = redis_admin.execute_command("AUDIT.SETEXCLUDEUSERS", excluded_users)
print(f"\nresult: {result}")
result = redis_admin.execute_command("AUDITUSERS")
print(f"\nresult: {result}")
