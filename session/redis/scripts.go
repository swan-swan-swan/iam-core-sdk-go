package redisstore

import goredis "github.com/redis/go-redis/v9"

var sessionCreateScript = goredis.NewScript(`
if redis.call("EXISTS", KEYS[1]) ~= 0 then
	return 0
end
redis.call("HSET", KEYS[1], "version", ARGV[1], "payload", ARGV[2])
redis.call("PEXPIRE", KEYS[1], ARGV[3])
return 1
`)

var sessionCompareAndSwapScript = goredis.NewScript(`
if redis.call("EXISTS", KEYS[1]) == 0 then
	return -1
end
local current = redis.call("HGET", KEYS[1], "version")
if current ~= ARGV[1] then
	return 0
end
redis.call("HSET", KEYS[1], "version", ARGV[2], "payload", ARGV[3])
redis.call("PEXPIRE", KEYS[1], ARGV[4])
return 1
`)

var flowPutScript = goredis.NewScript(`
local result = redis.call("SET", KEYS[1], ARGV[1], "NX", "PX", ARGV[2])
if result then
	return 1
end
return 0
`)

var flowConsumeScript = goredis.NewScript(`
local payload = redis.call("GET", KEYS[1])
if not payload then
	return false
end
redis.call("DEL", KEYS[1])
return payload
`)

var lockAcquireScript = goredis.NewScript(`
local result = redis.call("SET", KEYS[1], ARGV[1], "NX", "PX", ARGV[2])
if result then
	return 1
end
return 0
`)

var lockValidScript = goredis.NewScript(`
local current = redis.call("GET", KEYS[1])
if current and current == ARGV[1] then
	return 1
end
return 0
`)

var lockUnlockScript = goredis.NewScript(`
local current = redis.call("GET", KEYS[1])
if current and current == ARGV[1] then
	redis.call("DEL", KEYS[1])
	return 1
end
return 0
`)
