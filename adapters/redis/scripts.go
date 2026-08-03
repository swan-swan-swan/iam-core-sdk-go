package redis

import goredis "github.com/redis/go-redis/v9"

const (
	scriptMarkerCreate        = "iam-core:create"
	scriptMarkerCAS           = "iam-core:cas"
	scriptMarkerDeleteExpired = "iam-core:delete-expired"
	scriptMarkerFencedCAS     = "iam-core:fenced-cas"
	scriptMarkerFencedDelete  = "iam-core:fenced-delete"
	scriptMarkerFlowPut       = "iam-core:flow-put"
	scriptMarkerFlowConsume   = "iam-core:flow-consume"
	scriptMarkerFenceNext     = "iam-core:fence-next"
	scriptMarkerLeaseAcquire  = "iam-core:lease-acquire"
	scriptMarkerLeaseValid    = "iam-core:lease-valid"
	scriptMarkerLeaseRelease  = "iam-core:lease-release"
	scriptStatusStorageFailed = int64(-2)
)

var sessionCreateScript = goredis.NewScript(`
-- iam-core:create
if redis.call("EXISTS", KEYS[1]) ~= 0 then
	return 0
end
redis.call("HSET", KEYS[1], "version", ARGV[1], "payload", ARGV[2])
local expiry = redis.pcall("PEXPIRE", KEYS[1], ARGV[3])
if (type(expiry) == "table" and expiry.err) or expiry ~= 1 then
	redis.pcall("DEL", KEYS[1])
	return -2
end
return 1
`)

var sessionCompareAndSwapScript = goredis.NewScript(`
-- iam-core:cas
if redis.call("EXISTS", KEYS[1]) == 0 then
	return -1
end
local current = redis.call("HGET", KEYS[1], "version")
if current ~= ARGV[1] then
	return 0
end
local oldPayload = redis.call("HGET", KEYS[1], "payload")
if not oldPayload then
	return -2
end
redis.call("HSET", KEYS[1], "version", ARGV[2], "payload", ARGV[3])
local expiry = redis.pcall("PEXPIRE", KEYS[1], ARGV[4])
if (type(expiry) == "table" and expiry.err) or expiry ~= 1 then
	redis.pcall("HSET", KEYS[1], "version", current, "payload", oldPayload)
	return -2
end
return 1
`)

var sessionDeleteExpiredScript = goredis.NewScript(`
-- iam-core:delete-expired
local currentVersion = redis.call("HGET", KEYS[1], "version")
local currentPayload = redis.call("HGET", KEYS[1], "payload")
if currentVersion ~= ARGV[1] or currentPayload ~= ARGV[2] then
	return 0
end
local deleted = redis.call("DEL", KEYS[1], KEYS[2])
if deleted < 1 then
	return -2
end
return 1
`)

var flowPutScript = goredis.NewScript(`
-- iam-core:flow-put
local result = redis.call("SET", KEYS[1], ARGV[1], "NX", "PX", ARGV[2])
if result then
	return 1
end
return 0
`)

var flowConsumeScript = goredis.NewScript(`
-- iam-core:flow-consume
local payload = redis.call("GET", KEYS[1])
if not payload then
	return false
end
redis.call("DEL", KEYS[1])
return payload
`)

// fenceNextScript increments an unsigned 64-bit decimal string without converting it
// to a Lua number (Redis Lua numbers cannot exactly represent the full uint64 range).
var fenceNextScript = goredis.NewScript(`
-- iam-core:fence-next
local current = redis.call("GET", KEYS[1])
if not current then
	current = "0"
end
if not string.match(current, "^%d+$") or #current > 20 or
   (#current > 1 and string.sub(current, 1, 1) == "0") then
	return "invalid"
end
if current == "18446744073709551615" then
	return ""
end
local carry = 1
local nextDigits = {}
for index = #current, 1, -1 do
	local digit = string.byte(current, index) - 48 + carry
	if digit >= 10 then
		digit = digit - 10
		carry = 1
	else
		carry = 0
	end
	table.insert(nextDigits, 1, string.char(48 + digit))
end
if carry == 1 then
	table.insert(nextDigits, 1, "1")
end
local nextFence = table.concat(nextDigits)
if #nextFence > 20 or (#nextFence == 20 and nextFence > "18446744073709551615") then
	return ""
end
redis.call("SET", KEYS[1], nextFence)
return nextFence
`)

var leaseAcquireScript = goredis.NewScript(`
-- iam-core:lease-acquire
if redis.call("EXISTS", KEYS[1]) == 0 then
	return -1
end
if redis.call("EXISTS", KEYS[2]) ~= 0 then
	local currentExpiry = redis.call("HGET", KEYS[2], "expires_at")
	if not currentExpiry or not tonumber(currentExpiry) then
		return -2
	end
	if tonumber(currentExpiry) > tonumber(ARGV[5]) then
		return 0
	end
	redis.call("DEL", KEYS[2])
end
redis.call(
	"HSET", KEYS[2],
	"owner", ARGV[1],
	"fence", ARGV[2],
	"expires_at", ARGV[3]
)
local expiry = redis.pcall("PEXPIRE", KEYS[2], ARGV[4])
if (type(expiry) == "table" and expiry.err) or expiry ~= 1 then
	redis.pcall("DEL", KEYS[2])
	return -2
end
return 1
`)

var leaseValidScript = goredis.NewScript(`
-- iam-core:lease-valid
local owner = redis.call("HGET", KEYS[1], "owner")
local fence = redis.call("HGET", KEYS[1], "fence")
local expiresAt = redis.call("HGET", KEYS[1], "expires_at")
if owner == ARGV[1] and fence == ARGV[2] and expiresAt == ARGV[3] and
   tonumber(expiresAt) and tonumber(expiresAt) > tonumber(ARGV[4]) then
	return 1
end
return 0
`)

var leaseReleaseScript = goredis.NewScript(`
-- iam-core:lease-release
local owner = redis.call("HGET", KEYS[1], "owner")
local fence = redis.call("HGET", KEYS[1], "fence")
local expiresAt = redis.call("HGET", KEYS[1], "expires_at")
if owner ~= ARGV[1] or fence ~= ARGV[2] or expiresAt ~= ARGV[3] or
   not tonumber(expiresAt) or tonumber(expiresAt) <= tonumber(ARGV[4]) then
	return 0
end
redis.call("DEL", KEYS[1])
return 1
`)

var sessionCompareAndSwapWithLeaseScript = goredis.NewScript(`
-- iam-core:fenced-cas
local owner = redis.call("HGET", KEYS[2], "owner")
local fence = redis.call("HGET", KEYS[2], "fence")
local leaseExpiry = redis.call("HGET", KEYS[2], "expires_at")
if owner ~= ARGV[1] or fence ~= ARGV[2] or leaseExpiry ~= ARGV[3] or
   not tonumber(leaseExpiry) or tonumber(leaseExpiry) <= tonumber(ARGV[4]) then
	return -3
end
if redis.call("EXISTS", KEYS[1]) == 0 then
	return -1
end
local current = redis.call("HGET", KEYS[1], "version")
if current ~= ARGV[5] then
	return 0
end
local oldPayload = redis.call("HGET", KEYS[1], "payload")
if not oldPayload then
	return -2
end
local oldTTL = redis.call("PTTL", KEYS[1])
redis.call("HSET", KEYS[1], "version", ARGV[6], "payload", ARGV[7])
local expiry = redis.pcall("PEXPIRE", KEYS[1], ARGV[8])
if (type(expiry) == "table" and expiry.err) or expiry ~= 1 then
	redis.pcall("HSET", KEYS[1], "version", current, "payload", oldPayload)
	return -2
end
local deleted = redis.pcall("DEL", KEYS[2])
if (type(deleted) == "table" and deleted.err) or deleted ~= 1 then
	redis.pcall("HSET", KEYS[1], "version", current, "payload", oldPayload)
	if oldTTL >= 0 then
		redis.pcall("PEXPIRE", KEYS[1], oldTTL)
	else
		redis.pcall("PERSIST", KEYS[1])
	end
	return -2
end
return 1
`)

var sessionDeleteWithLeaseScript = goredis.NewScript(`
-- iam-core:fenced-delete
local owner = redis.call("HGET", KEYS[2], "owner")
local fence = redis.call("HGET", KEYS[2], "fence")
local leaseExpiry = redis.call("HGET", KEYS[2], "expires_at")
if owner ~= ARGV[1] or fence ~= ARGV[2] or leaseExpiry ~= ARGV[3] or
   not tonumber(leaseExpiry) or tonumber(leaseExpiry) <= tonumber(ARGV[4]) then
	return -3
end
if redis.call("EXISTS", KEYS[1]) == 0 then
	return -1
end
local current = redis.call("HGET", KEYS[1], "version")
if current ~= ARGV[5] then
	return 0
end
local deleted = redis.call("DEL", KEYS[1], KEYS[2])
if deleted ~= 2 then
	return -2
end
return 1
`)
