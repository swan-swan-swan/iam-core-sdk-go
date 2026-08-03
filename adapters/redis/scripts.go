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
redis.call("DEL", KEYS[2])
redis.call(
	"HSET", KEYS[1],
	"version", ARGV[1],
	"payload", ARGV[2],
	"generation", ARGV[3],
	"last_fence", "0"
)
local expiry = redis.pcall("PEXPIRE", KEYS[1], ARGV[4])
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
local currentGeneration = redis.call("HGET", KEYS[1], "generation")
if currentVersion ~= ARGV[1] or currentPayload ~= ARGV[2] or
   currentGeneration ~= ARGV[3] then
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
local maxExact = 9007199254740991
local maxExactText = "9007199254740991"

local function exactPositiveInteger(value)
	if type(value) ~= "string" or not string.match(value, "^[1-9]%d*$") or
	   #value > #maxExactText or (#value == #maxExactText and value > maxExactText) then
		return nil
	end
	local number = tonumber(value)
	if not number or number < 1 or number > maxExact or number ~= math.floor(number) or
	   string.format("%.0f", number) ~= value then
		return nil
	end
	return number
end

local function validFence(value)
	return type(value) == "string" and string.match(value, "^%d+$") and
	       #value <= 20 and not (#value > 1 and string.sub(value, 1, 1) == "0") and
	       (#value < 20 or value <= "18446744073709551615")
end

local function lessOrEqual(left, right)
	if #left ~= #right then
		return #left < #right
	end
	return left <= right
end

local sessionTTL = redis.call("PTTL", KEYS[1])
if sessionTTL == -2 or sessionTTL == 0 then
	return -1
end
if sessionTTL < 0 then
	return -2
end
if sessionTTL > maxExact or sessionTTL ~= math.floor(sessionTTL) then
	return -2
end
local generation = redis.call("HGET", KEYS[1], "generation")
if not generation then
	return -2
end
if generation ~= ARGV[3] then
	return -5
end
local leaseTTL = redis.call("PTTL", KEYS[2])
if leaseTTL >= 0 then
	return 0
end
if leaseTTL ~= -2 then
	return -2
end
local lastFence = redis.call("HGET", KEYS[1], "last_fence")
if not validFence(ARGV[2]) or not validFence(lastFence) then
	return -2
end
if lessOrEqual(ARGV[2], lastFence) then
	return -4
end
local requestedTTL = exactPositiveInteger(ARGV[4])
if not requestedTTL then
	return -2
end
if sessionTTL < requestedTTL then
	requestedTTL = sessionTTL
end
local redisTime = redis.call("TIME")
local seconds = tonumber(redisTime[1])
local microseconds = tonumber(redisTime[2])
if not seconds or not microseconds then
	return -2
end
local now = seconds * 1000 + math.floor(microseconds / 1000)
if now < 0 or now > maxExact or now ~= math.floor(now) or requestedTTL > maxExact - now then
	return -2
end
local expiresAt = string.format("%.0f", now + requestedTTL)
redis.call(
	"HSET", KEYS[2],
	"owner", ARGV[1],
	"fence", ARGV[2],
	"generation", ARGV[3],
	"expires_at", expiresAt
)
local expiry = redis.pcall("PEXPIRE", KEYS[2], string.format("%.0f", requestedTTL))
if (type(expiry) == "table" and expiry.err) or expiry ~= 1 then
	redis.pcall("DEL", KEYS[2])
	return -2
end
local granted = redis.pcall("HSET", KEYS[1], "last_fence", ARGV[2])
if type(granted) == "table" and granted.err then
	redis.pcall("DEL", KEYS[2])
	return -2
end
return requestedTTL
`)

var leaseValidScript = goredis.NewScript(`
-- iam-core:lease-valid
local maxExact = 9007199254740991
if redis.call("PTTL", KEYS[1]) <= 0 or redis.call("PTTL", KEYS[2]) <= 0 then
	return 0
end
local generation = redis.call("HGET", KEYS[1], "generation")
local owner = redis.call("HGET", KEYS[2], "owner")
local fence = redis.call("HGET", KEYS[2], "fence")
local leaseGeneration = redis.call("HGET", KEYS[2], "generation")
local expiresAt = redis.call("HGET", KEYS[2], "expires_at")
if generation ~= ARGV[3] or owner ~= ARGV[1] or fence ~= ARGV[2] or
   leaseGeneration ~= ARGV[3] or type(expiresAt) ~= "string" or
   not string.match(expiresAt, "^[1-9]%d*$") or #expiresAt > 16 then
	return 0
end
local expiry = tonumber(expiresAt)
local redisTime = redis.call("TIME")
local seconds = tonumber(redisTime[1])
local microseconds = tonumber(redisTime[2])
if not expiry or expiry > maxExact or string.format("%.0f", expiry) ~= expiresAt or
   not seconds or not microseconds then
	return 0
end
local now = seconds * 1000 + math.floor(microseconds / 1000)
if now < 0 or now > maxExact or now ~= math.floor(now) or expiry <= now then
	return 0
end
return 1
`)

var leaseReleaseScript = goredis.NewScript(`
-- iam-core:lease-release
local maxExact = 9007199254740991
if redis.call("PTTL", KEYS[1]) <= 0 or redis.call("PTTL", KEYS[2]) <= 0 then
	return 0
end
local generation = redis.call("HGET", KEYS[1], "generation")
local owner = redis.call("HGET", KEYS[2], "owner")
local fence = redis.call("HGET", KEYS[2], "fence")
local leaseGeneration = redis.call("HGET", KEYS[2], "generation")
local expiresAt = redis.call("HGET", KEYS[2], "expires_at")
if generation ~= ARGV[3] or owner ~= ARGV[1] or fence ~= ARGV[2] or
   leaseGeneration ~= ARGV[3] or type(expiresAt) ~= "string" or
   not string.match(expiresAt, "^[1-9]%d*$") or #expiresAt > 16 then
	return 0
end
local expiry = tonumber(expiresAt)
local redisTime = redis.call("TIME")
local seconds = tonumber(redisTime[1])
local microseconds = tonumber(redisTime[2])
if not expiry or expiry > maxExact or string.format("%.0f", expiry) ~= expiresAt or
   not seconds or not microseconds then
	return 0
end
local now = seconds * 1000 + math.floor(microseconds / 1000)
if now < 0 or now > maxExact or now ~= math.floor(now) or expiry <= now then
	return 0
end
redis.call("DEL", KEYS[2])
return 1
`)

var sessionCompareAndSwapWithLeaseScript = goredis.NewScript(`
-- iam-core:fenced-cas
local maxExact = 9007199254740991
local maxExactText = "9007199254740991"
local function exactPositiveInteger(value)
	if type(value) ~= "string" or not string.match(value, "^[1-9]%d*$") or
	   #value > #maxExactText or (#value == #maxExactText and value > maxExactText) then
		return nil
	end
	local number = tonumber(value)
	if not number or number ~= math.floor(number) or string.format("%.0f", number) ~= value then
		return nil
	end
	return number
end
if redis.call("PTTL", KEYS[1]) <= 0 then
	return -1
end
if redis.call("PTTL", KEYS[2]) <= 0 then
	return -3
end
local generation = redis.call("HGET", KEYS[1], "generation")
local owner = redis.call("HGET", KEYS[2], "owner")
local fence = redis.call("HGET", KEYS[2], "fence")
local leaseGeneration = redis.call("HGET", KEYS[2], "generation")
local leaseExpiry = redis.call("HGET", KEYS[2], "expires_at")
if generation ~= ARGV[3] or owner ~= ARGV[1] or fence ~= ARGV[2] or
   leaseGeneration ~= ARGV[3] or not exactPositiveInteger(leaseExpiry) then
	return -3
end
local redisTime = redis.call("TIME")
local seconds = tonumber(redisTime[1])
local microseconds = tonumber(redisTime[2])
if not seconds or not microseconds then
	return -2
end
local now = seconds * 1000 + math.floor(microseconds / 1000)
if now < 0 or now > maxExact or now ~= math.floor(now) or tonumber(leaseExpiry) <= now then
	return -3
end
local current = redis.call("HGET", KEYS[1], "version")
if current ~= ARGV[4] then
	return 0
end
local oldPayload = redis.call("HGET", KEYS[1], "payload")
if not oldPayload then
	return -2
end
local nextTTL = exactPositiveInteger(ARGV[7])
if not nextTTL then
	return -2
end
local oldTTL = redis.call("PTTL", KEYS[1])
redis.call("HSET", KEYS[1], "version", ARGV[5], "payload", ARGV[6])
local expiry = redis.pcall("PEXPIRE", KEYS[1], ARGV[7])
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
local maxExact = 9007199254740991
local maxExactText = "9007199254740991"
local function exactPositiveInteger(value)
	if type(value) ~= "string" or not string.match(value, "^[1-9]%d*$") or
	   #value > #maxExactText or (#value == #maxExactText and value > maxExactText) then
		return nil
	end
	local number = tonumber(value)
	if not number or number ~= math.floor(number) or string.format("%.0f", number) ~= value then
		return nil
	end
	return number
end
if redis.call("PTTL", KEYS[1]) <= 0 then
	return -1
end
if redis.call("PTTL", KEYS[2]) <= 0 then
	return -3
end
local generation = redis.call("HGET", KEYS[1], "generation")
local owner = redis.call("HGET", KEYS[2], "owner")
local fence = redis.call("HGET", KEYS[2], "fence")
local leaseGeneration = redis.call("HGET", KEYS[2], "generation")
local leaseExpiry = redis.call("HGET", KEYS[2], "expires_at")
if generation ~= ARGV[3] or owner ~= ARGV[1] or fence ~= ARGV[2] or
   leaseGeneration ~= ARGV[3] or not exactPositiveInteger(leaseExpiry) then
	return -3
end
local redisTime = redis.call("TIME")
local seconds = tonumber(redisTime[1])
local microseconds = tonumber(redisTime[2])
if not seconds or not microseconds then
	return -2
end
local now = seconds * 1000 + math.floor(microseconds / 1000)
if now < 0 or now > maxExact or now ~= math.floor(now) or tonumber(leaseExpiry) <= now then
	return -3
end
local current = redis.call("HGET", KEYS[1], "version")
if current ~= ARGV[4] then
	return 0
end
local deleted = redis.call("DEL", KEYS[1], KEYS[2])
if deleted ~= 2 then
	return -2
end
return 1
`)
