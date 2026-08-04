package main

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log"
	"os"

	goredis "github.com/redis/go-redis/v9"
	redisadapter "github.com/swan-swan-swan/iam-core-sdk-go/runtime/adapters/redis"
	"github.com/swan-swan-swan/iam-core-sdk-go/runtime/core"
)

var errInvalidEnvironment = errors.New("redis example: invalid environment")

func main() {
	address := os.Getenv("IAMCORE_REDIS_ADDR")
	prefix := os.Getenv("IAMCORE_REDIS_PREFIX")
	keyID := os.Getenv("IAMCORE_REDIS_KEY_ID")
	keyBytes, err := base64.RawURLEncoding.DecodeString(os.Getenv("IAMCORE_REDIS_KEY_BASE64URL"))
	if err != nil || address == "" || prefix == "" || keyID == "" || len(keyBytes) != 32 {
		log.Fatal(errInvalidEnvironment)
	}
	defer clear(keyBytes)

	codec, err := redisadapter.NewAESGCMCodec(redisadapter.Key{ID: keyID, Bytes: keyBytes}, nil)
	if err != nil {
		log.Fatal(errInvalidEnvironment)
	}
	client := goredis.NewClient(&goredis.Options{
		Addr:     address,
		Username: os.Getenv("IAMCORE_REDIS_USERNAME"),
		Password: os.Getenv("IAMCORE_REDIS_PASSWORD"),
	})
	defer func() {
		if err := client.Close(); err != nil {
			log.Print("redis example: close failed")
		}
	}()
	backend, err := redisadapter.New(client, redisadapter.Options{
		Prefix: prefix,
		Codec:  codec,
		Clock:  core.RealClock{},
		Random: rand.Reader,
	})
	if err != nil {
		log.Fatal("redis example: backend configuration failed")
	}

	_ = backend // Supply this Backend to bff.Config.Backend.
}
