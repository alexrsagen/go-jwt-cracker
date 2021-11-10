package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash"
	"math/big"
	"strings"
	"sync"
)

var (
	token     = flag.String("token", "", "The full HS256 jwt token to crack")
	alphabet  = flag.String("alphabet", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", "The alphabet to use for the brute force")
	prefix    = flag.String("prefix", "", "A string that is always prefixed to the secret")
	suffix    = flag.String("suffix", "", "A string that is always suffixed to the secret")
	maxLength = flag.Int("maxlen", 12, "The max length of the string generated during the brute force")
)

func main() {
	flag.Parse()

	if *token == "" {
		fmt.Println("Parameter token is empty\n")
		flag.Usage()
		return
	}
	if *alphabet == "" {
		fmt.Println("Parameter alphabet is empty\n")
		flag.Usage()
		return
	}
	if *maxLength == 0 {
		fmt.Println("Parameter maxlen is 0\n")
		flag.Usage()
		return
	}

	parsed, err := parseJWT(*token)
	if err != nil {
		fmt.Printf("Could not parse JWT: %v\n", err)
		return
	}

	fmt.Printf("Parsed JWT:\n- Algorithm: %s\n- Type: %s\n- Payload: %s\n- Signature (hex): %s\n\n",
		parsed.header.Algorithm,
		parsed.header.Type,
		parsed.payload,
		hex.EncodeToString(parsed.signature))

	if strings.ToUpper(parsed.header.Algorithm) != "HS256" && strings.ToUpper(parsed.header.Algorithm) != "HS384" && strings.ToUpper(parsed.header.Algorithm) != "HS512" {
		fmt.Println("Unsupported algorithm")
		return
	}

	combinations := big.NewInt(0)
	for i := 1; i <= *maxLength; i++ {
		alen, mlen := big.NewInt(int64(len(*alphabet))), big.NewInt(int64(i))
		combinations.Add(combinations, alen.Exp(alen, mlen, nil))
	}
	fmt.Printf("There are %s combinations to attempt\nCracking JWT secret...\n", combinations.String())

	done := make(chan struct{})
	wg := &sync.WaitGroup{}
	var found bool
	var attempts uint64
	for secret := range generateSecrets(*alphabet, *maxLength, wg, done) {
		wg.Add(1)
		go func(s string, i uint64) {
			select {
			case <-done:
				wg.Done()
				return
			default:
			}
			if bytes.Equal(parsed.signature, generateSignature(parsed.message, []byte(*prefix+s+*suffix))) {
				fmt.Printf("Found secret in %d attempts: %s\n", attempts, *prefix+s+*suffix)
				found = true
				close(done)
			}
			wg.Done()
		}(secret, attempts)

		attempts++
		if attempts%100000 == 0 {
			fmt.Printf("Attempts: %d\n", attempts)
		}
	}
	wg.Wait()
	if !found {
		fmt.Printf("No secret found in %d attempts\n", attempts)
	}
}

type jwtHeader struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
}

type jwt struct {
	header             *jwtHeader
	payload            string
	message, signature []byte
}

func parseJWT(input string) (*jwt, error) {
	parts := strings.Split(input, ".")
	decodedParts := make([][]byte, len(parts))
	if len(parts) != 3 {
		return nil, errors.New("invalid jwt: does not contain 3 parts (header, payload, signature)")
	}
	for i := range parts {
		decodedParts[i] = make([]byte, base64.RawURLEncoding.DecodedLen(len(parts[i])))
		if _, err := base64.RawURLEncoding.Decode(decodedParts[i], []byte(parts[i])); err != nil {
			return nil, err
		}
	}
	var parsedHeader jwtHeader
	if err := json.Unmarshal(decodedParts[0], &parsedHeader); err != nil {
		return nil, err
	}
	return &jwt{
		header:    &parsedHeader,
		payload:   string(decodedParts[1]),
		message:   []byte(parts[0] + "." + parts[1]),
		signature: decodedParts[2],
	}, nil
}

func generateSignature(message, secret []byte) []byte {
	var hasher hash.Hash
	parsed, _ := parseJWT(*token)
	if strings.ToUpper(parsed.header.Algorithm) == "HS256" {
		hasher = hmac.New(sha256.New, secret)
	} else if strings.ToUpper(parsed.header.Algorithm) == "HS384" {
		hasher = hmac.New(sha512.New384, secret)
	} else if strings.ToUpper(parsed.header.Algorithm) == "HS512" {
		hasher = hmac.New(sha512.New, secret)
	}
	hasher.Write(message)
	return hasher.Sum(nil)
}

func generateSecrets(alphabet string, n int, wg *sync.WaitGroup, done chan struct{}) <-chan string {
	if n <= 0 {
		return nil
	}

	c := make(chan string)

	wg.Add(1)
	go func() {
		defer close(c)
		var helper func(string)
		helper = func(input string) {
			if len(input) == n {
				return
			}
			select {
			case <-done:
				return
			default:
			}
			for _, char := range alphabet {
				s := input + string(char)
				c <- s
				helper(s)
			}
		}
		helper("")
		wg.Done()
	}()

	return c
}
