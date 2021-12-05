package main

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
)

const size = 16

func genCounter(nonce []byte) [size]byte {
	var counter [size]byte
	copy(counter[:], nonce)
	counter[size-1] = 1
	return counter
}

func incrementCounter(counter [size]byte) [size]byte {
	// nonce は 12バイトな想定
	// counter全体は16バイト
	// 残り4バイトのカウントを増やす
	c := counter[size-4:]
	binary.BigEndian.PutUint32(c, binary.BigEndian.Uint32(c)+1)
	copy(counter[size-4:], c)
	return counter
}

func xors(l, r []byte) []byte {
	ll := make([]byte, len(l))
	copy(ll, l)
	for i, rv := range r {
		ll[i] ^= rv
	}
	return ll
}

func enc(plaintext, key, nonce []byte) ([]byte, error) {
	blockNum, r := len(plaintext)/size, len(plaintext)%size
	if r != 0 {
		blockNum++
	}
	// plaintext は `size` の倍数であるとは限らないため、
	// plaintext より大きい倍数になるものを暗号化対象にする
	ct := make([]byte, blockNum*size)
	copy(ct, plaintext)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	c := genCounter(nonce)

	for i := 0; i < blockNum; i++ {
		start, end := size*i, size*(i+1)
		pt := ct[start:end]

		var mask [size]byte
		block.Encrypt(mask[:], c[:])
		copy(ct[start:end], xors(pt, mask[:]))

		c = incrementCounter(c)
	}
	// 事前にもともとの `plaintext`より大きいサイズになっている可能性があるので、削る
	// 暗号化前後でバイト列の長さは変わらない
	return ct[:len(plaintext)], nil
}

func main() {
	key, _ := hex.DecodeString("000102030405060708090A0B0C0E0F101112131415161718191A1B1C1E1F2021")
	plaintext := []byte("text")

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		fmt.Println(err)
		return
	}
	enc(plaintext, key, nonce)
}
