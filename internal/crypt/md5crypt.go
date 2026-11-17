// Package crypt implements the password hash the device stores in
// /etc/shadow, so a hash an attacker cracks matches the password they used.
package crypt

import (
	"crypto/md5"
	"strings"
)

const itoa64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// SaltChars are the characters a salt is made of.
const SaltChars = itoa64

// MD5 returns the md5-crypt ("$1$") hash of password, as uClibc's crypt(3)
// computes it. Only the first 8 characters of salt are used.
func MD5(password, salt string) string {
	const magic = "$1$"
	if len(salt) > 8 {
		salt = salt[:8]
	}
	pw := []byte(password)

	alt := md5.New()
	alt.Write(pw)
	alt.Write([]byte(salt))
	alt.Write(pw)
	altSum := alt.Sum(nil)

	ctx := md5.New()
	ctx.Write(pw)
	ctx.Write([]byte(magic + salt))
	for i := len(pw); i > 0; i -= 16 {
		ctx.Write(altSum[:min(16, i)])
	}
	for i := len(pw); i > 0; i >>= 1 {
		if i&1 != 0 {
			ctx.Write([]byte{0})
		} else {
			ctx.Write(pw[:1])
		}
	}
	final := ctx.Sum(nil)

	for i := range 1000 {
		c := md5.New()
		if i&1 != 0 {
			c.Write(pw)
		} else {
			c.Write(final)
		}
		if i%3 != 0 {
			c.Write([]byte(salt))
		}
		if i%7 != 0 {
			c.Write(pw)
		}
		if i&1 != 0 {
			c.Write(final)
		} else {
			c.Write(pw)
		}
		final = c.Sum(nil)
	}

	var b strings.Builder
	b.WriteString(magic + salt + "$")
	to64 := func(v uint32, n int) {
		for ; n > 0; n-- {
			b.WriteByte(itoa64[v&0x3f])
			v >>= 6
		}
	}
	for _, g := range [][3]int{{0, 6, 12}, {1, 7, 13}, {2, 8, 14}, {3, 9, 15}, {4, 10, 5}} {
		to64(uint32(final[g[0]])<<16|uint32(final[g[1]])<<8|uint32(final[g[2]]), 4)
	}
	to64(uint32(final[11]), 2)
	return b.String()
}
