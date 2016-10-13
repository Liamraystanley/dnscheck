package main

import "math/rand"

const (
	letters      = "bcdfghjklmnpqrstvwxyz" // ascii alpha w/o vowels
	vowels       = "aeiou"
	genTypeChar  = 0
	genTypeVowel = 1
)

func genWord(min, max int) string {
	word := ""
	syllables := min + int(rand.Float64()*(float64(max)-float64(min)))

	for i := 0; i < syllables; i++ {
		x := rand.Float32()

		if x < 0.333 {
			word += genWordPart(genTypeVowel) + genWordPart(genTypeChar)
			continue
		}

		if x < 0.666 {
			word += genWordPart(genTypeChar) + genWordPart(genTypeVowel)
			continue
		}

		word += genWordPart(genTypeChar) + genWordPart(genTypeVowel) + genWordPart(genTypeChar)
	}

	return word
}

func genWordPart(flag int) string {
	switch flag {
	case genTypeChar:
		return string(letters[rand.Intn(len(letters))])
	case genTypeVowel:
		return string(vowels[rand.Intn(len(vowels))])
	default:
		return ""
	}
}
