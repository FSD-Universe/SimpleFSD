// Package voice
package voice

var ICAOLettersMap = map[string]string{
	"A": "Alpha", "B": "Bravo", "C": "Charlie", "D": "Delta", "E": "Echo", "F": "Foxtrot", "G": "Golf", "H": "Hotel",
	"I": "India", "J": "Juliet", "K": "Kilo", "L": "Lima", "M": "Mike", "N": "November", "O": "Oscar", "P": "Papa",
	"Q": "Quebec", "R": "Romeo", "S": "Sierra", "T": "Tango", "U": "Uniform", "V": "Victor", "W": "Whiskey",
	"X": "X-ray", "Y": "Yankee", "Z": "Zulu",
}

var ICAODigitsMap = map[string]string{
	"0": "zero", "1": "one", "2": "two", "3": "tree", "4": "four", "5": "five", "6": "six", "7": "seven", "8": "eight", "9": "nine",
}

type ATISTransformerInterface interface {
	// Transform 将 D-ATIS 文本转化为 ATIS 结构体
	Transform(text string) *ATIS
}

type ATISGeneratorInterface interface {
	// Generate 将 ATIS 结构体转化为 voice ATIS 文本
	Generate(atis *ATIS) string
}

type TTSInterface interface {
	// Synthesize 将文本合成为音频数据，返回可直接放入语音 UDP 载荷的原始字节
	Synthesize(text string) (audio []byte, err error)
}
