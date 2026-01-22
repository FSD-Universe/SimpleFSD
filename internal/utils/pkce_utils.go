package utils

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

type ChallengeMethod string

const (
	S256  ChallengeMethod = "S256"
	Plain ChallengeMethod = "plain"
)

type PKCE struct {
	codeVerifier    string
	codeChallenge   string
	challengeMethod ChallengeMethod
}

func NewPKCE() *PKCE {
	return &PKCE{
		challengeMethod: S256,
	}
}

func NewPKCEWithVerifier(verifier string) *PKCE {
	return &PKCE{
		codeVerifier:    verifier,
		challengeMethod: S256,
	}
}

func (g *PKCE) GenerateCodeVerifier() error {
	data := make([]byte, 32)
	_, err := rand.Read(data)
	if err != nil {
		return err
	}

	g.codeVerifier = base64.RawURLEncoding.EncodeToString(data)
	return nil
}

func (g *PKCE) GenerateCodeChallenge() {
	switch g.challengeMethod {
	case Plain:
		g.codeChallenge = g.codeVerifier
	case S256:
		fallthrough
	default:
		hash := sha256.Sum256([]byte(g.codeVerifier))
		g.codeChallenge = base64.RawURLEncoding.EncodeToString(hash[:])
	}
}

func (g *PKCE) VerifyChallenge(challenge string) error {
	if challenge == "" || g.codeVerifier == "" {
		return errors.New("challenge or verifier cannot be empty")
	}

	switch g.challengeMethod {
	case Plain:
		if challenge != g.codeVerifier {
			return errors.New("verifier does not match challenge")
		}
		return nil
	case S256:
		hash := sha256.Sum256([]byte(g.codeVerifier))
		computedChallenge := base64.RawURLEncoding.EncodeToString(hash[:])
		if computedChallenge != challenge {
			return errors.New("verifier does not match challenge")
		}
		return nil
	}
	return errors.New("unsupported challenge method")
}

func (g *PKCE) GetCodeVerifier() string {
	return g.codeVerifier
}

func (g *PKCE) GetCodeChallenge() string {
	return g.codeChallenge
}

func (g *PKCE) GetChallengeMethod() string {
	return string(g.challengeMethod)
}

func (g *PKCE) SetChallengeMethod(method ChallengeMethod) {
	g.challengeMethod = method
}
