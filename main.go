package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"

	"github.com/cossacklabs/themis/gothemis/cell"
)

func main() {
	var (
		email    string
		password string
	)
	flag.StringVar(&email, "email", "", "your email")
	flag.StringVar(&password, "pass", "", "your password")
	flag.Parse()

	hasher := sha256.New()
	hasher.Write([]byte(password))
	passwordHash := hex.EncodeToString(hasher.Sum(nil))

	// Get access token by signing in!
	accessToken, err := signIn(email, passwordHash)
	if err != nil {
		log.Fatalln("Probably wrong email or password!", err)
	}
	// Get encrypted app key with access token!
	encryptedAppKey, err := getAppKey(accessToken)
	if err != nil {
		log.Fatalln("Error while trying to get encrypted app key!", err)
	}
	// Get encrypted mnemonic with access token!
	encryptedMnemonic, err := getMnemonics(accessToken)
	if err != nil {
		log.Fatalln("Error while trying to get encrypted mnemonic key!", err)
	}

	// Decrypt app key!
	seal1, err := cell.SealWithPassphrase(password)
	if err != nil {
		log.Fatalln("Empty password!")
	}
	rawAppKey, err := seal1.Decrypt(encryptedAppKey, nil)
	if err != nil {
		log.Fatalln("Error while trying to decrypt encrypted app key!", err)
	}

	// Decrypt mnemonic!
	seal2, err := cell.SealWithPassphrase(string(rawAppKey))
	if err != nil {
		log.Fatalln("Empty app key!")
	}
	data, err := seal2.Decrypt(encryptedMnemonic, nil)
	if err != nil {
		log.Fatalln("Error while trying to decrypt encrypted mnemonic!")
	}

	// Print it!
	fmt.Println("Your mnemonic: " + string(data))
}

func signIn(email, passwordHash string) (string, error) {
	type SignInRequest struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	type SignInResponse struct {
		UserID      int    `json:"user_id"`
		AccessToken string `json:"access_token"`
	}

	signinReq := &SignInRequest{
		Email:    email,
		Password: passwordHash,
	}
	buf := bytes.NewBuffer(nil)
	if err := json.NewEncoder(buf).Encode(signinReq); err != nil {
		return "", err
	}

	req, err := http.NewRequest(http.MethodPost, "https://account-api-chad.solarlabs.ee/auth/signIn", buf)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var signInResp *SignInResponse
	if err := json.NewDecoder(resp.Body).Decode(&signInResp); err != nil {
		return "", err
	}

	return signInResp.AccessToken, nil
}

func getAppKey(accessToken string) ([]byte, error) {
	type GetAppKeyResponse struct {
		EncryptedAppKey []byte `json:"encrypted_app_key"`
	}

	req, err := http.NewRequest(http.MethodGet, "https://account-api-chad.solarlabs.ee/profile/getAppKey", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Authorization", accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var getAppKeyResp *GetAppKeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&getAppKeyResp); err != nil {
		return nil, err
	}

	return getAppKeyResp.EncryptedAppKey, nil
}

func getMnemonics(accessToken string) ([]byte, error) {
	type GetMnemonicsResponse struct {
		EncryptedMnemonic []byte `json:"encrypted_mnemonic"`
	}

	req, err := http.NewRequest(http.MethodGet, "https://account-api-chad.solarlabs.ee/blockchain/getMnemonics?network=DVPN", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Authorization", accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var getMnemonicsResp []*GetMnemonicsResponse
	if err := json.NewDecoder(resp.Body).Decode(&getMnemonicsResp); err != nil {
		return nil, err
	}

	if len(getMnemonicsResp) > 0 {
		return getMnemonicsResp[0].EncryptedMnemonic, nil
	} else {
		return nil, errors.New("wrong length")
	}
}
