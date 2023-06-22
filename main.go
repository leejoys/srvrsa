package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
)

// Env is a struct that holds the fields from env.json
type Env struct {
	PrivateKey      string `json:"private_key"`
	PublicKey       string `json:"public_key"`
	ClientPublicKey string `json:"client_public_key"`
}

// Request is the struct for the POST request body
type Request struct {
	ID        []string `json:"id"`
	Text      []string `json:"text"`
	Signature []string `json:"signature"`
}

// Response is the struct for the JSON response
type Response struct {
	Processed string `json:"processed"`
	Code      int    `json:"code"`
	Reason    string `json:"reason"`
	Signature string `json:"signature"`
}

// readEnv is a function that reads env.json and returns an Env struct
func readEnv() (Env, error) {
	// Declare an Env variable
	var env Env

	// Read the file content
	content, err := os.ReadFile("env.json")
	if err != nil {
		return env, fmt.Errorf("Error when opening file: %s", err.Error())
	}

	// Unmarshal the JSON data into the Env variable
	err = json.Unmarshal(content, &env)
	if err != nil {
		return env, fmt.Errorf("Error during Unmarshal(): %s", err.Error())
	}

	// Return the Env variable
	return env, nil
}

// handleCheckoutInsert is the handler for the "/checkout/insert" endpoint
func handleCheckoutInsert(env Env) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Check if the request method is POST
		if r.Method != http.MethodPost {
			log.Println("!= http.MethodPost")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		// Decode the request body into a Request struct
		var req Request
		err := r.ParseForm()
		if err != nil {
			log.Println("r.ParseForm: ", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		values := r.Form

		log.Println(values)

		jsonData, err := json.Marshal(values)
		if err != nil {
			log.Println("json.Marshal: ", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		log.Println(jsonData)

		err = json.Unmarshal(jsonData, &req)
		if err != nil {
			log.Println("Decode: ", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		log.Println(req)

		if len(req.ID) < 1 ||
			len(req.Text) < 1 ||
			len(req.Signature) < 1 {
			log.Println("Bad request")
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Verify the signature of the request
		if !verifySignature(req, env) {
			log.Println("!verifySignature")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Process the text by converting it to upper case
		processed := strings.ToUpper(req.Text[0])

		// Create a Response struct with the processed text, code and reason
		resp := Response{
			Processed: processed,
			Code:      http.StatusOK,
			Reason:    "success",
		}

		// Sign the response with a signature
		resp, err = signResponse(resp, env)
		if err != nil {
			log.Println("signResponse: ", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// Encode the Response struct into JSON and write it to the response writer
		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(resp)
		if err != nil {
			log.Println("Encode: ", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}
}

func main() {

	// Read the Envs
	env, err := readEnv()
	if err != nil {
		log.Fatal(err)
	}

	// Create a new mux router and register the handler for "/checkout/insert" endpoint
	mux := http.NewServeMux()
	mux.HandleFunc("/checkout/insert", handleCheckoutInsert(env))

	// Start listening on port 3828 and log any errors
	fmt.Println("Listening on port 3828")
	log.Fatal(http.ListenAndServe(":3828", mux))
}

// verifySignature is a function that verifies the signature of a request
func verifySignature(req Request, env Env) bool {
	// Decode the signature from base64 to bytes
	signature, err := base64.StdEncoding.DecodeString(req.Signature[0])
	if err != nil {
		log.Println("DecodeString: ", err)
		return false
	}

	// // Get the public key of the client (for example, from a file or a database)
	// publicKey, err := getPublicKey(req.ID)
	// if err != nil {
	// 	return false
	// }

	publicKey, err := getClientPublicKey(env)
	if err != nil {
		log.Println("getClientPublicKey: ", err)
		return false
	}

	// Create a hash from the id and text fields of the request
	hashed := createHash("id:" + req.ID[0] + ";text:" + req.Text[0] + ";")

	// Verify the signature using the public key, the hash and the SHA256 algorithm
	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], signature)
	if err != nil {
		log.Println("VerifyPKCS1v15: ", err)
		return false
	}

	// Return true if the signature is valid
	return true
}

// signResponse is a function that signs the response with a signature
func signResponse(resp Response, env Env) (Response, error) {
	// Create a hash from the processed, code and reason fields of the response
	hashed := createHash("code:" + strconv.Itoa(resp.Code) + ";processed:" + resp.Processed + ";reason:" + resp.Reason + ";")

	privateKey, err := getPrivateKey(env)
	if err != nil {
		return resp, err
	}

	// Sign the hash using our private key and the SHA256 algorithm
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return resp, err
	}

	// Encode the signature in base64 and add it to the signature field of the response
	resp.Signature = base64.StdEncoding.EncodeToString(signature)

	// Return the signed response
	return resp, nil
}

// createHash is a helper function that creates a hash from a string using SHA256 algorithm
func createHash(s string) [32]byte {
	return sha256.Sum256([]byte(s))
}

// getPublicKey is a stub function that gets the public key of a client by id (for example, from a file or a database)
func getPublicKey(id string) (*rsa.PublicKey, error) {
	// TODO: implement the logic to get the public key of a client by id
	return nil, nil
}

// getClientPublicKey is a function that converts env.ClientPublicKey to *rsa.PublicKey
func getClientPublicKey(env Env) (*rsa.PublicKey, error) {
	// Decode the string env.ClientPublicKey from base64 to bytes
	clientPublicKeyBytes, err := base64.StdEncoding.DecodeString(env.ClientPublicKey)
	if err != nil {
		return nil, fmt.Errorf("Error when decoding the ClientPublicKey string: %s", err.Error())
	}

	// Parse the bytes into a PKIXPublicKey structure
	clientPublicKey, err := x509.ParsePKCS1PublicKey(clientPublicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("Error when parsing PKCS1PublicKey: %s", err.Error())
	}

	// Return *rsa.PublicKey
	return clientPublicKey, nil
}

// getPrivateKey is a function that converts env.PrivateKey to *rsa.PrivateKey
func getPrivateKey(env Env) (*rsa.PrivateKey, error) {
	// Decode the string env.PrivateKey from base64 to bytes
	privateKeyBytes, err := base64.StdEncoding.DecodeString(env.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("Error when decoding the PrivateKey string: %s", err.Error())
	}

	// Parse the bytes into a *rsa.PrivateKey
	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("Error when parsing PKCS1PrivateKey: %s", err.Error())
	}

	// Return *rsa.PrivateKey
	return privateKey, nil
}
