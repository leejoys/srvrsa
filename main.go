package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
)

// Request is the struct for the POST request body
type Request struct {
	ID        string `json:"id"`
	Text      string `json:"text"`
	Signature string `json:"signature"`
}

// Response is the struct for the JSON response
type Response struct {
	Processed string `json:"processed"`
	Code      int    `json:"code"`
	Reason    string `json:"reason"`
	Signature string `json:"signature"`
}

// handleCheckoutInsert is the handler for the "/checkout/insert" endpoint
func handleCheckoutInsert(w http.ResponseWriter, r *http.Request) {
	// Check if the request method is POST
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// Decode the request body into a Request struct
	var req Request
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Verify the signature of the request
	if !verifySignature(req) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Process the text by converting it to upper case
	processed := strings.ToUpper(req.Text)

	// Create a Response struct with the processed text, code and reason
	resp := Response{
		Processed: processed,
		Code:      http.StatusOK,
		Reason:    "success",
	}

	// Sign the response with a signature
	resp = signResponse(resp)

	// Encode the Response struct into JSON and write it to the response writer
	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(resp)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func main() {
	// Create a new mux router and register the handler for "/checkout/insert" endpoint
	mux := http.NewServeMux()
	mux.HandleFunc("/checkout/insert", handleCheckoutInsert)

	// Start listening on port 3828 and log any errors
	fmt.Println("Listening on port 3828")
	log.Fatal(http.ListenAndServe(":3828", mux))
}

// verifySignature is a function that verifies the signature of a request
func verifySignature(req Request) bool {
	// Decode the signature from base64 to bytes
	signature, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		return false
	}

	// Get the public key of the client (for example, from a file or a database)
	publicKey, err := getPublicKey(req.ID)
	if err != nil {
		return false
	}

	// Create a hash from the id and text fields of the request
	hashed := createHash(req.ID + ":" + req.Text + ";")

	// Verify the signature using the public key, the hash and the SHA256 algorithm
	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], signature)
	if err != nil {
		return false
	}

	// Return true if the signature is valid
	return true
}

// signResponse is a function that signs the response with a signature
func signResponse(resp Response) Response {
	// Create a hash from the processed, code and reason fields of the response
	hashed := createHash(resp.Processed + ":" + strconv.Itoa(resp.Code) + ":" + resp.Reason + ";")

	// Sign the hash using our private key and the SHA256 algorithm
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return resp
	}

	// Encode the signature in base64 and add it to the signature field of the response
	resp.Signature = base64.StdEncoding.EncodeToString(signature)

	// Return the signed response
	return resp
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
