package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/julienschmidt/httprouter"
)

type appType struct {
	env          string
	authUrl      string
	graphUrl     string
	clientId     string
	clientSecret string
	scope        string
	code         string
	tokenAccess  string
	tokenId      string
	tokenExpires int
}

type appUserType struct {
	givenName         string
	surname           string
	displayName       string
	id                string
	userPrincipalName string
}

var appVars = appType{
	env:          os.Getenv("APP_ENV"),
	authUrl:      "https://login.microsoftonline.com/common/oauth2/v2.0/",
	graphUrl:     "https://graph.microsoft.com/v1.0/",
	clientId:     os.Getenv("MSFT_CLIENT_ID"),
	clientSecret: os.Getenv("MSFT_CLIENT_SECRET"),
	scope:        "openid User.Read Contacts.Read Contacts.Read.Shared Contacts.ReadWrite Contacts.ReadWrite.Shared",
	code:         "",
	tokenAccess:  "",
	tokenId:      "",
	tokenExpires: 0}

var appUser = appUserType{
	givenName:         "",
	surname:           "",
	displayName:       "",
	id:                "",
	userPrincipalName: ""}

const (
	headerContText  = "text/plain; charset=utf-8"
	headerContJson  = "application/json"
	headerContHtml  = "text/html; charset=utf-8"
	headerContForm  = "application/x-www-form-urlencoded"
	headerContAgent = "my_agent/1.0"
)

func dbg(txt string) {
	if appVars.env != "production" {
		log.Println(txt)
	}
}

func buildHttpHeader(request *http.Request) *http.Request {
	dbg("execute func buildHttpHeader")

	request.Header.Add("Content-Type", headerContJson)
	request.Header.Add("User-Agent", "my_agent/1.0")
	request.Header.Add("Authorization", "Bearer "+appVars.tokenAccess)
	request.Header.Add("Accept", headerContJson)
	request.Header.Add("X-AnchorMailbox", appUser.userPrincipalName)

	return request
}

func getUrlScheme(r *http.Request) string {
	dbg("execute func getUrlScheme")

	if r.URL.Scheme == "" && r.TLS != nil {
		return "https://"
	}
	return "http://"
}

func getList(w http.ResponseWriter, r *http.Request) {
	dbg("execute func getList")

	r.URL.Scheme = getUrlScheme(r)

	paramsGET := url.Values{}
	paramsGET.Set("$top", "100")
	paramsGET.Add("$select", "givenName,surname,emailAddresses")
	paramsGET.Add("$orderby", "givenName ASC")
	dbg("paramsGET.Encode()" + paramsGET.Encode())
	requestGET, err := http.NewRequest("GET", appVars.graphUrl+"me/contacts", strings.NewReader(paramsGET.Encode()))
	if err != nil {
		fmt.Printf("http.NewRequest() error: %v\n", err)
	}

	requestGET = buildHttpHeader(requestGET)

	clientHTTP := &http.Client{}
	responseGET, err := clientHTTP.Do(requestGET)
	if err != nil {
		fmt.Printf("http.Do() error: %v\n", err)
	}
	defer responseGET.Body.Close()

	dataGET, err := ioutil.ReadAll(responseGET.Body)
	if err != nil {
		fmt.Printf("ioutil.ReadAll() error: %v\n", err)
	}
	dbg("read responseGET.Body successfully: " + string(dataGET))
	inGET := dataGET
	var raw map[string]interface{}
	json.Unmarshal(inGET, &raw)

}

func getMe(w http.ResponseWriter, r *http.Request) {
	dbg("execute func getMe")

	r.URL.Scheme = getUrlScheme(r)

	paramsGET := url.Values{}
	paramsGET.Set("$select", "displayName,mail")
	dbg("paramsGET.Encode()" + paramsGET.Encode())
	requestGET, err := http.NewRequest("GET", appVars.graphUrl+"me", strings.NewReader(paramsGET.Encode()))
	if err != nil {
		fmt.Printf("http.NewRequest() error: %v\n", err)
	}

	requestGET = buildHttpHeader(requestGET)

	clientHTTP := &http.Client{}
	responseGET, err := clientHTTP.Do(requestGET)
	if err != nil {
		fmt.Printf("http.Do() error: %v\n", err)
	}
	defer responseGET.Body.Close()

	dataGET, err := ioutil.ReadAll(responseGET.Body)
	if err != nil {
		fmt.Printf("ioutil.ReadAll() error: %v\n", err)
	}
	dbg("read responseGET.Body successfully: " + string(dataGET))
	inGET := dataGET
	var raw map[string]interface{}
	json.Unmarshal(inGET, &raw)

	if raw["error_description"] == nil && raw["error"] == nil {
		appUser.userPrincipalName = raw["userPrincipalName"].(string)
		appUser.givenName = raw["givenName"].(string)
		appUser.surname = raw["surname"].(string)
		appUser.id = raw["id"].(string)
		appUser.displayName = raw["displayName"].(string)
	}

}

func getCode(w http.ResponseWriter, r *http.Request) {
	dbg("execute func getCode")
	dbg("go url: " + appVars.authUrl + "authorize/?")

	r.URL.Scheme = getUrlScheme(r)

	dbg("return url: " + r.URL.Scheme + r.Host + r.URL.Path)
	dbg("Access Token: " + appVars.tokenAccess)
	if appVars.tokenAccess == "" {
		paramsGET := url.Values{}
		paramsGET.Set("client_id", appVars.clientId)
		paramsGET.Add("scope", appVars.scope)
		paramsGET.Add("response_type", "code")
		paramsGET.Add("redirect_uri", r.URL.Scheme+r.Host+r.URL.Path)
		http.Redirect(w, r, appVars.authUrl+"authorize/?"+paramsGET.Encode(), http.StatusSeeOther)
	}
}

func getTokenAuth(w http.ResponseWriter, r *http.Request) bool {
	dbg("execute func getTokenAuth")

	r.URL.Scheme = getUrlScheme(r)

	paramsPOST := url.Values{}
	paramsPOST.Set("scope", appVars.scope)
	paramsPOST.Add("client_id", appVars.clientId)
	paramsPOST.Add("client_secret", appVars.clientSecret)
	paramsPOST.Add("code", appVars.code)
	paramsPOST.Add("redirect_uri", r.URL.Scheme+r.Host+r.URL.Path)
	paramsPOST.Add("grant_type", "authorization_code")
	dbg("paramsPOST.Encode()" + paramsPOST.Encode())
	requestPOST, err := http.NewRequest("POST", appVars.authUrl+"token", strings.NewReader(paramsPOST.Encode()))
	if err != nil {
		fmt.Printf("http.NewRequest() error: %v\n", err)
		return false
	}

	requestPOST.Header.Add("Content-Type", headerContForm)
	clientHTTP := &http.Client{}
	responsePOST, err := clientHTTP.Do(requestPOST)
	if err != nil {
		fmt.Printf("http.Do() error: %v\n", err)
		return false
	}
	defer responsePOST.Body.Close()

	dataPOST, err := ioutil.ReadAll(responsePOST.Body)
	if err != nil {
		fmt.Printf("ioutil.ReadAll() error: %v\n", err)
		return false
	}
	dbg("read responsePOST.Body successfully: " + string(dataPOST))
	inPOST := dataPOST
	var raw map[string]interface{}
	json.Unmarshal(inPOST, &raw)

	if raw["error_description"] == nil && raw["error"] == nil {
		appVars.tokenAccess = string(raw["access_token"].(string))
		dbg("retrieve TOKEN_ACCESS: " + appVars.tokenAccess)
		appVars.tokenId = raw["id_token"].(string)
		dbg("retrieve TOKEN_ID: " + appVars.tokenId)
		appVars.tokenExpires = raw["expires_in"].(int)
		dbg("retrieve TOKEN_EXPIRES: " + string(appVars.tokenExpires))
		return true
	} else {
		dbg("error from tokens: " + raw["error"].(string))
		getCode(w, r)
	}
	return false
}

func getToken(w http.ResponseWriter, r *http.Request) {
	dbg("execute func getToken")

	getTokenAuth(w, r)

	if appVars.tokenAccess != "" {
		dbg("tokens are retrieved right")
		getMe(w, r)
		getList(w, r)
	} else {
		dbg("problems returnin tokens")
	}

}

func handleGET(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	dbg("execute func handleGET")

	if r.URL.Query().Get("code") != "" {
		dbg("get param code")
		appVars.code = r.URL.Query().Get("code")
		getToken(w, r)
	} else {
		getCode(w, r)
	}

}

func handlePOST(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	dbg("execute func handlePOST")
}

func main() {
	dbg(">> BEGINS >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")

	router := httprouter.New()
	router.GET("/", handleGET)
	router.POST("/", handlePOST)

	if appVars.env == "production" {
		dbg("Running server now in production mode")
	} else {
		dbg("Running server now in dev mode")
	}

	http.ListenAndServe(":8080", router)
}
