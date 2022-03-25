package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/sessions"
	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var _ = GetOauthDetails()

func GetOauthDetails() error {
	loadEnv()
	return nil
}

var (
	googleOauthConfig = &oauth2.Config{
		RedirectURL:  "http://localhost:8080/callback",
		ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"},
		Endpoint:     google.Endpoint,
	}
	randomState = GenerateRandomString(32)
)

var store = sessions.NewCookieStore([]byte(os.Getenv("SESSION_KEY")))
var session_name = "google-oauth"

func GenerateRandomString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return base64.URLEncoding.EncodeToString(b)
}

func loadEnv() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("failed call to godotenv.Load() with error: %v", err)
	}
}

func main() {
	// loadEnv()
	http.HandleFunc("/", handleHome)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/callback", handleCallback)
	http.Handle("/dashboard", AuthMiddleware(http.HandlerFunc(dashboardHandler)))
	http.Handle("/logout", AuthMiddleware(http.HandlerFunc(logoutHandler)))
	http.ListenAndServe(":8080", nil)
}

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, session_name)
		if user, ok := session.Values["fullname"]; !ok || user == "" {
			fmt.Printf("no session values, ok=%t user=%s\n", ok, user)
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, session_name)
	data := map[string]interface{}{
		"fullname": session.Values["fullname"],
	}
	tmpl := template.Must(template.ParseFiles("html/dashboard.html"))
	tmpl.Execute(w, data)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, session_name)
	session.Values["fullname"] = ""
	session.Save(r, w)
	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("html/home.html"))
	data := map[string]interface{}{
		// "title": "Hello",
		// "random": randomState,
	}
	tmpl.Execute(w, data)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, session_name)
	if user, ok := session.Values["fullname"]; ok && user != "" {
		fmt.Printf("already logged in user=%s\n", user)
		http.Redirect(w, r, "/dashboard", http.StatusTemporaryRedirect)
		return
	}
	url := googleOauthConfig.AuthCodeURL(randomState)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	if r.FormValue("state") != randomState {
		fmt.Println("state is not valid")
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	token, err := googleOauthConfig.Exchange(context.TODO(), r.FormValue("code"))
	if err != nil {
		fmt.Printf("could not get token: %s\n", err.Error())
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	resp, err := http.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + token.AccessToken)
	if err != nil {
		fmt.Printf("could not authenticate: %s\n", err.Error())
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	defer resp.Body.Close()

	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("could not parse response: %s\n", err.Error())
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	var contentMap map[string]interface{}
	if err := json.Unmarshal(content, &contentMap); err != nil {
		fmt.Printf("could not unmarshal response: %s\n", err.Error())
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	session, _ := store.Get(r, session_name)
	session.Values["user"] = contentMap["email"]
	session.Values["fullname"] = contentMap["name"]
	session.Save(r, w)

	fmt.Println(contentMap)
	http.Redirect(w, r, "/dashboard", http.StatusTemporaryRedirect)
	// return
}
