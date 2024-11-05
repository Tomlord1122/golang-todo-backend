package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"svelte-todo-backend/db"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/markbates/goth/gothic"
	"golang.org/x/exp/rand"
)

type contextKey string

const userIDKey contextKey = "user_id"

func (s *Server) RegisterRoutes() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.Logger)

	// Use environment variable for allowed origins
	allowedOrigins := []string{"http://localhost:5173"}
	if prodOrigin := os.Getenv("FRONTEND_URL"); prodOrigin != "" {
		allowedOrigins = append(allowedOrigins, prodOrigin)
	}

	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   allowedOrigins,
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	r.Route("/auth", func(r chi.Router) {
		r.Get("/{provider}/callback", s.getAuthCallbackFunction)
		r.Get("/{provider}", s.beginAuthProviderCallback)
		r.Get("/logout/{provider}", s.logOutFunction)
	})

	// Protected routes
	r.Group(func(r chi.Router) {
		r.Use(s.AuthMiddleware)

		// Add your protected routes here
		r.Route("/api", func(r chi.Router) {
			r.Get("/todos", s.getTodos) // Example protected endpoint
			r.Post("/todos", s.createTodo)
			r.Put("/todos/{id}", s.updateTodo)
			r.Delete("/todos/{id}", s.deleteTodo)
		})
	})
	return r
}

func (s *Server) getAuthCallbackFunction(w http.ResponseWriter, r *http.Request) {
	// Ensure proper CORS headers
	// w.Header().Set("Access-Control-Allow-Credentials", "true")

	user, err := gothic.CompleteUserAuth(w, r)
	if err != nil {
		log.Printf("Auth error: %v", err)
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	userID := uint(rand.Intn(900000000) + 100000000) // Generate a random 9-digit integer

	// Create or update user in database
	var dbUser db.User
	db := db.GetDB()
	db.Where("email = ?", user.Email).First(&dbUser)
	if dbUser.ID == 0 {
		dbUser.Username = user.Name
		dbUser.Email = user.Email
		dbUser.UserID = userID
		dbUser.AccessToken = user.AccessToken
		dbUser.RefreshToken = user.RefreshToken
		db.Create(&dbUser)
	}

	// Set secure cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    dbUser.AccessToken,
		Path:     "/",
		MaxAge:   86400,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	redirectURL := (os.Getenv("FRONTEND_URL"))
	if redirectURL == "" {
		redirectURL = "http://localhost:5173"
	}

	redirectURL = fmt.Sprintf("%s/auth/callback?username=%s&email=%s&id=%s&refresh_token=%s&access_token=%s",
		redirectURL,
		url.QueryEscape(user.Name),
		url.QueryEscape(dbUser.Email),
		url.QueryEscape(strconv.Itoa(int(dbUser.UserID))),
		url.QueryEscape(dbUser.RefreshToken),
		url.QueryEscape(dbUser.AccessToken))

	http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
}

func (s *Server) logOutFunction(w http.ResponseWriter, r *http.Request) {
	gothic.Logout(w, r)

	redirectURL := os.Getenv("FRONTEND_URL")
	if redirectURL == "" {
		redirectURL = "http://localhost:5173"
	}

	http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
}

func (s *Server) beginAuthProviderCallback(w http.ResponseWriter, r *http.Request) {
	// Begin auth flow
	gothic.BeginAuthHandler(w, r)
}

func (s *Server) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get auth token from cookie
		cookie, _ := r.Cookie("auth_token")
		// Validate token against database
		var dbUser db.User
		db := db.GetDB()
		if err := db.Where("access_token = ?", cookie.Value).First(&dbUser).Error; err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		// Add user info to request context
		ctx := context.WithValue(r.Context(), userIDKey, dbUser.UserID) // ctx = r.Context() + dbUser.UserID
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) getTodos(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value(userIDKey).(uint) // userID = r.Context().Value(userIDKey) = dbUser.UserID
	if userID == 0 {
		http.Error(w, "Unauthorized - No user ID", http.StatusUnauthorized)
		return
	}
	var dbUser db.User
	db := db.GetDB()
	db.Where("user_id = ?", userID).First(&dbUser)
	db.Model(&dbUser).Association("Todos").Find(&dbUser.Todos)
	fmt.Printf("dbUser.Todos: %v\n", dbUser.Todos)
	json.NewEncoder(w).Encode(dbUser.Todos)

}

func (s *Server) createTodo(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value(userIDKey).(uint) // get UserID from context
	if userID == 0 {
		http.Error(w, "Unauthorized - No user ID", http.StatusUnauthorized)
		return
	}
	var todo db.Todo
	if err := json.NewDecoder(r.Body).Decode(&todo); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	fmt.Printf("todo: %v\n", todo)
	var dbUser db.User
	db := db.GetDB()
	db.Where("user_id = ?", userID).First(&dbUser) // get UserId from database to avoid postgreSQL error
	todo.UserID = dbUser.ID

	if err := db.Create(&todo).Error; err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(todo)
}

func (s *Server) updateTodo(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value(userIDKey).(uint)
	todoID := chi.URLParam(r, "id")

	var todo db.Todo
	if err := json.NewDecoder(r.Body).Decode(&todo); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var dbUser db.User
	db := db.GetDB()
	db.Where("user_id = ?", userID).First(&dbUser)
	// It will only update the fields that are not nil
	result := db.Where("id = ? AND user_id = ?", todoID, dbUser.ID).Updates(&todo)
	if result.Error != nil {
		http.Error(w, result.Error.Error(), http.StatusInternalServerError)
		return
	}
	if result.RowsAffected == 0 {
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(todo)
}

func (s *Server) deleteTodo(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value(userIDKey).(uint)
	todoID := chi.URLParam(r, "id")
	var todo db.Todo
	var dbUser db.User
	db := db.GetDB()
	db.Where("user_id = ?", userID).First(&dbUser)
	result := db.Where("id = ? AND user_id = ?", todoID, dbUser.ID).Delete(&todo)
	if result.Error != nil {
		http.Error(w, result.Error.Error(), http.StatusInternalServerError)
		return
	}
	if result.RowsAffected == 0 {
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func cleanupSoftDelete() {
	dbConnection := db.GetDB()

	// Permanently delete soft deleted todos
	if err := dbConnection.Unscoped().Where("deleted_at IS NOT NULL").Delete(&db.Todo{}).Error; err != nil {
		log.Printf("Error deleting soft deleted todos: %v", err)
	} else {
		log.Println("Soft deleted todos deleted successfully")
	}

	// Permanently delete users with no todos
	if err := dbConnection.Unscoped().Where("todos_count = 0").Delete(&db.User{}).Error; err != nil {
		log.Printf("Error deleting users with no todos: %v", err)
	} else {
		log.Println("Users with no todos deleted successfully")
	}
}
