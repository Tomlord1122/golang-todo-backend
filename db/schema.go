package db

import "gorm.io/gorm"

type User struct {
	gorm.Model
	Username     string `json:"username" gorm:"unique"`
	Email        string `json:"email" gorm:"unique"`
	UserID       uint   `json:"user_id"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	Todos        []Todo `json:"todos" gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE"`
}

type CreateUserRequest struct {
	Username  string `json:"username"`
	Email     string `json:"email"`
	SessionId string `json:"session_id"`
}

type Todo struct {
	// Make sure the field name is the same as the JSON key -> Check the type in the frontend
	gorm.Model
	Task                    string `json:"Task"`
	Award                   string `json:"Award"`
	Completed               bool   `json:"Completed"`
	TargetCount             int    `json:"TargetCount"`
	CurrentCount            int    `json:"CurrentCount"`
	Percentage              int    `json:"Percentage"`
	ShowCompletionAnimation bool   `json:"ShowCompletionAnimation"`
	UserID                  uint   `json:"user_id" gorm:"not null"`
	User                    User   `json:"user" gorm:"constraint:OnDelete:CASCADE"`
}
