package models

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID                        uuid.UUID        `gorm:"type:uuid;default:uuid_generate_v4();primary_key" json:"id"`
	Name                      string           `gorm:"type:text;not null" json:"name"`
	Username                  string           `gorm:"type:text;unique;not null" json:"username"`
	Email                     string           `gorm:"unique;not null" json:"-"`
	Password                  string           `json:"-"`
	CreatedAt                 time.Time        `gorm:"default:current_timestamp;index:idx_created_at,sort:desc" json:"-"`
}