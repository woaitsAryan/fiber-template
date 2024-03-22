package initializers

import (
	"fmt"

	"github.com/woaitsAryan/fiber-template-go/models"
)

func AutoMigrate() {
	fmt.Println("\nStarting Migrations...")
	DB.AutoMigrate(
		&models.User{},

	)
	fmt.Println("Migrations Finished!")
}
