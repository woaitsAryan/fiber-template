package validators

import (
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/woaitsAryan/fiber-template-go/helpers"
	"github.com/woaitsAryan/fiber-template-go/initializers"
	"github.com/woaitsAryan/fiber-template-go/models"
	"github.com/woaitsAryan/fiber-template-go/schemas"
	"gorm.io/gorm"
)

func UserCreateValidator(c *fiber.Ctx) error {
	var reqBody schemas.UserCreateSchema

	if err := c.BodyParser(&reqBody); err != nil {
		return &fiber.Error{Code: 400, Message: "Invalid Req Body"}
	}

	if err := helpers.Validate[schemas.UserCreateSchema](reqBody); err != nil {
		return &fiber.Error{Code: 400, Message: err.Error()}
	}

	if reqBody.Password != reqBody.ConfirmPassword {
		return &fiber.Error{Code: 400, Message: "Passwords do not match."}
	}

	var user models.User
	initializers.DB.Session(&gorm.Session{SkipHooks: true}).First(&user, "email = ?", reqBody.Email)
	if user.ID != uuid.Nil {
		return &fiber.Error{Code: 400, Message: "User with this Email ID already exists"}
	}

	initializers.DB.Session(&gorm.Session{SkipHooks: true}).First(&user, "username = ?", reqBody.Username)
	if user.ID != uuid.Nil {
		return &fiber.Error{Code: 400, Message: "User with this Username already exists"}
	}

	return c.Next()
}
