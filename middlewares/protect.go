package middlewares

import (
	"fmt"
	"strings"
	"time"

	"github.com/woaitsAryan/fiber-template-go/cache"
	"github.com/woaitsAryan/fiber-template-go/config"
	"github.com/woaitsAryan/fiber-template-go/helpers"
	"github.com/woaitsAryan/fiber-template-go/initializers"
	"github.com/woaitsAryan/fiber-template-go/models"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"
)

func verifyToken(tokenString string, user *models.User) (*models.User, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(initializers.CONFIG.JWT_SECRET), nil
	})

	if err != nil {
		return nil, &fiber.Error{Code: fiber.StatusForbidden, Message: config.TOKEN_EXPIRED_ERROR}
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if float64(time.Now().Unix()) > claims["exp"].(float64) {
			return nil, &fiber.Error{Code: fiber.StatusForbidden, Message: "Your token has expired."}
		}

		userID, ok := claims["sub"].(string)
		if !ok {
			return nil, &fiber.Error{Code: fiber.StatusUnauthorized, Message: "Invalid user ID in token claims."}
		}

		userInCache, err := cache.GetUser(userID)
		if err == nil {
			user = userInCache
		} else {
			if err := initializers.DB.First(&user, "id = ?", userID).Error; err != nil {
				if err == gorm.ErrRecordNotFound {
					return nil, &fiber.Error{Code: fiber.StatusUnauthorized, Message: "User of this token no longer exists"}
				}
				return nil, helpers.AppError{Code: fiber.StatusInternalServerError, Message: config.DATABASE_ERROR, LogMessage: err.Error(), Err: err}
			}

			go cache.SetUser(user.ID.String(), user)
		}

		return user, nil
	} else {
		return nil, &fiber.Error{Code: fiber.StatusForbidden, Message: "Invalid Token"}
	}
}

func Protect(c *fiber.Ctx) error {
	authHeader := c.Get("Authorization")
	tokenArr := strings.Split(authHeader, " ")

	if len(tokenArr) != 2 {
		return &fiber.Error{Code: fiber.StatusUnauthorized, Message: "You are Not Logged In."}
	}

	tokenString := tokenArr[1]

	var user *models.User
	user, err := verifyToken(tokenString, user)
	if err != nil {
		return err
	}

	c.Set("loggedInUserID", user.ID.String())

	return c.Next()
}
