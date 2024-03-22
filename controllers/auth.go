package controllers

import (
	"errors"
	"fmt"
	"time"

	"github.com/woaitsAryan/fiber-template-go/config"
	"github.com/woaitsAryan/fiber-template-go/helpers"
	"github.com/woaitsAryan/fiber-template-go/initializers"
	"github.com/woaitsAryan/fiber-template-go/models"
	"github.com/woaitsAryan/fiber-template-go/schemas"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

func CreateSendToken(c *fiber.Ctx, user models.User, statusCode int, message string) error {
	access_token_claim := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": user.ID,
		"crt": time.Now().Unix(),
		"exp": time.Now().Add(config.ACCESS_TOKEN_TTL).Unix(),
	})

	refresh_token_claim := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": user.ID,
		"crt": time.Now().Unix(),
		"exp": time.Now().Add(config.REFRESH_TOKEN_TTL).Unix(),
	})

	access_token, err := access_token_claim.SignedString([]byte(initializers.CONFIG.JWT_SECRET))
	if err != nil {
		go helpers.LogServerError("Error while decrypting JWT Token.", err, c.Path())
		return helpers.AppError{Code: fiber.StatusInternalServerError , Message: config.SERVER_ERROR, Err: err}
	}

	refresh_token, err := refresh_token_claim.SignedString([]byte(initializers.CONFIG.JWT_SECRET))
	if err != nil {
		go helpers.LogServerError("Error while decrypting JWT Token.", err, c.Path())
		return helpers.AppError{Code: fiber.StatusInternalServerError , Message: config.SERVER_ERROR, Err: err}
	}

	c.Cookie(&fiber.Cookie{
		Name:     "refresh_token",
		Value:    refresh_token,
		Expires:  time.Now().Add(config.REFRESH_TOKEN_TTL),
		HTTPOnly: true,
		Secure:   true,
	})

	return c.Status(statusCode).JSON(fiber.Map{
		"status":  "success",
		"message": message,
		"token":   access_token,
		"user":    user,
		"email":   user.Email,
	})
}

func SignUp(c *fiber.Ctx) error {
	var reqBody schemas.UserCreateSchema

	c.BodyParser(&reqBody)

	hash, err := bcrypt.GenerateFromPassword([]byte(reqBody.Password), 12)
	if err != nil {
		go helpers.LogServerError("Error while hashing Password.", err, c.Path())
		return helpers.AppError{Code: fiber.StatusInternalServerError , Message: config.SERVER_ERROR, Err: err}
	}

	newUser := models.User{
		Name:     reqBody.Name,
		Email:    reqBody.Email,
		Password: string(hash),
		Username: reqBody.Username,
	}

	result := initializers.DB.Create(&newUser)
	if result.Error != nil {
		return helpers.AppError{Code: fiber.StatusInternalServerError , Message: config.DATABASE_ERROR, LogMessage: result.Error.Error(), Err: result.Error}
	}

	c.Set("loggedInUserID", newUser.ID.String())

	return CreateSendToken(c, newUser, fiber.StatusCreated, "Account Created")
}

func LogIn(c *fiber.Ctx) error {
	var reqBody struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := c.BodyParser(&reqBody); err != nil {
		return &fiber.Error{Code: fiber.StatusBadRequest , Message: "Validation Failed"}
	}

	var user models.User
	if err := initializers.DB.Session(&gorm.Session{SkipHooks: true}).First(&user, "username = ?", reqBody.Username).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return &fiber.Error{Code: fiber.StatusBadRequest, Message: "No account with these credentials found."}
		} else {
			return helpers.AppError{Code: fiber.StatusInternalServerError, Message: config.DATABASE_ERROR, LogMessage: err.Error(), Err: err}
		}
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(reqBody.Password)); err != nil {
		return &fiber.Error{Code: fiber.StatusBadRequest, Message: "No account with these credentials found."}
	}

	if err := initializers.DB.Save(&user).Error; err != nil {
		return helpers.AppError{Code: fiber.StatusInternalServerError, Message: config.DATABASE_ERROR, LogMessage: err.Error(), Err: err}
	}

	return CreateSendToken(c, user, fiber.StatusOK, "Logged In")
}


func Refresh(c *fiber.Ctx) error {
	var reqBody struct {
		Token string `json:"token"`
	}

	if err := c.BodyParser(&reqBody); err != nil {
		return &fiber.Error{Code: fiber.StatusBadRequest, Message: "Validation Failed"}
	}

	access_token_string := reqBody.Token

	access_token, err := jwt.Parse(access_token_string, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(initializers.CONFIG.JWT_SECRET), nil
	})

	if err != nil && !errors.Is(err, jwt.ErrTokenExpired) {
		initializers.Logger.Infow("Token Expiration: ", "Error", err)
		return &fiber.Error{Code: fiber.StatusBadRequest, Message: config.TOKEN_EXPIRED_ERROR}
	}

	if access_token_claims, ok := access_token.Claims.(jwt.MapClaims); ok {
		access_token_userID, ok := access_token_claims["sub"].(string)
		if !ok {
			return &fiber.Error{Code: fiber.StatusUnauthorized , Message: "Invalid user ID in token claims."}
		}

		var user models.User
		err := initializers.DB.First(&user, "id = ?", access_token_userID).Error
		if err != nil {
			return helpers.AppError{Code: fiber.StatusInternalServerError, Message: config.DATABASE_ERROR, LogMessage: err.Error(), Err: err}
		}

		if user.ID == uuid.Nil {
			return &fiber.Error{Code: fiber.StatusUnauthorized , Message: "User of this token no longer exists"}
		}

		refresh_token_string := c.Cookies("refresh_token")
		if refresh_token_string == "" {
			initializers.Logger.Infow("Token Expiration: ", "Error", err)
			return &fiber.Error{Code: fiber.StatusUnauthorized , Message: config.TOKEN_EXPIRED_ERROR}
		}

		refresh_token, err := jwt.Parse(refresh_token_string, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(initializers.CONFIG.JWT_SECRET), nil
		})

		if err != nil {
			initializers.Logger.Infow("Token Expiration: ", "Error", err)
			return &fiber.Error{Code: fiber.StatusBadRequest , Message: config.TOKEN_EXPIRED_ERROR}
		}

		if refresh_token_claims, ok := refresh_token.Claims.(jwt.MapClaims); ok && refresh_token.Valid {
			refresh_token_userID, ok := refresh_token_claims["sub"].(string)
			if !ok {
				return &fiber.Error{Code: fiber.StatusUnauthorized, Message: "Invalid user ID in token claims."}
			}

			if refresh_token_userID != access_token_userID {
				initializers.Logger.Warnw("Mismatched Tokens: ", "Access Token User ID", access_token_userID, "Refresh Token User ID", refresh_token_userID)
				return &fiber.Error{Code:  fiber.StatusUnauthorized, Message: "Mismatched Tokens."}
			}

			if time.Now().After(time.Unix(int64(refresh_token_claims["exp"].(float64)), 0)) {
				initializers.Logger.Infow("Token Expiration: ", "Error", err)
				return &fiber.Error{Code:  fiber.StatusUnauthorized, Message: config.TOKEN_EXPIRED_ERROR}
			}

			new_access_token_claim := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
				"sub": user.ID,
				"crt": time.Now().Unix(),
				"exp": time.Now().Add(config.ACCESS_TOKEN_TTL).Unix(),
			})

			new_access_token, err := new_access_token_claim.SignedString([]byte(initializers.CONFIG.JWT_SECRET))
			if err != nil {
				go helpers.LogServerError("Error while decrypting JWT Token.", err, c.Path())
				return helpers.AppError{Code: fiber.StatusInternalServerError , Message: config.SERVER_ERROR, Err: err}
			}

			return c.Status(200).JSON(fiber.Map{
				"status": "success",
				"token":  new_access_token,
			})
		}

		return nil
	} else {
		return &fiber.Error{Code:  fiber.StatusUnauthorized , Message: "Invalid Token"}
	}
}
