package routers

import (
	"github.com/gofiber/fiber/v2"
	"github.com/woaitsAryan/fiber-template-go/controllers"
	"github.com/woaitsAryan/fiber-template-go/middlewares"
	"github.com/woaitsAryan/fiber-template-go/validators"
)

func UserRouter(app *fiber.App) {
	app.Post("/signup", validators.UserCreateValidator, controllers.SignUp)
	app.Post("/login", controllers.LogIn)
	app.Post("/refresh", controllers.Refresh)

	userRoutes := app.Group("/users", middlewares.Protect)
	userRoutes.Get("/me", controllers.GetMe)
}
