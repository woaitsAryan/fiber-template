package schemas

type UserCreateSchema struct {
	Name            string `json:"name" validate:"required,max=25"`
	Username        string `json:"username" validate:"required,max=16"` //alphanum+_
	Email           string `json:"email" validate:"required,email"`
	Password        string `json:"password" validate:"required,min=8"`
	ConfirmPassword string `json:"confirmPassword" validate:"required,min=8"`
}
