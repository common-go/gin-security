package security

import (
	"github.com/gin-gonic/gin"
	"net/http"
	"sort"
)

type DefaultUserAuthorizationHandler struct {
	sortedUsers bool
}

func NewUserAuthorizationHandler(sortedUsers bool) *DefaultUserAuthorizationHandler {
	return &DefaultUserAuthorizationHandler{sortedUsers}
}

func (h *DefaultUserAuthorizationHandler) Authorize(users []string) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		userId := GetUserIdFromGinContext(ctx)
		if len(userId) == 0 {
			ctx.AbortWithStatusJSON(http.StatusBadRequest, "Invalid User Id.")
			return
		}
		if len(users) == 0 {
			ctx.AbortWithStatusJSON(http.StatusForbidden, "No Permission.")
			return
		}
		if h.sortedUsers {
			if HasSortedUser(userId, users) {
				ctx.Next()
				return
			}
		}
		if HasUser(userId, users) {
			ctx.Next()
			return
		}
		ctx.AbortWithStatusJSON(http.StatusForbidden, "No Permission.")
	}
}

func HasUser(currentUser string, users []string) bool {
	for _, user := range users {
		if user == currentUser {
			return true
		}
	}
	return false
}

func HasSortedUser(currentUser string, users []string) bool {
	i := sort.SearchStrings(users, currentUser)
	if i >= 0 && users[i] == currentUser {
		return true
	}
	return false
}
