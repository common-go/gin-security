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
		userId := h.getUserIdFromContext(ctx)
		if len(userId) == 0 {
			ctx.AbortWithStatusJSON(http.StatusBadRequest, "Invalid User Id.")
			return
		}
		if len(users) == 0 {
			ctx.AbortWithStatusJSON(http.StatusForbidden, "No Permission.")
			return
		}
		if h.sortedUsers {
			if h.hasSortedUser(userId, users) {
				ctx.Next()
				return
			}
		}
		if h.hasUser(userId, users) {
			ctx.Next()
			return
		}
		ctx.AbortWithStatusJSON(http.StatusForbidden, "No Permission.")
	}
}

func (h *DefaultUserAuthorizationHandler) hasUser(currentUser string, users []string) bool {
	for _, user := range users {
		if user == currentUser {
			return true
		}
	}
	return false
}

func (h *DefaultUserAuthorizationHandler) hasSortedUser(currentUser string, users []string) bool {
	i := sort.SearchStrings(users, currentUser)
	if i >= 0 && users[i] == currentUser {
		return true
	}
	return false
}

func (h *DefaultUserAuthorizationHandler) getUserIdFromContext(ctx *gin.Context) string {
	if token, exist := ctx.Get(Authorization); exist {
		if authorizationToken, exist := token.(map[string]interface{}); exist {
			return GetUserId(authorizationToken)
		}
	}
	return ""
}
